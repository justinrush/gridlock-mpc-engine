use crate::communication::nats::PeerMessenger;
use crate::communication::protocol::{ AllRounds, KeyShareRegenAllRounds };
use crate::keygen::key_import::ed25519Scalar_to_two_factor_key;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use paillier::{ DecryptionKey, EncryptionKey, KeyGeneration, Paillier };
use serde::de::DeserializeOwned;
use serde::Serialize;
use zk_paillier::zkproofs::DLogStatement;

use crate::storage::{ KeyshareSaver, Sr25519, TwoFactorAuth, ECDSA, EDDSA };

use crate::recovery::calculator::RecoveryCalculator;
use crate::recovery::encryption::TargetEncryptor;

use crate::recovery::{
    replace_elem_in_vec,
    ECDSARecoveryPackage,
    EdDSARecoveryPackage,
    RecoveryValidationResult,
    ShareRecoveryInfo,
};
use anyhow::{ bail, Result };
use curv::elliptic::curves::{ Curve, Ed25519, Point, Scalar, Secp256k1 };
use itertools::Itertools;
use tracing::{ error, info };

pub struct KeyshareRecoveryTarget<C, E, K> {
    pub messenger: C,
    pub encryptor: E,
    pub key_behaviour: K,
}

impl<PM, E, R> KeyshareRecoveryTarget<PM, E, R>
    where
        PM: PeerMessenger<KeyShareRegenAllRounds>,
        E: TargetEncryptor,
        R: KeyshareBehaviourTargetRole,
        R::Curve: Curve
{
    pub fn new(messenger: PM, encryptor: E, key: R) -> Self {
        Self {
            messenger,
            encryptor,
            key_behaviour: key,
        }
    }

    pub fn recover_keyshare<'a>(
        &self,
        recovery_index: usize,
        threshold: usize,
        encrypted_packages: Vec<<E as TargetEncryptor>::Output>
    ) -> Result<RecoveryValidationResult> {
        let recovery_packages = self.encryptor.decrypt_from_all_parties(encrypted_packages)?;

        info!("Decrypted recovery packages");

        let validation_result = self.key_behaviour.process_recovery_packages(
            recovery_index,
            threshold,
            &recovery_packages
        );

        info!("Validation result: {:?}", &validation_result);

        Ok(validation_result)
    }

    pub fn broadcast_result(&self, result: RecoveryValidationResult) -> Result<()> {
        self.broadcast_validation_result(result)
    }

    pub fn try_recieve_encrypted_packages(&self) -> Result<Vec<<E as TargetEncryptor>::Output>> {
        info!("Attempting to recieve recovery packages as the target node");
        let received_packages = self.messenger.collect_messages::<E::Output>(
            &<KeyShareRegenAllRounds as AllRounds>::BroadcastRound::DeliverRecoveryPackage
        )?;
        info!("Received recovery packages");
        Ok(received_packages)
    }

    fn broadcast_validation_result(
        &self,
        validation_result: RecoveryValidationResult
    ) -> Result<()> {
        self.messenger.broadcast_message::<RecoveryValidationResult>(
            &<KeyShareRegenAllRounds as AllRounds>::BroadcastRound::ValidationResult,
            validation_result
        )
    }
}

pub trait KeyshareBehaviourTargetRole where <Self::Curve as Curve>::Scalar: Clone {
    type Curve: Curve + Clone;
    type RecoveryPackage: Serialize + Clone + DeserializeOwned;
    fn process_recovery_packages(
        &self,
        recovery_index: usize,
        threshold: usize,
        packages: &[Self::RecoveryPackage]
    ) -> RecoveryValidationResult;
}

pub struct EdDSABehaviourTargetRole {
    key_saver: KeyshareSaver,
}

impl EdDSABehaviourTargetRole {
    pub fn new(key_id: &str) -> Self {
        Self {
            key_saver: KeyshareSaver::new_creator_modifier(key_id),
        }
    }
}

impl KeyshareBehaviourTargetRole for EdDSABehaviourTargetRole {
    type Curve = Ed25519;
    type RecoveryPackage = EdDSARecoveryPackage;
    fn process_recovery_packages(
        &self,
        recovery_index: usize,
        threshold: usize,
        packages: &[Self::RecoveryPackage]
    ) -> RecoveryValidationResult {
        let share_info = packages
            .iter()
            .map(|x| x.share_recovery_info.clone())
            .collect::<Vec<ShareRecoveryInfo<Self::Curve>>>();
        let (recovered_secret, vss, y_sum) = match
            recover_and_validate_secret(recovery_index, share_info)
        {
            Ok(ss) => ss,
            Err(err) => {
                return RecoveryValidationResult::error(
                    format!("The provided recovery packages could not be validated: {}", err)
                );
            }
        };

        let new_keyshare = EDDSA {
            threshold,
            party_index: recovery_index,
            x_i: recovered_secret.into(),
            y_sum: y_sum.into(),
            vss_scheme_vec: vss,
        };

        match self.key_saver.save_key(&new_keyshare) {
            Ok(()) => {
                info!("New file successfully saved for keyshare {}", recovery_index);
                RecoveryValidationResult::validated()
            }

            Err(err) => {
                let msg =
                    format!("The keyshare was recovered and validated successfully but the new keyshare file could not be saved: {}", err);
                error!("{}", msg);
                RecoveryValidationResult::error(msg.to_string())
            }
        }
    }
}

pub struct ECDSABehaviourTargetRole {
    key_saver: KeyshareSaver,
}

impl ECDSABehaviourTargetRole {
    pub fn new(key_id: &str) -> Self {
        Self {
            key_saver: KeyshareSaver::new_creator_modifier(key_id),
        }
    }
}

impl KeyshareBehaviourTargetRole for ECDSABehaviourTargetRole {
    type Curve = Secp256k1;
    type RecoveryPackage = ECDSARecoveryPackage;
    fn process_recovery_packages(
        &self,
        recovery_index: usize,
        threshold: usize,
        packages: &[Self::RecoveryPackage]
    ) -> RecoveryValidationResult {
        let share_info = packages
            .iter()
            .map(|x| x.share_recovery_info.clone())
            .collect::<Vec<ShareRecoveryInfo<Self::Curve>>>();
        info!("Calculated share info");

        let (x_i, vss_scheme_vec, y_sum) = match
            recover_and_validate_secret(recovery_index, share_info)
        {
            Ok(ss) => ss,
            Err(err) => {
                return RecoveryValidationResult::error(
                    format!("The provided recovery packages could not be validated: {}", err)
                );
            }
        };
        info!("Validated share info recieved");

        let validated_recovery_items = match
            validate_ecdsa_specific_recovery_package_items(packages, recovery_index)
        {
            Ok(ss) => {
                info!("Returned new ecdsa items");
                ss
            }
            Err(err) => {
                return RecoveryValidationResult::error(
                    format!("The provided recovery packages could not be validated: {}", err)
                );
            }
        };
        info!("Validated ecdsa specific items");

        let keyshare = ECDSA {
            threshold,
            y_sum: y_sum.into(),
            x_i: x_i.into(),
            party_index: recovery_index,
            public_key_vec: validated_recovery_items.public_key_vec
                .into_iter()
                .map_into()
                .collect(),
            vss_scheme_vec,
            paillier_key_vec: validated_recovery_items.new_paillier_key_vec.clone(),
            h1_h2_N_tilde_vec: validated_recovery_items.h1_h2_N_tilde_vec
                .iter()
                .cloned()
                .map_into()
                .collect(),
            paillier_dk: validated_recovery_items.paillier_dk,
        };
        info!("Calculated new keyshare");

        match self.key_saver.save_key(&keyshare) {
            Ok(()) => {
                info!("New file successfully saved for keyshare {}", recovery_index);
                RecoveryValidationResult::validated_with_eks(validated_recovery_items.paillier_ek)
            }
            Err(err) => {
                let msg =
                    format!("The keyshare was recovered and validated successfully but the new keyshare file could not be saved: {}", err);
                error!("{}", msg);
                RecoveryValidationResult::error(msg.to_string())
            }
        }
    }
}

pub struct TwoFABehaviourTargetRole {
    key_saver: KeyshareSaver,
}

impl TwoFABehaviourTargetRole {
    pub fn new(key_id: &str) -> Self {
        Self {
            key_saver: KeyshareSaver::new_creator(key_id),
        }
    }
}

impl KeyshareBehaviourTargetRole for TwoFABehaviourTargetRole {
    type Curve = Ed25519;
    type RecoveryPackage = EdDSARecoveryPackage;
    fn process_recovery_packages(
        &self,
        recovery_index: usize,
        threshold: usize,
        packages: &[Self::RecoveryPackage]
    ) -> RecoveryValidationResult {
        let share_info = packages
            .iter()
            .map(|x| x.share_recovery_info.clone())
            .collect::<Vec<ShareRecoveryInfo<Self::Curve>>>();
        let (recovered_secret, vss, _y_sum) = match
            recover_and_validate_secret(recovery_index, share_info)
        {
            Ok(ss) => ss,
            Err(err) => {
                return RecoveryValidationResult::error(
                    format!("The provided recovery packages could not be validated: {}", err)
                );
            }
        };

        let twofa_code = if recovery_index == 0 {
            match ed25519Scalar_to_two_factor_key(&recovered_secret) {
                Ok(code) => Some(code),
                Err(err) => {
                    error!("Could not recover the 2fa code from the recovered secret: {}", err);
                    None
                }
            }
        } else {
            None
        };

        let vss_scheme = match vss.into_iter().nth(0) {
            Some(vss) => vss,
            None => {
                let msg = "Could not retrieve the vss scheme from the recovered items";
                error!("{}", msg);
                return RecoveryValidationResult::error(msg.to_string());
            }
        };

        let new_keyshare = TwoFactorAuth {
            threshold,
            party_index: recovery_index,
            x_i: recovered_secret.into(),
            twofa_code,
            vss_scheme: vss_scheme.into(),
        };

        match self.key_saver.save_key(&new_keyshare) {
            Ok(()) => {
                info!("New file successfully saved for keyshare {}", recovery_index);
                RecoveryValidationResult::validated()
            }

            Err(err) => {
                let msg =
                    format!("The keyshare was recovered and validated successfully but the new keyshare file could not be saved: {}", err);
                error!("{}", msg);
                RecoveryValidationResult::error(msg.to_string())
            }
        }
    }
}

pub struct Sr25519BehaviourTargetRole {
    key_saver: KeyshareSaver,
}

impl Sr25519BehaviourTargetRole {
    pub fn new(key_id: &str) -> Self {
        Self {
            key_saver: KeyshareSaver::new_creator(key_id),
        }
    }
}

impl KeyshareBehaviourTargetRole for Sr25519BehaviourTargetRole {
    type Curve = Ed25519;
    type RecoveryPackage = EdDSARecoveryPackage;
    fn process_recovery_packages(
        &self,
        recovery_index: usize,
        threshold: usize,
        packages: &[Self::RecoveryPackage]
    ) -> RecoveryValidationResult {
        let share_info = packages
            .iter()
            .map(|x| x.share_recovery_info.clone())
            .collect::<Vec<ShareRecoveryInfo<Self::Curve>>>();
        let (recovered_secret, vss, _y_sum) = match
            recover_and_validate_secret(recovery_index, share_info)
        {
            Ok(ss) => ss,
            Err(err) => {
                return RecoveryValidationResult::error(
                    format!("The provided recovery packages could not be validated: {err}")
                );
            }
        };

        let secret_key = if recovery_index == 0 {
            Some(recovered_secret.clone().into())
        } else {
            None
        };

        let vss_scheme = match vss.into_iter().nth(0) {
            Some(vss) => vss,
            None => {
                let msg = "Could not retrieve the vss scheme from the recovered items";
                error!("{}", msg);
                return RecoveryValidationResult::error(msg.to_string());
            }
        };

        let new_keyshare = Sr25519 {
            secret_key,
            threshold,
            party_index: recovery_index,
            x_i: recovered_secret.into(),
            vss_scheme: vss_scheme.into(),
        };

        match self.key_saver.save_key(&new_keyshare) {
            Ok(()) => {
                info!("New file successfully saved for keyshare {}", recovery_index);
                RecoveryValidationResult::validated()
            }

            Err(err) => {
                let msg =
                    format!("The keyshare was recovered and validated successfully but the new keyshare file could not be saved: {}", err);
                error!("{}", msg);
                RecoveryValidationResult::error(msg.to_string())
            }
        }
    }
}

struct ECDSASpecificValidatedRecoveryItems {
    public_key_vec: Vec<Point<Secp256k1>>,
    new_paillier_key_vec: Vec<EncryptionKey>,
    h1_h2_N_tilde_vec: Vec<DLogStatement>,
    paillier_ek: EncryptionKey,
    paillier_dk: DecryptionKey,
}

fn validate_ecdsa_specific_recovery_package_items(
    recovery_packages: &[ECDSARecoveryPackage],
    recovery_index: usize
) -> Result<ECDSASpecificValidatedRecoveryItems> {
    let public_key_vecs = recovery_packages
        .iter()
        .map(|x| x.public_key_vec.clone())
        .collect::<Vec<Vec<Point<Secp256k1>>>>();

    let paillier_key_vecs = recovery_packages
        .iter()
        .map(|x| x.paillier_key_vec.clone())
        .collect::<Vec<Vec<EncryptionKey>>>();

    let h1_h2_N_tilde_vecs = recovery_packages
        .iter()
        .map(|x| x.h1_h2_N_tilde_vec.clone())
        .collect::<Vec<Vec<DLogStatement>>>();

    // Taking first item as partial equality comparision unavailable
    let h1_h2_N_tilde_vec = h1_h2_N_tilde_vecs[0].clone();

    let public_key_vec = validate_all_matching_items(&public_key_vecs, "Public key vec")?;

    let mut paillier_key_vec = validate_all_matching_items(
        &paillier_key_vecs,
        "Paillier encryption keys"
    )?;

    let (paillier_ek, paillier_dk) = create_new_paillier_keys_and_update_vec(
        &mut paillier_key_vec,
        recovery_index
    )?;

    Ok(ECDSASpecificValidatedRecoveryItems {
        public_key_vec,
        new_paillier_key_vec: paillier_key_vec,
        h1_h2_N_tilde_vec,
        paillier_ek,
        paillier_dk,
    })
}

fn create_new_paillier_keys_and_update_vec(
    paillier_key_vec: &mut [EncryptionKey],
    recovery_index: usize
) -> Result<(EncryptionKey, DecryptionKey)> {
    let (new_ek, new_dk) = Paillier::keypair().keys();
    replace_elem_in_vec(paillier_key_vec, recovery_index - 1, new_ek.clone())?;
    Ok((new_ek, new_dk))
}

fn recover_and_validate_secret<C>(
    recovery_index: usize,
    share_infos: Vec<ShareRecoveryInfo<C>>
) -> Result<(Scalar<C>, Vec<VerifiableSS<C>>, Point<C>)>
    where C: Curve
{
    let mut vss_vec = Vec::new();
    let mut secrets = Vec::new();

    share_infos.into_iter().for_each(|x| {
        vss_vec.push(x.vss_vec);
        secrets.push(x.partial_secret);
    });

    let vss = validate_all_matching_items(&vss_vec, "VSS scheme vecs")?;
    // let y_sum = validate_all_matching_items(&y_sums, "y sums")?;

    let y_sum = RecoveryCalculator::<C>::calculate_y_sum_from_vss_vec(&vss)?;

    let secret = secrets.iter().sum();

    let _ = RecoveryCalculator::<C>::validate_recovered_share(&secret, &vss, recovery_index)?;

    Ok((secret, vss, y_sum))
}

fn validate_all_matching_items<T: PartialEq + Clone>(items: &[T], description: &str) -> Result<T> {
    let first_item = &items[0];
    let all_matching = items.into_iter().all(|item| item == first_item);
    if !all_matching {
        bail!("{} provided do not match, key recovery cannot be validated", &description);
    }
    Ok(first_item.clone())
}
