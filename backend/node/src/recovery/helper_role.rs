use crate::communication::nats::PeerMessenger;
use crate::communication::protocol::{ AllRounds, KeyShareRegenAllRounds };
use crate::recovery::encryption::HelperEncryptor;
use crate::recovery::{ ECDSARecoveryPackage, EdDSARecoveryPackage, Party, ShareRecoveryInfo };
use crate::storage::{ KeyshareAccessor, ECDSA, EDDSA };
use anyhow::Result;
use curv::elliptic::curves::{ Curve, Ed25519, Scalar, Secp256k1 };
use itertools::Itertools;
use serde::Serialize;
use tracing::info;

use super::calculator::RecoveryCalculator;

/// Recovery of a keyshare by a helper guardian for both ECDSA and EdDSA
pub struct KeyshareRecoveryHelper<M, E, K> {
    pub messenger: M,
    pub encryptor: E,
    pub key: K,
}

impl<M, E, K> KeyshareRecoveryHelper<M, E, K>
    where
        M: PeerMessenger<KeyShareRegenAllRounds>,
        E: HelperEncryptor,
        K: KeyshareBehaviourHelperRole,
        K::Curve: Curve
{
    pub fn new(messenger: M, encryptor: E, key: K) -> Self {
        Self {
            messenger,
            encryptor,
            key,
        }
    }

    pub fn try_recovery(&mut self, recovery_index: usize, party: Party) -> Result<()> {
        self.send_recovery_package(recovery_index, party)
    }

    fn send_recovery_package(&mut self, recovery_index: usize, party: Party) -> Result<()> {
        info!("Starting recovery process as a helper node");
        let recovery = self.key.get_recovery_params(recovery_index, party);
        let contrib = recovery.create_secret_sharing_of_lost_share();
        let encrypted_shares = self.encryptor.encrypt_for_peers(contrib.for_peer_exchange)?;
        info!("Encrypted secret shares");

        let received_shares = self.messenger.send_p2p_and_collect_messages(
            &<KeyShareRegenAllRounds as AllRounds>::P2PRound::ExchangePartShares,
            encrypted_shares
        )?;

        let decrypted_shares = self.encryptor.decrypt_from_peers(received_shares)?;
        info!("Decrypted secret shares");
        let partial_share = recovery.sum_secret_shares(contrib.retained, decrypted_shares);

        let recovery_package = self.package_result(partial_share)?;

        self.messenger.broadcast_message(
            &<KeyShareRegenAllRounds as AllRounds>::BroadcastRound::DeliverRecoveryPackage,
            recovery_package
        )?;
        info!("Sent a recovery package");
        Ok(())
    }

    pub fn package_result(
        &self,
        secret_share: Scalar<K::Curve>
    ) -> Result<<E as HelperEncryptor>::Output> {
        let result = self.key.create_recovery_result(secret_share);
        info!("Encrypting recovery packages");
        self.encryptor.encrypt_for_target(result)
    }
}

/// Keyshare specific behaviour for keyshare recovery by a helper guardian
pub trait KeyshareBehaviourHelperRole {
    type Curve: Curve;
    type RecoveryPackage: Serialize;

    fn create_recovery_result(&self, result: Scalar<Self::Curve>) -> Self::RecoveryPackage;

    fn get_recovery_params(
        &self,
        recovery_index: usize,
        party: Party
    ) -> RecoveryCalculator<Self::Curve>;
}

/// EdDSA specific behaviour for keyshare recovery by a helper guardian
pub struct EdDSABehaviourHelperRole {
    key_accessor: KeyshareAccessor<EDDSA>,
}

impl EdDSABehaviourHelperRole {
    pub fn from_key_accessor(key_accessor: KeyshareAccessor<EDDSA>) -> Self {
        Self { key_accessor }
    }
}

impl KeyshareBehaviourHelperRole for EdDSABehaviourHelperRole {
    type Curve = Ed25519;
    type RecoveryPackage = EdDSARecoveryPackage;

    fn create_recovery_result(&self, result: Scalar<Self::Curve>) -> Self::RecoveryPackage {
        EdDSARecoveryPackage {
            share_recovery_info: ShareRecoveryInfo {
                partial_secret: result,
                vss_vec: self.key_accessor.key.vss_scheme_vec
                    .clone()
                    .into_iter()
                    .map_into()
                    .collect(),
            },
        }
    }

    fn get_recovery_params(
        &self,
        recovery_index: usize,
        party: Party
    ) -> RecoveryCalculator<Self::Curve> {
        RecoveryCalculator::<Self::Curve> {
            secret_share: self.key_accessor.key.x_i.clone().into(),
            threshold: self.key_accessor.key.threshold,
            party,
            recovery_index,
        }
    }
}

/// ECDSA specific behaviour for keyshare recovery by a helper guardian
pub struct ECDSABehaviourHelperRole {
    key_accessor: KeyshareAccessor<ECDSA>,
}

impl ECDSABehaviourHelperRole {
    pub fn from_key_accessor(key_accessor: KeyshareAccessor<ECDSA>) -> Self {
        Self { key_accessor }
    }
}

impl KeyshareBehaviourHelperRole for ECDSABehaviourHelperRole {
    type Curve = Secp256k1;
    type RecoveryPackage = ECDSARecoveryPackage;

    fn create_recovery_result(&self, result: Scalar<Self::Curve>) -> Self::RecoveryPackage {
        Self::RecoveryPackage {
            share_recovery_info: ShareRecoveryInfo {
                partial_secret: result,
                vss_vec: self.key_accessor.key.vss_scheme_vec.iter().cloned().map_into().collect(),
            },
            h1_h2_N_tilde_vec: self.key_accessor.key.h1_h2_N_tilde_vec
                .iter()
                .cloned()
                .map_into()
                .collect(),
            paillier_key_vec: self.key_accessor.key.paillier_key_vec.clone(),
            public_key_vec: self.key_accessor.key.public_key_vec
                .iter()
                .cloned()
                .map_into()
                .collect(),
        }
    }

    fn get_recovery_params(
        &self,
        recovery_index: usize,
        party: Party
    ) -> RecoveryCalculator<Self::Curve> {
        RecoveryCalculator::<Self::Curve> {
            secret_share: self.key_accessor.key.x_i.clone().into(),
            threshold: self.key_accessor.key.threshold,
            party,
            recovery_index,
        }
    }
}
