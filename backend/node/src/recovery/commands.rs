use crate::command::{ JsonCommand, MsgContext };
use crate::communication::{ nats::DummyMessenger, protocol::Topic };
use crate::node::NodeIdentity;
use crate::recovery::encryption::NKeyTargetEncryptor;
use crate::recovery::target_role::{
    ECDSABehaviourTargetRole,
    EdDSABehaviourTargetRole,
    KeyshareBehaviourTargetRole,
    KeyshareRecoveryTarget,
    Sr25519BehaviourTargetRole,
    TwoFABehaviourTargetRole,
};
use crate::recovery::{
    save_new_paillier_keys,
    update_paillier_keys,
    Key,
    RecoveryValidationResult,
};
use crate::security::check_for_small_primes;
use crate::storage::{ KeyshareAccessor, ECDSA };
use anyhow::{ anyhow, Result };
use paillier::EncryptionKey;
use serde::{ Deserialize, Serialize };
use shared::recovery::{
    ReceiveRecoveryPackages,
    UpdatePaillierKeysCommand,
    UpdateSinglePaillierKeyCommand,
};
use std::fmt::Debug;

fn process_rec_package<TR: KeyshareBehaviourTargetRole>(
    rec_package: ReceiveRecoveryPackages,
    target_role: TR
) -> Result<RecoveryValidationResult> {
    let node = NodeIdentity::load()?;
    let private_key = node.networking_private_key;

    // TODO: Do we really need dummyMessenger or abstractions leaked again?
    // This dummy messenger is needed because communication, though abstracted needs to be moved up a level
    let messenger = DummyMessenger::new(Topic::KeyShareRecovery)?;

    let encryptor = NKeyTargetEncryptor::new(
        &rec_package.recovery_info.public_keys.into(),
        &rec_package.recovery_info.peers,
        private_key
    ).map_err(|err| anyhow!("Unable to create encryptor: {}", err))?;

    let recoverer = KeyshareRecoveryTarget::new(messenger, encryptor, target_role);

    recoverer.recover_keyshare(
        rec_package.recovery_info.recovery_index,
        rec_package.recovery_info.threshold,
        rec_package.recovery_info.encrypted_packages.clone()
    )
}

impl JsonCommand for ReceiveRecoveryPackages {
    type Response = RecoveryValidationResult;

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        match self.kind {
            Key::ECDSA => {
                let role = ECDSABehaviourTargetRole::new(&self.recovery_info.key_id);
                process_rec_package(self, role)
            }
            Key::EDDSA => {
                let role = EdDSABehaviourTargetRole::new(&self.recovery_info.key_id);
                process_rec_package(self, role)
            }
            Key::TwoFA => {
                let role = TwoFABehaviourTargetRole::new(&self.recovery_info.key_id);
                process_rec_package(self, role)
            }
            Key::Sr25519 => {
                let role = Sr25519BehaviourTargetRole::new(&self.recovery_info.key_id);
                process_rec_package(self, role)
            }
        }
    }
}

impl JsonCommand for UpdatePaillierKeysCommand {
    type Response = ();
    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        // Security issue: CVE-2023-33241
        for ek in &self.new_eks {
            check_for_small_primes(ek)?;
        }

        let mut ka = KeyshareAccessor::<ECDSA>::modifiable(&self.key_id)?;
        save_new_paillier_keys(&mut ka, self.new_eks)?;
        Ok(())
    }
}

impl JsonCommand for UpdateSinglePaillierKeyCommand {
    type Response = ();
    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        // Security issue: CVE-2023-33241
        check_for_small_primes(&self.new_ek)?;

        let mut ka = KeyshareAccessor::<ECDSA>::modifiable(&self.key_id)?;
        let _ = update_paillier_keys(&mut ka, self.index, self.new_ek)?;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetPaillierKeysCommand {
    pub key_id: String,
}

impl Debug for GetPaillierKeysCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("GetPaillierKeysCommand").field("key_id", &self.key_id).finish()
    }
}

impl JsonCommand for GetPaillierKeysCommand {
    type Response = PaillierKeysResponse;
    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        let ka = KeyshareAccessor::<ECDSA>::read_only(&self.key_id)?;
        Ok(PaillierKeysResponse {
            eks: ka.key.paillier_key_vec,
        })
    }
}

#[derive(Clone, Serialize)]
pub struct PaillierKeysResponse {
    eks: Vec<EncryptionKey>,
}
