use derive_more::Display;
use kzen_paillier::EncryptionKey;
use serde::{ Deserialize, Serialize };
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ReceiveRecoveryPackages {
    #[serde(flatten)]
    pub kind: Key,
    #[serde(flatten)]
    pub recovery_info: RecoveryPackageInfo,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePaillierKeysCommand {
    pub key_id: String,
    pub new_eks: Vec<EncryptionKey>,
}

impl Debug for UpdatePaillierKeysCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("UpdatePaillierKeysCommand").field("key_id", &self.key_id).finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSinglePaillierKeyCommand {
    pub key_id: String,
    pub new_ek: EncryptionKey,
    pub index: usize,
}

impl Debug for UpdateSinglePaillierKeyCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("UpdateSinglePaillierKeyCommand")
            .field("key_id", &self.key_id)
            .field("index", &self.index)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Display)]
#[serde(tag = "key_type")]
pub enum Key {
    ECDSA,
    #[serde(alias = "EdDSA")]
    EDDSA,
    Sr25519,
    TwoFA,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedData {
    pub aead_pack: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl Debug for EncryptedData {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "...")
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RecoveryPackageInfo {
    pub key_id: String,
    pub recovery_index: usize,
    pub threshold: usize,
    pub peers: Vec<usize>,
    pub public_keys: PublicKeysEnum,
    pub encrypted_packages: Vec<EncryptedData>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum PublicKeysEnum {
    Vec(Vec<String>),
    Map(Vec<(usize, String)>),
}

impl From<PublicKeysEnum> for HashMap<usize, String> {
    fn from(value: PublicKeysEnum) -> Self {
        match value {
            PublicKeysEnum::Vec(v) =>
                v
                    .into_iter()
                    .enumerate()
                    .map(|(i, x)| (i + 1, x))
                    .collect(),
            PublicKeysEnum::Map(h) => h.into_iter().collect(),
        }
    }
}
