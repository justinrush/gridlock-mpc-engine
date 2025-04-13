use crate::encryption::{
    decrypt_and_deserialize,
    serialize_and_encrypt,
    shared_secret_from_nkeys,
    shared_secrets_from_nkeys,
};
use anyhow::{ anyhow, Result };
use serde::de::DeserializeOwned;
use serde::Serialize;
use shared::recovery::EncryptedData;
use std::collections::HashMap;
use tracing::info;

pub trait HelperEncryptor {
    type Output: Serialize + Clone + DeserializeOwned;
    //encrypt for other party members
    fn encrypt_for_peers<T: Serialize>(&self, inputs: Vec<T>) -> Result<Vec<Self::Output>>;
    //decrypt from other party members (number of messages will be total number of party members minus one)
    fn decrypt_from_peers<T: DeserializeOwned>(&self, inputs: Vec<Self::Output>) -> Result<Vec<T>>;
    //encrypt for individual by index
    fn encrypt_for_target<T: Serialize>(&self, input: T) -> Result<Self::Output>;
}
pub trait TargetEncryptor {
    type Output: Serialize + Clone + DeserializeOwned;
    //decrypt message from each party member - used by participant outside of party (number of messages will be total number of party members)
    fn decrypt_from_all_parties<T: DeserializeOwned>(
        &self,
        inputs: Vec<Self::Output>
    ) -> Result<Vec<T>>;
}

pub struct Plaintext;

impl Plaintext {
    fn encrypt<T: Serialize>(&self, input: T) -> Result<Vec<u8>> {
        let s = serde_json::to_vec(&input)?;
        Ok(s)
    }
    fn decrypt<T: DeserializeOwned>(&self, input: Vec<u8>) -> Result<T> {
        let d = serde_json::from_slice::<T>(&input)?;
        Ok(d)
    }
}

impl HelperEncryptor for Plaintext {
    type Output = Vec<u8>;
    fn encrypt_for_peers<T: Serialize>(&self, inputs: Vec<T>) -> Result<Vec<Self::Output>> {
        inputs
            .iter()
            .map(|p| self.encrypt(p))
            .collect()
    }
    fn decrypt_from_peers<T: DeserializeOwned>(&self, inputs: Vec<Self::Output>) -> Result<Vec<T>> {
        inputs
            .iter()
            .map(|p| self.decrypt(p.to_vec()))
            .collect()
    }
    fn encrypt_for_target<T: Serialize>(&self, input: T) -> Result<Self::Output> {
        self.encrypt(input)
    }
}

impl TargetEncryptor for Plaintext {
    type Output = Vec<u8>;
    fn decrypt_from_all_parties<T: DeserializeOwned>(
        &self,
        inputs: Vec<Self::Output>
    ) -> Result<Vec<T>> {
        inputs
            .iter()
            .map(|p| self.decrypt(p.to_vec()))
            .collect()
    }
}

pub struct NKeyHelperEncryptor {
    peer_encryption_keys: Vec<Vec<u8>>,
    target_encryption_key: Vec<u8>,
}

impl NKeyHelperEncryptor {
    pub fn new<'a>(
        public_keys: &'a HashMap<usize, String>,
        recovery_index: usize,
        own_index: usize,
        peers: &'a [usize],
        private_key: String
    ) -> Result<Self> {
        let peer_pks = peers
            .iter()
            .filter(|&x| *x != own_index)
            .map(|i| {
                public_keys
                    .get(i)
                    .and_then(|s| Some(s.to_owned()))
                    .ok_or_else(|| {
                        anyhow!("Could not find public key corresponding to node with keyshare {i}")
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let target_pk = public_keys
            .get(&recovery_index)
            .and_then(|s| Some(s.to_owned()))
            .ok_or_else(|| anyhow!("Could not find public key corresponding to the target node"))?;
        let peer_encryption_keys = shared_secrets_from_nkeys(&private_key, &peer_pks)?;
        info!("Created peer encryption keys");
        let target_encryption_key = shared_secret_from_nkeys(&private_key, &target_pk)?;
        info!("Created target encryption key");
        Ok(Self {
            peer_encryption_keys,
            target_encryption_key,
        })
    }
}

impl HelperEncryptor for NKeyHelperEncryptor {
    type Output = EncryptedData;

    fn encrypt_for_peers<T: Serialize>(&self, inputs: Vec<T>) -> Result<Vec<Self::Output>> {
        inputs
            .iter()
            .enumerate()
            .map(|(i, input)| serialize_and_encrypt(&input, &self.peer_encryption_keys[i]))
            .collect()
    }
    fn decrypt_from_peers<T: DeserializeOwned>(&self, inputs: Vec<Self::Output>) -> Result<Vec<T>> {
        inputs
            .iter()
            .enumerate()
            .map(|(i, input)| decrypt_and_deserialize(&input, &self.peer_encryption_keys[i]))
            .collect()
    }
    fn encrypt_for_target<T: Serialize>(&self, input: T) -> Result<Self::Output> {
        serialize_and_encrypt(&input, &self.target_encryption_key)
    }
}

pub struct NKeyTargetEncryptor {
    helper_encryption_keys: Vec<Vec<u8>>,
}

impl NKeyTargetEncryptor {
    pub fn new<'a>(
        public_keys: &'a HashMap<usize, String>,
        peers: &'a [usize],
        private_key: String
    ) -> Result<Self> {
        let helper_pks = peers
            .iter()
            .map(|i| {
                public_keys
                    .get(i)
                    .and_then(|s| Some(s.to_owned()))
                    .ok_or_else(|| {
                        anyhow!("Could not find public key corresponding to node with keyshare {i}")
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let helper_encryption_keys = shared_secrets_from_nkeys(&private_key, &helper_pks)?;

        Ok(Self {
            helper_encryption_keys,
        })
    }
}

impl TargetEncryptor for NKeyTargetEncryptor {
    type Output = EncryptedData;

    fn decrypt_from_all_parties<T: DeserializeOwned>(
        &self,
        inputs: Vec<Self::Output>
    ) -> Result<Vec<T>> {
        inputs
            .iter()
            .enumerate()
            .map(|(i, input)| decrypt_and_deserialize(&input, &self.helper_encryption_keys[i]))
            .collect()
    }
}
