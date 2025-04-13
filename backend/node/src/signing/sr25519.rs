use crate::command::{ JsonCommand, MsgContext };
use crate::storage::{ KeyshareAccessor, Sr25519 };
use anyhow::{ bail, Context, Result };
use schnorrkel::{ ExpansionMode, Keypair, MiniSecretKey, SecretKey };
use serde::{ Deserialize, Serialize };
use std::convert::TryInto;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySignCommand {
    pub key_id: String,
    pub key_type: String,
    pub message: Vec<u8>,
}

impl JsonCommand for KeySignCommand {
    type Response = String;

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        match self.key_type.as_str() {
            "sr25519" => sign_for_sr25519(self.key_id, self.message),
            "sr25519_musig" | "eddsa" | "ecdsa" => {
                bail!("Sign orchestration inside node is not yet implemented for {}", self.key_type)
            }
            _ => bail!("Signature can not be done for the key type"),
        }
    }
}

// Signing context that polkadot-js using for tx signing
// https://github.com/polkadot-js/wasm/blob/3a06871f829b316eb8c2b7763f1df18aa0e5fcb2/packages/wasm-crypto/src/rs/sr25519.rs#L18
const CTX: &'static [u8] = b"substrate";

fn sign_for_sr25519(key_id: String, message: Vec<u8>) -> Result<String> {
    let ka = KeyshareAccessor::<Sr25519>::read_only(&key_id)?;
    let secret = ka.key.secret_key.context("Can not sign. This user is not the owner of this key")?;
    let mini_secret: MiniSecretKey = secret.try_into()?;

    let public = mini_secret.expand_to_public(ExpansionMode::Ed25519);
    let secret: SecretKey = mini_secret.expand(ExpansionMode::Ed25519);
    let keypair = Keypair { public, secret };
    let signature = keypair.sign_simple(CTX, &message);
    Ok(hex::encode(signature.to_bytes()))
}
