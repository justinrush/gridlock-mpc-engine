use crate::command::{ JsonCommand, MsgContext };
use crate::keygen::key_import::KeyImportShareCommand;
use crate::storage::SchnorrkelSecretKey;
use anyhow::{ bail, Result };
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{ Ed25519, Scalar };
use schnorrkel::SecretKey;
use serde::{ Deserialize, Serialize };
use std::iter::Iterator;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyGenCommand {
    pub key_id: String,
    pub key_type: String,
    pub threshold: usize,
    pub share_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenResponse {
    pub pk: String,
    pub import_cmd: Vec<KeyImportShareCommand>,
}

impl JsonCommand for KeyGenCommand {
    type Response = KeyGenResponse;

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        match self.key_type.as_str() {
            "sr25519" => generate_key_for_sr25519(&self.key_id, self.threshold, self.share_count),
            "eddsa" => bail!("EdDSA key generation implemented different way"),
            "ecdsa" => bail!("ECDSA key generation implemented different way"),
            _ => bail!("Key generation does not exist for the key type"),
        }
    }
}

fn generate_key_for_sr25519(
    key_id: &str,
    threshold: usize,
    share_count: usize
) -> Result<KeyGenResponse> {
    let secret = SchnorrkelSecretKey::generate();
    let schnor_secret: SecretKey = secret.clone().into();
    let pk = hex::encode(schnor_secret.to_public().to_bytes());
    let key: Scalar<Ed25519> = secret.clone().into();

    // 2fa key shares start from 0 index
    let indices = (0..share_count as u16).collect::<Vec<u16>>();
    let (vss, shares) = VerifiableSS::<Ed25519>::share_at_indices(
        threshold as u16,
        share_count as u16,
        &key,
        &indices
    );
    let import_cmd = shares
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let key_share = serde_json::to_string(&s)?;
            let vss = serde_json::to_string(&vss)?;
            let key = if i == 0 { Some(serde_json::to_string(&secret)?) } else { None };
            Ok(KeyImportShareCommand {
                key: key,
                key_id: key_id.to_string(),
                key_type: "sr25519".to_string(),
                key_share,
                vss,
                threshold,
                index: i,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(KeyGenResponse { import_cmd, pk })
}
