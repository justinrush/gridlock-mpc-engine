use crate::command::{ JsonCommand, MsgContext };
use crate::storage::{
    KeyshareAccessor,
    KeyshareSaver,
    SchnorrkelSecretKey,
    Sr25519,
    TwoFactorAuth,
};
use anyhow::{ anyhow, bail, Result };
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{ Ed25519, Scalar };
use curv::BigInt;
use serde::{ Deserialize, Serialize };
use std::convert::{ TryFrom, TryInto };
use std::iter::Iterator;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyImportCommand {
    pub key_id: String,
    pub key_type: String,
    pub key: String,
    pub threshold: usize,
    pub share_count: usize,
}

impl JsonCommand for KeyImportCommand {
    type Response = Vec<KeyImportShareCommand>;

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        match self.key_type.as_str() {
            "2fa" =>
                create_share_import_cmds_for_2fa(
                    &self.key,
                    &self.key_id,
                    self.threshold,
                    self.share_count
                ),
            "sr25519" => bail!("sr25519 import not yet implemented"),
            "eddsa" => bail!("EdDSA import not yet implemented"),
            "ecdsa" => bail!("ECDSA import not yet implemented"),
            _ => bail!("Unknown type provided for key being imported"),
        }
    }
}

fn create_share_import_cmds_for_2fa(
    twofa_code: &str,
    key_id: &str,
    threshold: usize,
    share_count: usize
) -> Result<Vec<KeyImportShareCommand>> {
    let key = two_factor_key_to_ed25519Scalar(&twofa_code);
    // Note we generate shares from 0 index for 2fa. We do NOT want to use the 0 index when we implement import for eth or solana as the keyshare at 0 index holds the entire secret. This is what we want for 2fa but NOT a secret key securing real funds.
    let indices = (0..share_count as u16).collect::<Vec<u16>>();
    let (vss, shares) = VerifiableSS::<Ed25519>::share_at_indices(
        threshold as u16,
        share_count as u16,
        &key,
        &*indices
    );
    shares
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let key_share = serde_json::to_string(&s)?;
            let vss = serde_json::to_string(&vss)?;
            let key = if i == 0 { Some(twofa_code.to_string()) } else { None };
            Ok(KeyImportShareCommand {
                key,
                key_id: key_id.to_string(),
                key_type: "2fa".to_string(),
                key_share,
                vss,
                threshold,
                index: i,
            })
        })
        .collect::<Result<Vec<_>>>()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct KeyImportShareCommand {
    pub key_id: String,
    pub key_type: String,
    pub key_share: String,
    pub vss: String,
    pub threshold: usize,
    pub index: usize,
    pub key: Option<String>,
}

impl TryFrom<KeyImportShareCommand> for TwoFactorAuth {
    type Error = anyhow::Error;
    fn try_from(k: KeyImportShareCommand) -> Result<Self> {
        let secret = serde_json::from_str::<Scalar<Ed25519>>(&k.key_share)?;
        let vss = serde_json::from_str::<VerifiableSS<Ed25519>>(&k.vss)?;
        Ok(Self {
            twofa_code: k.key,
            threshold: k.threshold,
            party_index: k.index,
            x_i: secret.into(),
            vss_scheme: vss.into(),
        })
    }
}

impl TryFrom<KeyImportShareCommand> for Sr25519 {
    type Error = anyhow::Error;
    fn try_from(k: KeyImportShareCommand) -> Result<Self> {
        let secret = serde_json::from_str::<Scalar<Ed25519>>(&k.key_share)?;
        let vss = serde_json::from_str::<VerifiableSS<Ed25519>>(&k.vss)?;
        let secret_key = match k.key {
            None => None,
            Some(key) => Some(serde_json::from_str::<SchnorrkelSecretKey>(&key)?),
        };
        Ok(Self {
            secret_key,
            threshold: k.threshold,
            party_index: k.index,
            x_i: secret.into(),
            vss_scheme: vss.into(),
        })
    }
}

impl JsonCommand for KeyImportShareCommand {
    type Response = ();

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        match self.key_type.as_str() {
            // TODO: use flags
            "2fa" => {
                let keyfile: TwoFactorAuth = self.clone().try_into()?;
                let ks = KeyshareSaver::new_creator(&self.key_id);
                ks.save_key(&keyfile)
            }
            "sr25519" => {
                let keyfile: Sr25519 = self.clone().try_into()?;
                let ks = KeyshareSaver::new_creator(&self.key_id);
                ks.save_key(&keyfile)
            }
            _ => bail!("Unknown type provided for key being imported"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TwoFACodeRetrievalCommand {
    pub key_id_for_2fa_code_retrieval: String,
}

impl JsonCommand for TwoFACodeRetrievalCommand {
    type Response = String;

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        let ka = KeyshareAccessor::<TwoFactorAuth>::read_only(&self.key_id_for_2fa_code_retrieval)?;
        if let Some(code) = ka.key.twofa_code {
            return Ok(code);
        }
        bail!("Key file exists, however it was not possible to retrieve the 2fa code")
    }
}

// TODO: use TryFrom with new type
pub fn ed25519Scalar_to_two_factor_key(scalar: &Scalar<Ed25519>) -> Result<String> {
    String::from_utf8(scalar.to_bigint().to_bytes()).map_err(|_|
        anyhow!("Could not retrieve 2fa code")
    )
}

fn two_factor_key_to_ed25519Scalar(key: &str) -> Scalar<Ed25519> {
    let bn = BigInt::from_bytes(key.as_bytes());
    Scalar::<Ed25519>::from(&bn)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_convert_between_2fa_and_ed25519_scalar() {
        let twofa = "123ghjy6tgf";
        let scalar = two_factor_key_to_ed25519Scalar(&twofa);
        let twofa2 = ed25519Scalar_to_two_factor_key(&scalar).expect(
            "Can't retrieve 2fa key from ed25519 scalar"
        );
        assert_eq!(*twofa, twofa2);
    }

    #[test]
    fn can_create_2fa_key_type_from_2fa_code() {
        let import_command = KeyImportCommand {
            key_id: String::from("abc"),
            key_type: String::from("2fa"),
            key: String::from("GTHKlafdfdtty5"),
            threshold: 2,
            share_count: 5,
        };

        let share_commands = import_command
            .execute_message(MsgContext::FFI)
            .expect("Couldn't execute KeyImportCommand");
        let share1 = share_commands.iter().nth(0).expect("Couldn't get first share");
        let _: TwoFactorAuth = share1
            .clone()
            .try_into()
            .expect("Couldn't convert import command to key");
    }

    #[test]
    fn can_create_correct_count_of_keyshare_import_cmds() {
        let share_count = 5;
        let shares = create_share_import_cmds_for_2fa("3gthSDERx", "x", 2, share_count).expect(
            "Import of 2fa code failed"
        );
        assert_eq!(shares.len(), share_count);
    }

    #[test]
    fn can_create_keyshare_import_cmds_with_first_containing_0_index() {
        let share_count = 5;
        let shares = create_share_import_cmds_for_2fa("3gthSDERx", "x", 2, share_count).expect(
            "Import of 2fa code failed"
        );
        let first_share = shares.iter().nth(0).expect("Could not retrieve first key share");
        assert_eq!(first_share.index, 0);
        assert!(first_share.key.is_some());

        let second_share = shares.iter().nth(1).expect("Could not retrieve second key share");
        assert_eq!(second_share.index, 1);
        assert!(second_share.key.is_none());
    }
}
