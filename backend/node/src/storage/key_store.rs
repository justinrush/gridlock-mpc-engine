use super::fs::{ FileSystem, WriteOpts };
use crate::recovery::RecoveryCalculator;
use anyhow::{ anyhow, bail, Context, Result };
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{ Curve, Ed25519, Point, Scalar, Secp256k1 };
use curv::BigInt;
use itertools::Itertools;
use paillier::{ DecryptionKey, EncryptionKey };
use serde::de::{ Error, MapAccess, SeqAccess, Visitor };
use serde::{ de::DeserializeOwned, Deserialize, Serialize, Serializer };
use shared::recovery::EncryptedData;
use std::convert::TryFrom;
use std::fs;
use std::ops::Index;
use zk_paillier::zkproofs::DLogStatement;

use crate::encryption::{ aes_decrypt, aes_encrypt, AES_KEY_BYTES_LEN };
use crate::storage::wrappers::{
    SchnorrkelSecretKey,
    WDLogStatement,
    WEcSharedKeys,
    WEdKeys,
    WEdSharedKeys,
    WPoint,
    WScalar,
    WVerifiableSS,
};

const TEMP_ENCRYPTION_KEY: &[u8; AES_KEY_BYTES_LEN] = b"65hjkt23scdfbfh8789kj2isdv870m84";

//Marker trait to make sure we save keyfiles in most up to date format
pub trait CurrentKeyshareFormat: Serialize + DeserializeOwned + TryFrom<KeyshareFormat> {}

// Note that if CurrentKeyshareFormat is updated from EdDSA_V2, it will be necessary to update the TryFrom method to allow converting from TwoFractorAuth to new EdDSA format (this is necessary for regeneration of 2fa).
impl CurrentKeyshareFormat for ECDSA_V4 {}
impl CurrentKeyshareFormat for EdDSA_V3 {}
impl CurrentKeyshareFormat for TwoFactorAuth {}
impl CurrentKeyshareFormat for Sr25519 {}

impl TryFrom<KeyshareFormat> for ECDSA_V4 {
    type Error = &'static str;

    fn try_from(kf: KeyshareFormat) -> Result<Self, Self::Error> {
        match kf {
            KeyshareFormat::ECDSA_V1V2(ecdsa_v1v2) =>
                Ok(Self {
                    party_index: ecdsa_v1v2.party_id,
                    threshold: 2,
                    vss_scheme_vec: ecdsa_v1v2.vss_scheme_vec.into_iter().map_into().collect(),
                    x_i: ecdsa_v1v2.shared_keys.x_i.into(),
                    h1_h2_N_tilde_vec: ecdsa_v1v2.h1_h2_N_tilde_vec
                        .into_iter()
                        .map_into()
                        .collect(),
                    paillier_key_vec: ecdsa_v1v2.paillier_key_vector,
                    y_sum: ecdsa_v1v2.y_sum.into(),
                    public_key_vec: ecdsa_v1v2.public_key_vec.into_iter().map_into().collect(),
                    paillier_dk: ecdsa_v1v2.party_keys.dk,
                }),
            KeyshareFormat::ECDSA_V3(ecdsa_v3) =>
                Ok(Self {
                    threshold: ecdsa_v3.threshold,
                    y_sum: ecdsa_v3.y_sum.into(),
                    x_i: ecdsa_v3.x_i.into(),
                    party_index: ecdsa_v3.party_index,
                    public_key_vec: ecdsa_v3.public_key_vec.into_iter().map_into().collect(),
                    vss_scheme_vec: ecdsa_v3.vss_scheme_vec.into_iter().map_into().collect(),
                    paillier_key_vec: ecdsa_v3.paillier_key_vec.into_iter().map_into().collect(),
                    h1_h2_N_tilde_vec: ecdsa_v3.h1_h2_N_tilde_vec.into_iter().map_into().collect(),
                    paillier_dk: ecdsa_v3.paillier_dk.into(),
                }),
            KeyshareFormat::ECDSA_V4(ecdsa_v4) => Ok(ecdsa_v4),
            | KeyshareFormat::EdDSA_V1(_)
            | KeyshareFormat::EdDSA_V2(_)
            | KeyshareFormat::EdDSA_V3(_)
            | KeyshareFormat::TwoFactorAuth(_)
            | KeyshareFormat::Sr25519(_) => {
                Err("The key file contained a different key type, expecting ECDSA")
            }
        }
    }
}

impl TryFrom<KeyshareFormat> for EdDSA_V3 {
    type Error = &'static str;

    fn try_from(kf: KeyshareFormat) -> Result<Self, Self::Error> {
        match kf {
            KeyshareFormat::EdDSA_V1(eddsa_v1) => {
                let eddsa_v2 = Self {
                    party_index: eddsa_v1.key.party_index as usize,
                    threshold: eddsa_v1.threshold,
                    vss_scheme_vec: eddsa_v1.vss_scheme_vec.into_iter().map_into().collect(),
                    x_i: eddsa_v1.shared_key.x_i.into(),
                    y_sum: eddsa_v1.shared_key.y.into(),
                };
                Ok(eddsa_v2)
            }
            KeyshareFormat::EdDSA_V2(eddsa_v2) =>
                Ok(Self {
                    threshold: eddsa_v2.threshold,
                    party_index: eddsa_v2.party_index,
                    x_i: eddsa_v2.x_i.into(),
                    y_sum: eddsa_v2.y_sum.into(),
                    vss_scheme_vec: eddsa_v2.vss_scheme_vec.into_iter().map_into().collect(),
                }),
            KeyshareFormat::EdDSA_V3(eddsa_v2) => Ok(eddsa_v2),
            // Deserialising 2fa to eddsa key type as it is almost the same for purpose of regen
            KeyshareFormat::TwoFactorAuth(two_factor_auth) => {
                let two_factor_auth = two_factor_auth;
                let vss_scheme_vec = vec![two_factor_auth.vss_scheme.into()];
                match RecoveryCalculator::calculate_y_sum_from_vss_vec(&vss_scheme_vec) {
                    Ok(y_sum) => {
                        let eddsa_v2 = Self {
                            party_index: two_factor_auth.party_index,
                            threshold: two_factor_auth.threshold,
                            vss_scheme_vec: vss_scheme_vec.into_iter().map_into().collect(),
                            x_i: two_factor_auth.x_i.into(),
                            y_sum: y_sum.into(),
                        };
                        Ok(eddsa_v2)
                    }
                    Err(_) => Err("Unable to calculate y sum from the 2fa key file: {}"),
                }
            }
            KeyshareFormat::Sr25519(sr25519) => {
                let sr25519 = sr25519;
                let vss_scheme_vec = vec![sr25519.vss_scheme.into()];
                match RecoveryCalculator::calculate_y_sum_from_vss_vec(&vss_scheme_vec) {
                    Ok(y_sum) => {
                        let eddsa_v2 = Self {
                            party_index: sr25519.party_index,
                            threshold: sr25519.threshold,
                            vss_scheme_vec: vss_scheme_vec.into_iter().map_into().collect(),
                            x_i: sr25519.x_i.into(),
                            y_sum: y_sum,
                        };
                        Ok(eddsa_v2)
                    }
                    Err(_) => Err("Unable to calculate y sum from the Sr25519 key file: {}"),
                }
            }
            | KeyshareFormat::ECDSA_V1V2(_)
            | KeyshareFormat::ECDSA_V3(_)
            | KeyshareFormat::ECDSA_V4(_) => {
                Err("The key file contained a different key type, expecting EdDSA")
            }
        }
    }
}

impl TryFrom<KeyshareFormat> for TwoFactorAuth {
    type Error = &'static str;

    fn try_from(kf: KeyshareFormat) -> Result<Self, Self::Error> {
        match kf {
            KeyshareFormat::TwoFactorAuth(two_factor_auth) => Ok(two_factor_auth),
            _ => Err("The key file contained a different key type, expecting two factor auth"),
        }
    }
}

impl TryFrom<KeyshareFormat> for Sr25519 {
    type Error = &'static str;

    fn try_from(kf: KeyshareFormat) -> Result<Self, Self::Error> {
        match kf {
            KeyshareFormat::Sr25519(sr25519) => Ok(sr25519),
            _ => Err("The key file contained a different key type, expecting sr25519"),
        }
    }
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct ECDSA_V4 {
    pub threshold: usize,
    pub y_sum: Point<Secp256k1>,
    pub x_i: Scalar<Secp256k1>,
    pub party_index: usize,
    pub public_key_vec: Vec<Point<Secp256k1>>,
    pub vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub h1_h2_N_tilde_vec: Vec<DLogStatement>,
    pub paillier_dk: DecryptionKey,
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct ECDSA_V3 {
    pub threshold: usize,
    pub y_sum: WPoint<Secp256k1>,
    pub x_i: WScalar<Secp256k1>,
    pub party_index: usize,
    pub public_key_vec: Vec<WPoint<Secp256k1>>,
    pub vss_scheme_vec: Vec<WVerifiableSS<Secp256k1>>,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub h1_h2_N_tilde_vec: Vec<WDLogStatement>,
    pub paillier_dk: DecryptionKey,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Serialize, Deserialize)]
pub struct ECDSA_V1V2 {
    pub party_keys: ECKeysV1V2,
    pub shared_keys: WEcSharedKeys,
    pub public_key_vec: Vec<WPoint<Secp256k1>>,
    pub party_id: usize,
    pub vss_scheme_vec: Vec<WVerifiableSS<Secp256k1>>,
    pub paillier_key_vector: Vec<EncryptionKey>,
    pub y_sum: WPoint<Secp256k1>,
    pub h1_h2_N_tilde_vec: Vec<WDLogStatement>,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Serialize, Deserialize)]
pub struct EdDSA_V3 {
    pub threshold: usize,
    pub party_index: usize,
    pub x_i: Scalar<Ed25519>,
    pub y_sum: Point<Ed25519>,
    pub vss_scheme_vec: Vec<VerifiableSS<Ed25519>>,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Serialize, Deserialize)]
pub struct EdDSA_V2 {
    pub threshold: usize,
    pub party_index: usize,
    pub x_i: WScalar<Ed25519>,
    pub y_sum: WPoint<Ed25519>,
    pub vss_scheme_vec: Vec<WVerifiableSS<Ed25519>>,
}

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[derive(Clone, Serialize, Deserialize)]
pub struct EdDSA_V1 {
    pub key: WEdKeys,
    pub threshold: usize,
    pub shared_key: WEdSharedKeys,
    pub vss_scheme_vec: Vec<WVerifiableSS<Ed25519>>,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwoFactorAuth {
    pub twofa_code: Option<String>,
    pub threshold: usize,
    pub party_index: usize,
    pub x_i: WScalar<Ed25519>,
    pub vss_scheme: WVerifiableSS<Ed25519>,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sr25519 {
    pub secret_key: Option<SchnorrkelSecretKey>,
    pub threshold: usize,
    pub party_index: usize,
    pub x_i: WScalar<Ed25519>,
    pub vss_scheme: WVerifiableSS<Ed25519>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ECKeysV1V2 {
    u_i: WScalar<Secp256k1>,
    y_i: WPoint<Secp256k1>,
    dk: DecryptionKey,
    ek: EncryptionKey,
    party_index: usize,
    N_tilde: BigInt,
    h1: BigInt,
    h2: BigInt,
    xhi: BigInt,
    xhi_inv: Option<BigInt>,
}

#[allow(non_camel_case_types)]
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum KeyshareFormat {
    ECDSA_V1V2(ECDSA_V1V2),
    ECDSA_V3(ECDSA_V3),
    ECDSA_V4(ECDSA_V4),
    EdDSA_V1(EdDSA_V1),
    EdDSA_V2(EdDSA_V2),
    EdDSA_V3(EdDSA_V3),
    TwoFactorAuth(TwoFactorAuth),
    Sr25519(Sr25519),
}

pub struct Keystore;

impl Keystore {
    pub fn encrypt_and_save_key<T: CurrentKeyshareFormat>(
        keyshare: &T,
        key_id: &str,
        index: usize,
        write_access: &WriteOpts
    ) -> Result<()> {
        let mut contents = serde_json::to_string(keyshare)?;

        let encrypted_data = aes_encrypt(&contents.as_bytes(), TEMP_ENCRYPTION_KEY)?;
        contents = serde_json::to_string(&encrypted_data)?;

        FileSystem::add_keyfile(key_id, index, &contents, write_access)
    }

    pub fn encrypt_and_save_key_with_email<T: CurrentKeyshareFormat>(
        keyshare: &T,
        key_id: &str,
        index: usize,
        email: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        let mut contents = serde_json::to_string(keyshare)?;

        let encrypted_data = aes_encrypt(&contents.as_bytes(), TEMP_ENCRYPTION_KEY)?;
        contents = serde_json::to_string(&encrypted_data)?;

        FileSystem::add_keyfile_with_email(key_id, index, email, &contents, write_access)
    }

    pub fn save_key<T: CurrentKeyshareFormat>(
        keyshare: &T,
        key_id: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        let contents = serde_json::to_string(keyshare)?;

        FileSystem::add_keyfile(key_id, 0, &contents, write_access)
    }

    pub fn save_key_with_email<T: CurrentKeyshareFormat>(
        keyshare: &T,
        key_id: &str,
        email: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        let contents = serde_json::to_string(keyshare)?;

        FileSystem::add_keyfile_with_email(key_id, 0, email, &contents, write_access)
    }

    pub fn get_key(key_id: &str) -> Result<KeyshareFormat> {
        let data = FileSystem::read_keyfile(key_id, 0)?;
        Self::deserialize_key(&data)
    }

    pub fn get_key_with_email(key_id: &str, email: &str) -> Result<KeyshareFormat> {
        let file_path = FileSystem::find_keyfile_with_email(key_id, 0, email)?;
        let data = fs::read_to_string(file_path)?;
        Self::deserialize_key(&data)
    }

    pub fn get_encrypted_key(key_id: &str) -> Result<KeyshareFormat> {
        let decrypted = Self::decrypt_keyfile_to_string(key_id)?;
        Self::deserialize_key(&decrypted)
    }

    pub fn get_encrypted_key_with_email(key_id: &str, email: &str) -> Result<KeyshareFormat> {
        let decrypted = Self::decrypt_keyfile_to_string_with_email(key_id, email)?;
        Self::deserialize_key(&decrypted)
    }

    // This function should not need changing; if new keyshare formats are added they should be added directly to the KeyshareFormat enum.
    // This is just a weird case for ECDSA v1 as it was serialized in a non json standard way, so deserializer doesn't understand how to
    // deserialize it as an untagged KeyshareFormat variant.
    fn deserialize_key(data: &str) -> Result<KeyshareFormat> {
        let ks = match serde_json::from_str::<KeyshareFormat>(&data) {
            Ok(ks) => ks,
            Err(_) => {
                let ks = serde_json::from_str::<ECDSA_V1V2>(data)?;
                KeyshareFormat::ECDSA_V1V2(ks)
            }
        };
        Ok(ks)
    }

    fn decrypt_keyfile_to_string(key_id: &str) -> Result<String> {
        let contents = FileSystem::read_keyfile(key_id, 0)?;
        let data = serde_json::from_str::<EncryptedData>(&contents)?;
        let decrypted = aes_decrypt(&data, TEMP_ENCRYPTION_KEY)?;
        Ok(String::from_utf8(decrypted)?)
    }

    fn decrypt_keyfile_to_string_with_email(key_id: &str, email: &str) -> Result<String> {
        let file_path = FileSystem::find_keyfile_with_email(key_id, 0, email)?;
        let contents = fs::read_to_string(file_path)?;
        let data = serde_json::from_str::<EncryptedData>(&contents)?;
        let decrypted = aes_decrypt(&data, TEMP_ENCRYPTION_KEY)?;
        Ok(String::from_utf8(decrypted)?)
    }
}
