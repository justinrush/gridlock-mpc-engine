mod calculator;
mod commands;
mod encryption;
mod helper_role;
pub mod orchestrate;
pub mod recovery_session;
mod target_role;

use crate::command::{ JsonCommand, MsgContext };
use crate::recovery::orchestrate::orchestrate;
use crate::storage::KeyshareAccessor;
use crate::storage::ECDSA;
use anyhow::{ anyhow, Result };
pub use calculator::RecoveryCalculator;
pub use commands::GetPaillierKeysCommand;
use curv::arithmetic::Zero;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{ Curve, Ed25519, Point, Scalar, Secp256k1 };
use curv::BigInt;
use derive_more::Display;
use itertools::Itertools;
use paillier::EncryptionKey;
use serde::{ Deserialize, Serialize };
use shared::key_info::NodeId;
use shared::recovery::Key;
use std::collections::HashMap;
use zk_paillier::zkproofs::DLogStatement;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RecoveryCommand {
    #[serde(flatten)]
    kind: Key,
    key_id: String,
    session_id: String,
    new_node_id: NodeId,
    new_node_public_key: String,
    old_node_id: NodeId,
    party_nodes: Vec<NodeId>,
    email: String,
}

impl JsonCommand for RecoveryCommand {
    type Response = RecoveryResponse;

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        orchestrate(self, ctx).map(|_| RecoveryResponse::Completed)
    }
}

#[derive(Serialize)]
pub enum RecoveryResponse {
    Completed,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum RecoveryRole {
    Helper,
    Target,
}

pub struct Party {
    pub party_index: usize,
    pub all_parties: Vec<usize>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EdDSARecoveryPackage {
    pub share_recovery_info: ShareRecoveryInfo<Ed25519>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ECDSARecoveryPackage {
    pub share_recovery_info: ShareRecoveryInfo<Secp256k1>,
    pub h1_h2_N_tilde_vec: Vec<DLogStatement>,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub public_key_vec: Vec<Point<Secp256k1>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ShareRecoveryInfo<C> where C: Curve {
    pub partial_secret: Scalar<C>,
    pub vss_vec: Vec<VerifiableSS<C>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MultiplePointContribution<C> where C: Curve {
    pub lost_point: Scalar<C>,
    pub zero_point: Scalar<C>,
}

// This enum needed to save api contract with node js recovery logic
#[derive(Serialize, Clone, Deserialize, Debug)]
#[serde(untagged)]
pub enum RecoveryValidationResult {
    ECDSA(ValidatedWithEksResult),
    EDDSA(ValidatedResult),
    Error(ValidationErrorResult),
}

impl RecoveryValidationResult {
    pub fn validated() -> RecoveryValidationResult {
        RecoveryValidationResult::EDDSA(ValidatedResult::Validated)
    }

    pub fn validated_with_eks(eks: EncryptionKey) -> RecoveryValidationResult {
        RecoveryValidationResult::ECDSA(ValidatedWithEksResult::Validated(eks))
    }

    pub fn error(err: String) -> RecoveryValidationResult {
        RecoveryValidationResult::Error(ValidationErrorResult::ValidationError(err))
    }
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub enum ValidatedWithEksResult {
    Validated(EncryptionKey),
}

impl ValidatedWithEksResult {
    pub fn eks(self) -> EncryptionKey {
        match self {
            ValidatedWithEksResult::Validated(eks) => eks,
        }
    }
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub enum ValidatedResult {
    Validated,
}

#[derive(Serialize, Clone, Deserialize, Debug, Display)]
pub enum ValidationErrorResult {
    ValidationError(String),
}

pub fn update_paillier_keys(
    key_accessor: &mut KeyshareAccessor<ECDSA>,
    keyshare_index: usize,
    new_ek: EncryptionKey
) -> Result<()> {
    let mut eks = key_accessor.key.paillier_key_vec.clone();

    // pad eks vec if keyshare_index is bigger
    if keyshare_index >= eks.len() {
        let default = EncryptionKey::from(&BigInt::zero());
        eks = eks
            .into_iter()
            .pad_using(keyshare_index, |_| default.clone())
            .collect_vec();
    }

    replace_elem_in_vec(&mut eks, keyshare_index - 1, new_ek)?;
    save_new_paillier_keys(key_accessor, eks)
}

pub fn save_new_paillier_keys(
    key_accessor: &mut KeyshareAccessor<ECDSA>,
    new_eks: Vec<EncryptionKey>
) -> Result<()> {
    key_accessor.key.paillier_key_vec = new_eks;
    key_accessor.update_saved_key()
}

pub fn replace_elem_in_vec<T: Clone>(old_vec: &mut [T], index: usize, new_value: T) -> Result<()> {
    let elem = old_vec
        .get_mut(index)
        .ok_or(anyhow!("Unable to access element at index {} to replace its value", index))?;
    *elem = new_value;
    Ok(())
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
