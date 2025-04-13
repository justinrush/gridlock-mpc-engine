use anyhow::{ bail, Result };
use curv::elliptic::curves::{ Curve, Ed25519, Scalar, Secp256k1 };
use curv::{ cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS, BigInt };
use itertools::Itertools;
use serde::{ Deserialize, Serialize };
use tracing::{ error, info };

use crate::command::{ JsonCommand, MsgContext };
use crate::storage::{ KeyshareAccessor, ECDSA, EDDSA };

const THRESHOLD: usize = 3;

#[derive(Deserialize, Serialize, Debug)]
pub struct EjectInfo {
    pub key_id: String,
    pub share_info: EjectShareInfo,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct KeyReconstructionResult {
    pub key_id: String,
    pub key: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum EjectShareInfo {
    Secp256k1(Scalar<Secp256k1>, usize),
    Ed25519(Scalar<Ed25519>, usize),
}

impl From<EDDSA> for EjectShareInfo {
    fn from(ed: EDDSA) -> Self {
        Self::Ed25519(ed.x_i.into(), ed.party_index)
    }
}

impl From<ECDSA> for EjectShareInfo {
    fn from(ec: ECDSA) -> Self {
        Self::Secp256k1(ec.x_i.into(), ec.party_index)
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct EjectSharesCommand {
    key_ids_to_eject: Vec<String>,
}

impl JsonCommand for EjectSharesCommand {
    type Response = Vec<EjectInfo>;

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        let key_ids = self.key_ids_to_eject.into_iter().unique().collect::<Vec<String>>();

        retrieve_eject_info_from_key_ids(&key_ids)
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct EjectKeysCommand {
    key_ids: Vec<String>,
    eject_info: Vec<Vec<EjectInfo>>,
}

impl JsonCommand for EjectKeysCommand {
    type Response = Vec<KeyReconstructionResult>;

    fn execute_message(mut self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        self.retrieve_keys()
    }
}

impl EjectKeysCommand {
    /// Combines two sets of imported keyshares with the set owned by this device to recover the associated private keys
    fn retrieve_keys(&mut self) -> Result<Vec<KeyReconstructionResult>> {
        let key_ids = self.key_ids.clone().into_iter().unique().collect::<Vec<String>>();
        let owned_shares = retrieve_eject_info_from_key_ids(&key_ids)?;

        self.eject_info.push(owned_shares);
        let reformed_keys = combine_keyshares(&key_ids, &self.eject_info);
        Ok(reformed_keys)
    }
}

fn retrieve_eject_info_from_key_ids(key_ids: &[String]) -> Result<Vec<EjectInfo>> {
    let eject_info = key_ids
        .iter()
        .filter_map(|key_id| {
            if let Ok(ka) = KeyshareAccessor::<ECDSA>::read_only(key_id) {
                let share_info = EjectShareInfo::from(ka.key);
                Some(EjectInfo {
                    key_id: key_id.to_string(),
                    share_info,
                })
            } else if let Ok(ka) = KeyshareAccessor::<EDDSA>::read_only(key_id) {
                let share_info = EjectShareInfo::from(ka.key);
                Some(EjectInfo {
                    key_id: key_id.to_string(),
                    share_info,
                })
            } else {
                None
            }
        })
        .collect();
    Ok(eject_info)
}

fn combine_keyshares(
    key_ids: &[String],
    eject_info_vec: &[Vec<EjectInfo>]
) -> Vec<KeyReconstructionResult> {
    key_ids
        .iter()
        .filter_map(|key_id| {
            let shares = collect_shares_by_key_id_from_supplied_keyshares(key_id, eject_info_vec);
            match reconstruct_key_from_collected_eject_info(&shares) {
                Ok(key) =>
                    Some(KeyReconstructionResult {
                        key_id: key_id.clone(),
                        key,
                    }),
                Err(err) => {
                    error!("Unable to reconstruct key with id {key_id}: {err}");
                    None
                }
            }
        })
        .collect()
}

fn reconstruct_key_from_collected_eject_info(eject_infos: &[EjectShareInfo]) -> Result<String> {
    if eject_infos.len() < THRESHOLD {
        bail!("Not enough keyshares found to reconstruct private key");
    }

    let mut secp_scalars = Vec::new();
    let mut ed25519_scalars = Vec::new();
    let mut indices = Vec::new();
    eject_infos.into_iter().for_each(|x| {
        match x {
            EjectShareInfo::Secp256k1(scalar, index) => {
                secp_scalars.push(scalar.clone());
                indices.push(*index);
            }
            EjectShareInfo::Ed25519(scalar, index) => {
                ed25519_scalars.push(scalar.clone());
                indices.push(*index);
            }
        }
    });

    let res = (if
        let Some(reconstructed_key) = reconstruct_key::<Secp256k1>(&indices, &secp_scalars)
    {
        serde_json::to_string(&reconstructed_key)
    } else if let Some(reconstructed_key) = reconstruct_key::<Ed25519>(&indices, &*ed25519_scalars) {
        serde_json::to_string(&reconstructed_key)
    } else {
        bail!(
            "Not enough keyshares of same key type found to reconstruct private key (this shouldn't happen!)"
        );
    })?;
    Ok(res)
}

fn collect_shares_by_key_id_from_supplied_keyshares(
    key_id: &str,
    eject_info_vec: &[Vec<EjectInfo>]
) -> Vec<EjectShareInfo> {
    eject_info_vec
        .iter()
        .enumerate()
        .filter_map(|(set_index, eject_info_set)| {
            match
                eject_info_set
                    .iter()
                    .filter(|x| x.key_id == key_id)
                    .next()
            {
                Some(EjectInfo { key_id: _, share_info }) => Some(share_info.clone()),
                None => {
                    info!("No eject info for key id {} in set {}", key_id, set_index);
                    None
                }
            }
        })
        .collect::<Vec<EjectShareInfo>>()
}

fn reconstruct_key<C>(indices: &[usize], shares: &[Scalar<C>]) -> Option<Scalar<C>> where C: Curve {
    if shares.len() != indices.len() || shares.len() < THRESHOLD {
        return None;
    }

    let points = indices
        .iter()
        .map(|i| {
            let index_bn = BigInt::from(*i as u32);
            index_bn.into()
        })
        .collect::<Vec<Scalar<C>>>();
    Some(VerifiableSS::<C>::lagrange_interpolation_at_zero(&points, &shares))
}

fn remove_first_and_last_and_backslash(value: &str) -> String {
    let mut chars = value.chars();
    chars.next();
    chars.next_back();
    chars.as_str().replace("\\", "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::arithmetic::traits::Converter;
    use curv::elliptic::curves::secp256_k1::Secp256k1;
    use curv::elliptic::curves::Scalar;

    #[test]
    fn can_combine_keyshares_to_reconstruct_secp_key() {
        let secret: Scalar<Secp256k1> = Scalar::from(
            &BigInt::from_str_radix(
                "679cfbe0538354f0bfb19c0eeb53910784783e84f3df025222e3914e0994c7fa",
                16
            ).unwrap()
        );

        let mut expected_result = Vec::new();
        expected_result.push(KeyReconstructionResult {
            key_id: "x".to_string(),
            key: serde_json::to_string(&secret).unwrap(),
        });

        let x_share1 = EjectInfo {
            key_id: "x".to_string(),
            share_info: EjectShareInfo::Secp256k1(
                Scalar::from(
                    &BigInt::from_str_radix(
                        "7b55069597f51c955cc12a16e350b06865f18457aa9878c806fff711a2e7aa3c",
                        16
                    ).unwrap()
                ),
                1
            ),
        };

        let x_share2 = EjectInfo {
            key_id: "x".to_string(),
            share_info: EjectShareInfo::Secp256k1(
                Scalar::from(
                    &BigInt::from_str_radix(
                        "522562921022117ee54e25d114004a8b2af352b6d2c8934ec0b00f8a5bc17e08",
                        16
                    ).unwrap()
                ),
                2
            ),
        };

        let x_share3 = EjectInfo {
            key_id: "x".to_string(),
            share_info: EjectShareInfo::Secp256k1(
                Scalar::from(
                    &BigInt::from_str_radix(
                        "ec0e0fd5bc0a33ad59588f3d7d625f6e8e2c86891bb7f2220fc639450458849f",
                        16
                    ).unwrap()
                ),
                3
            ),
        };

        let mut keyshares1 = Vec::new();
        keyshares1.push(x_share1);

        let mut keyshares2 = Vec::new();
        keyshares2.push(x_share2);

        let mut keyshares3 = Vec::new();
        keyshares3.push(x_share3);

        let mut keyshares = Vec::new();
        keyshares.push(keyshares1);
        keyshares.push(keyshares2);
        keyshares.push(keyshares3);

        let key_ids = vec!["x".to_string()];

        let result = combine_keyshares(&key_ids, &keyshares);

        assert_eq!(expected_result, result);
    }

    #[test]
    fn attempting_to_reconstruct_ed25519_key_will_produce_null() {
        let secret = Scalar::<Ed25519>::random();
        let indices = vec![2, 5, 9];
        let (_, secret_shares) = VerifiableSS::<Ed25519>::share_at_indices(2, 3, &secret, &indices);

        let y_share1 = EjectInfo {
            key_id: "y".to_string(),
            share_info: EjectShareInfo::Ed25519(secret_shares[0].clone(), indices[0] as usize),
        };

        let y_share2 = EjectInfo {
            key_id: "y".to_string(),
            share_info: EjectShareInfo::Ed25519(secret_shares[1].clone(), indices[1] as usize),
        };

        let y_share3 = EjectInfo {
            key_id: "y".to_string(),
            share_info: EjectShareInfo::Ed25519(secret_shares[2].clone(), indices[2] as usize),
        };

        let key_ids = vec!["y".to_string()];

        let mut keyshares1 = Vec::new();
        keyshares1.push(y_share1);

        let mut keyshares2 = Vec::new();
        keyshares2.push(y_share2);

        let mut keyshares3 = Vec::new();
        keyshares3.push(y_share3);

        let keyshares = vec![keyshares1, keyshares2, keyshares3];

        let result = combine_keyshares(&key_ids, &keyshares);

        let mut expected_result = Vec::new();
        expected_result.push(KeyReconstructionResult {
            key_id: "y".to_string(),
            key: serde_json::to_string(&secret).unwrap(),
        });
        assert_eq!(expected_result, result);
    }

    #[test]
    fn missing_keyshares_do_not_cause_complete_sets_to_fail() {
        let secret1 = Scalar::<Secp256k1>::random();
        let secret2 = Scalar::<Secp256k1>::random();
        let indices = vec![2, 5, 9];
        let indices2 = vec![7, 10, 90];
        let (_, secret_shares) = VerifiableSS::<Secp256k1>::share_at_indices(
            2,
            3,
            &secret1,
            &indices
        );
        let (_, secret_shares2) = VerifiableSS::<Secp256k1>::share_at_indices(
            2,
            3,
            &secret2,
            &indices2
        );

        let x_share1 = EjectInfo {
            key_id: "x".to_string(),
            share_info: EjectShareInfo::Secp256k1(secret_shares[0].clone(), indices[0] as usize),
        };

        let x_share2 = EjectInfo {
            key_id: "x".to_string(),
            share_info: EjectShareInfo::Secp256k1(secret_shares[1].clone(), indices[1] as usize),
        };

        let x_share3 = EjectInfo {
            key_id: "x".to_string(),
            share_info: EjectShareInfo::Secp256k1(secret_shares[2].clone(), indices[2] as usize),
        };

        let y_share1 = EjectInfo {
            key_id: "y".to_string(),
            share_info: EjectShareInfo::Secp256k1(secret_shares2[0].clone(), indices2[0] as usize),
        };

        let y_share3 = EjectInfo {
            key_id: "y".to_string(),
            share_info: EjectShareInfo::Secp256k1(secret_shares2[2].clone(), indices2[2] as usize),
        };

        let keyshares1 = vec![x_share1, y_share1];
        let keyshares2 = vec![x_share2];
        let keyshares3 = vec![x_share3, y_share3];

        let key_ids = vec!["x".to_string(), "y".to_string()];
        let keyshares = vec![keyshares1, keyshares2, keyshares3];

        let result = combine_keyshares(&key_ids, &keyshares);

        let mut expected_result = Vec::new();
        expected_result.push(KeyReconstructionResult {
            key_id: "x".to_string(),
            key: serde_json::to_string(&secret1).unwrap(),
        });

        assert_eq!(expected_result, result);
    }
}
