use crate::storage::fs::FileSystem;
use crate::storage::{ KeyshareAccessor, ECDSA, EDDSA };
use anyhow::{ bail, Result };
use serde::{ Deserialize, Serialize };
use tracing::error;

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct KeyshareIndex {
    pub key_id: String,
    pub index: usize,
}

pub fn get_all_keyshare_indices() -> Result<Vec<KeyshareIndex>> {
    let key_ids = FileSystem::find_all_key_ids()?;
    let all_keyshares = get_all_keyshare_indices_by_key_id(&key_ids)?;
    Ok(all_keyshares)
}

fn get_all_keyshare_indices_by_key_id(key_ids: &[String]) -> Result<Vec<KeyshareIndex>> {
    let results = key_ids
        .iter()
        .map(|key_id| {
            let index = get_keyshare_index(&key_id);
            (key_id, index)
        })
        .filter(|(_, index)| index.is_ok())
        .map(|(key_id, index)| KeyshareIndex {
            key_id: key_id.clone(),
            index: index.unwrap(),
        })
        .collect();
    Ok(results)
}

fn get_keyshare_index(key_id: &str) -> Result<usize> {
    match KeyshareAccessor::<ECDSA>::read_only(&key_id) {
        Ok(ka) => Ok(ka.key.party_index),
        Err(err1) =>
            match KeyshareAccessor::<EDDSA>::read_only(&key_id) {
                Ok(ka) => Ok(ka.key.party_index),
                Err(err2) => {
                    let err_msg = format!(
                        "Could not decrypt key file to expected format: {}, {}",
                        err1,
                        err2
                    );
                    error!("{}", &err_msg);
                    bail!("{}", &err_msg)
                }
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_failure_if_keyshare_not_found() {
        let key_ids = [String::from("0f64e0eb-ed88-454c-97d9-ad112a5ac267")].to_vec();
        let res = get_all_keyshare_indices_by_key_id(&key_ids);
        assert!(res.is_ok())
    }
}
