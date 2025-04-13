use crate::storage::{ KeyshareAccessor, ECDSA, EDDSA };
use anyhow::{ bail, Result };
use tracing::error;

pub fn decrypt_ghost_shares(key_id: &str) -> Result<usize> {
    match KeyshareAccessor::<ECDSA>::modifiable_from_encrypted(&key_id) {
        Ok(mut ka) => {
            ka.update_saved_key()?;
            Ok(ka.key.party_index)
        }
        Err(err1) =>
            match KeyshareAccessor::<EDDSA>::modifiable_from_encrypted(&key_id) {
                Ok(mut ka) => {
                    ka.update_saved_key()?;
                    Ok(ka.key.party_index)
                }
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
