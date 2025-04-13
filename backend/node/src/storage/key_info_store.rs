use crate::storage::fs::{ FileSystem, WriteOpts };
use anyhow::{ Context, Result };
use shared::key_info::KeyInfo;

pub struct KeyInfoStore;

impl KeyInfoStore {
    pub fn save_key_info(keyinfo: &KeyInfo, key_id: &str, write_access: &WriteOpts) -> Result<()> {
        let contents = serde_json::to_string(keyinfo)?;
        FileSystem::add_key_info_file(key_id, &contents, write_access)
    }

    pub fn get_key_info(key_id: &str) -> Result<KeyInfo> {
        let data = FileSystem::read_key_info_file(key_id)?;
        serde_json::from_str(&data).context("Deserialize key info")
    }
}
