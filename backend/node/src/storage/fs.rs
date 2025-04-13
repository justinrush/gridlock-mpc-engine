use crate::config::{ Config, ConfigProvider };
use anyhow::{ anyhow, bail, Result };
use glob::glob;
use regex::Regex;
use std::fs;
use std::path::PathBuf;
use tracing::info;

pub struct FileSystem;

#[derive(PartialEq)]
pub enum WriteOpts {
    /// Only write if file does not exist; file will not get overwritten
    CreateNewOnly,
    /// File can be created new or modified if pre-existing
    Modify,
}

impl FileSystem {
    pub fn add_keyfile(
        key_id: &str,
        index: usize,
        content: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        let filepath = Config::get_key_storage_path(key_id, index);

        if write_access == &WriteOpts::CreateNewOnly && filepath.exists() {
            bail!("Tried to write to a keyfile that already exists");
        }

        fs::write(filepath, content)?;
        Ok(())
    }

    pub fn add_keyfile_with_email(
        key_id: &str,
        index: usize,
        email: &str,
        content: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        // Ensure the account directory exists
        Self::ensure_account_directory_exists(email, Some(key_id))?;

        // Create path for the keyfile in the user's directory
        let mut filepath = Config::get_gridlock_directory();
        filepath.push("accounts");
        filepath.push(email);
        filepath.push("keys");
        filepath.push(key_id);

        if index == 0 {
            filepath.push(format!("keyshare-{}.json", key_id));
        } else {
            filepath.push(format!("keyshare-{}-{}.json", key_id, index));
        }

        if write_access == &WriteOpts::CreateNewOnly && filepath.exists() {
            bail!("Tried to write to a keyfile that already exists");
        }

        fs::write(filepath, content)?;
        Ok(())
    }

    pub fn add_key_info_file(key_id: &str, content: &str, write_access: &WriteOpts) -> Result<()> {
        let filepath = Config::get_key_info_storage_path(key_id);

        if write_access == &WriteOpts::CreateNewOnly && filepath.exists() {
            bail!("Tried to write key info that already exists");
        }

        fs::write(filepath, content)?;
        Ok(())
    }

    pub fn read_keyfile(key_id: &str, index: usize) -> Result<String> {
        let filename = Config::get_key_storage_path(key_id, index);
        let kf = fs::read_to_string(filename)?;
        Ok(kf)
    }

    pub fn find_keyfile_with_email(key_id: &str, index: usize, email: &str) -> Result<PathBuf> {
        // Build path for the keyfile in the account directory
        let mut filepath = Config::get_gridlock_directory();
        filepath.push("accounts");
        filepath.push(email);
        filepath.push("keys");
        filepath.push(key_id);

        if index == 0 {
            filepath.push(format!("keyshare-{}.json", key_id));
        } else {
            filepath.push(format!("keyshare-{}-{}.json", key_id, index));
        }

        if !filepath.exists() {
            bail!("Keyfile not found for key_id: {}, index: {}, email: {}", key_id, index, email);
        }

        Ok(filepath)
    }

    pub fn read_key_info_file(key_id: &str) -> Result<String> {
        let filename = Config::get_key_info_storage_path(key_id);
        let kf = fs::read_to_string(filename)?;
        Ok(kf)
    }

    pub fn save_node_identity(node_params: &str) -> Result<()> {
        let mut filepath = Config::get_gridlock_directory();
        filepath.push("node.json");
        fs::write(filepath, node_params)?;
        Ok(())
    }

    pub fn read_node_identity() -> Result<String> {
        let mut filepath = Config::get_gridlock_directory();
        filepath.push("node.json");
        let info = fs::read_to_string(filepath)?;
        Ok(info)
    }

    pub fn find_all_key_ids() -> Result<Vec<String>> {
        let keyfiles = Self::find_all_key_files()?;
        let key_ids = keyfiles
            .iter()
            .map(|f| Self::file_path_to_key_id(f))
            .filter_map(|x| x)
            .collect();

        Ok(key_ids)
    }

    fn find_all_key_files() -> Result<Vec<PathBuf>> {
        let filepath = Config::get_gridlock_directory();
        let search_term = filepath
            .to_str()
            .and_then(|s| {
                let mut search_term = String::from(s);
                search_term.push_str("/keys--*.json");
                Some(search_term)
            })
            .ok_or(anyhow!("Could not create search"))?;

        let results = glob(&search_term)?.into_iter().filter_map(Result::ok).collect();
        Ok(results)
    }

    fn file_path_to_key_id(filepath: &PathBuf) -> Option<String> {
        let re = Regex::new(r"keys--(.*).json$").ok()?;
        filepath
            .to_str()
            .and_then(|fp| re.captures(fp))
            .and_then(|caps| caps.get(1))
            .and_then(|key_id| Some(String::from(key_id.as_str())))
    }

    // Helper function to get the key metadata file path
    fn get_key_metadata_file_path(key_id: &str, metadata_type: &str, email: &str) -> PathBuf {
        // Build the path based on the structure
        let mut filepath = Config::get_gridlock_directory();
        filepath.push("accounts");
        filepath.push(email);

        if metadata_type == "access" {
            // access_key is stored directly in the email folder
            filepath.push("access_key");
        } else {
            // Other types go in the keys/keyId directory
            filepath.push("keys");
            filepath.push(key_id);

            // Format the filename based on the metadata type
            if metadata_type == "keys" {
                filepath.push(format!("keyshare-{}.json", key_id));
            } else {
                filepath.push(format!("{}-{}", metadata_type, key_id));
            }
        }

        filepath
    }

    // Helper to ensure account directory structure exists
    fn ensure_account_directory_exists(email: &str, key_id: Option<&str>) -> Result<()> {
        let mut filepath = Config::get_gridlock_directory();
        filepath.push("accounts");
        fs::create_dir_all(&filepath)?;

        filepath.push(email);
        fs::create_dir_all(&filepath)?;

        // Create the keys directory
        filepath.push("keys");
        fs::create_dir_all(&filepath)?;

        // If a key_id is provided, create the key-specific directory
        if let Some(key_id) = key_id {
            filepath.push(key_id);
            fs::create_dir_all(&filepath)?;
        }

        Ok(())
    }

    pub fn add_key_metadata_file(
        key_id: &str,
        metadata_type: &str,
        content: &str,
        email: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        let filepath = Self::get_key_metadata_file_path(key_id, metadata_type, email);

        // Ensure the directory exists
        if let Some(parent) = filepath.parent() {
            fs::create_dir_all(parent)?;
        }

        if write_access == &WriteOpts::CreateNewOnly && filepath.exists() {
            bail!("Tried to write key metadata that already exists");
        }

        fs::write(filepath, content)?;
        Ok(())
    }

    pub fn read_key_metadata_file(
        key_id: &str,
        metadata_type: &str,
        email: &str
    ) -> Result<String> {
        let filepath = Self::get_key_metadata_file_path(key_id, metadata_type, email);

        if !filepath.exists() {
            bail!("Metadata file not found for key_id: {}, type: {}", key_id, metadata_type);
        }

        let content = fs::read_to_string(filepath)?;
        Ok(content)
    }

    pub fn remove_key_metadata_file(key_id: &str, metadata_type: &str, email: &str) -> Result<()> {
        let filepath = Self::get_key_metadata_file_path(key_id, metadata_type, email);

        if !filepath.exists() {
            bail!(
                "Key metadata file does not exist for id `{}` and type `{}`",
                key_id,
                metadata_type
            );
        }

        fs::remove_file(filepath)?;
        Ok(())
    }

    pub fn get_gridlock_directory() -> Result<PathBuf> {
        Ok(Config::get_gridlock_directory())
    }

    // Get the file path for user metadata
    fn get_user_metadata_file_path(metadata_type: &str, email: &str) -> PathBuf {
        let mut filepath = Config::get_gridlock_directory();
        filepath.push("accounts");
        filepath.push(email);

        // Add the metadata type as the filename
        filepath.push(metadata_type);

        filepath
    }

    // Function to add user metadata files
    pub fn add_user_metadata_file(
        metadata_type: &str,
        content: &str,
        email: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        let filepath = Self::get_user_metadata_file_path(metadata_type, email);

        // Ensure the directory exists
        if let Some(parent) = filepath.parent() {
            fs::create_dir_all(parent)?;
        }

        if write_access == &WriteOpts::CreateNewOnly && filepath.exists() {
            bail!("Tried to write user metadata that already exists");
        }

        fs::write(filepath, content)?;
        Ok(())
    }

    // Function to read user metadata files
    pub fn read_user_metadata_file(metadata_type: &str, email: &str) -> Result<String> {
        let filepath = Self::get_user_metadata_file_path(metadata_type, email);

        if !filepath.exists() {
            bail!("User metadata file not found for type: {}", metadata_type);
        }

        let content = fs::read_to_string(filepath)?;
        Ok(content)
    }

    // Function to remove user metadata files
    pub fn remove_user_metadata_file(metadata_type: &str, email: &str) -> Result<()> {
        let filepath = Self::get_user_metadata_file_path(metadata_type, email);

        if !filepath.exists() {
            bail!("User metadata file does not exist for type: {}", metadata_type);
        }

        fs::remove_file(filepath)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_get_key_id_from_pathbuf() {
        let filepath = PathBuf::from(r"/gridlock/keys--1b2359cf-e7d1-44e9-a8c2-daebdce9a89f.json");
        assert_eq!(
            FileSystem::file_path_to_key_id(&filepath),
            Some(String::from("1b2359cf-e7d1-44e9-a8c2-daebdce9a89f"))
        )
    }
}
