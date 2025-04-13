use crate::storage::fs::{ FileSystem, WriteOpts };
use anyhow::Result;

/// Store for key-related metadata that isn't a KeyInfo object
/// Handles string-based data like access tokens, recovery codes, emails, etc.
pub struct KeyMetadataStore;

impl KeyMetadataStore {
    /// Save key-specific metadata
    pub fn save(
        content: &str,
        key_id: &str,
        metadata_type: &str,
        email: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        FileSystem::add_key_metadata_file(key_id, metadata_type, content, email, write_access)
    }

    /// Get key-specific metadata
    pub fn get(key_id: &str, metadata_type: &str, email: &str) -> Result<String> {
        FileSystem::read_key_metadata_file(key_id, metadata_type, email)
    }

    /// Remove key-specific metadata
    pub fn remove(key_id: &str, metadata_type: &str, email: &str) -> Result<()> {
        FileSystem::remove_key_metadata_file(key_id, metadata_type, email)
    }

    /// Save user metadata
    pub fn save_user_level(
        content: &str,
        metadata_type: &str,
        email: &str,
        write_access: &WriteOpts
    ) -> Result<()> {
        FileSystem::add_user_metadata_file(metadata_type, content, email, write_access)
    }

    /// Get user metadata
    pub fn get_user_level(metadata_type: &str, email: &str) -> Result<String> {
        FileSystem::read_user_metadata_file(metadata_type, email)
    }

    /// Remove user metadata
    pub fn remove_user_level(metadata_type: &str, email: &str) -> Result<()> {
        FileSystem::remove_user_metadata_file(metadata_type, email)
    }
}
