use super::fs::WriteOpts;
use crate::storage::key_store::{ CurrentKeyshareFormat, KeyshareFormat, Keystore };

use anyhow::{ anyhow, bail, Result };
use std::convert::TryFrom;
use std::fmt::Display;

// TODO: do we need keshare access? Looks like unnessecary abstraction

pub struct KeyshareAccessor<K> {
    pub key: K,
    key_saver: Option<KeyshareSaver>,
}

impl<K> KeyshareAccessor<K>
    where K: CurrentKeyshareFormat, <K as TryFrom<KeyshareFormat>>::Error: Display
{
    pub fn read_only(key_id: &str) -> Result<Self> {
        Self::accessor_with_opts(key_id, AccessOpts::Standard, None)
    }

    pub fn read_only_with_email(key_id: &str, email: &str) -> Result<Self> {
        Self::accessor_with_opts_and_email(key_id, AccessOpts::Standard, None, email)
    }

    pub fn modifiable_from_encrypted(key_id: &str) -> Result<Self> {
        Self::accessor_with_opts(key_id, AccessOpts::FromEncrypted, Some(WriteOpts::Modify))
    }

    pub fn modifiable_from_encrypted_with_email(key_id: &str, email: &str) -> Result<Self> {
        Self::accessor_with_opts_and_email(
            key_id,
            AccessOpts::FromEncrypted,
            Some(WriteOpts::Modify),
            email
        )
    }

    pub fn modifiable(key_id: &str) -> Result<Self> {
        Self::accessor_with_opts(key_id, AccessOpts::Standard, Some(WriteOpts::Modify))
    }

    pub fn modifiable_with_email(key_id: &str, email: &str) -> Result<Self> {
        Self::accessor_with_opts_and_email(
            key_id,
            AccessOpts::Standard,
            Some(WriteOpts::Modify),
            email
        )
    }

    fn accessor_with_opts(
        key_id: &str,
        access_opts: AccessOpts,
        write_access: Option<WriteOpts>
    ) -> Result<Self> {
        let key_format = (match access_opts {
            AccessOpts::Standard => Keystore::get_key(key_id),
            AccessOpts::FromEncrypted => Keystore::get_encrypted_key(key_id),
        })?;

        let key = K::try_from(key_format).map_err(|err| anyhow!("{}", err))?;

        // Accessed key will be saved without encryption regardless of whether it was stored encrypted - this is what we need currently
        let key_saver: Option<KeyshareSaver> = write_access.and_then(|write_access| {
            Some(KeyshareSaver::new_with_write_opts(key_id, write_access))
        });

        Ok(Self { key, key_saver })
    }

    fn accessor_with_opts_and_email(
        key_id: &str,
        access_opts: AccessOpts,
        write_access: Option<WriteOpts>,
        email: &str
    ) -> Result<Self> {
        let key_format = (match access_opts {
            AccessOpts::Standard => Keystore::get_key_with_email(key_id, email),
            AccessOpts::FromEncrypted => Keystore::get_encrypted_key_with_email(key_id, email),
        })?;

        let key = K::try_from(key_format).map_err(|err| anyhow!("{}", err))?;

        // Accessed key will be saved without encryption regardless of whether it was stored encrypted - this is what we need currently
        let key_saver: Option<KeyshareSaver> = write_access.and_then(|write_access| {
            Some(KeyshareSaver::new_with_write_opts(key_id, write_access).with_email(email))
        });

        Ok(Self { key, key_saver })
    }

    pub fn update_saved_key(&mut self) -> Result<()> {
        if let Some(saver) = &mut self.key_saver {
            return saver.save_key(&self.key);
        }
        bail!(
            "Error trying to save a key without a keyshare accessor which allows creation/modification of keyshares"
        );
    }
}

pub enum AccessOpts {
    Standard,
    FromEncrypted,
}

pub struct KeyshareSaver {
    key_id: String,
    encryption: EncryptionOpts,
    write_access: WriteOpts,
    email: Option<String>,
}

pub enum EncryptionOpts {
    None,
    EncryptAndSaveWithSpecialIndex(usize),
}

impl KeyshareSaver {
    /// For key generation (so we can't replace existing keyshare)
    pub fn new_creator(key_id: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            encryption: EncryptionOpts::None,
            write_access: WriteOpts::CreateNewOnly,
            email: None,
        }
    }

    /// For key regeneration target (so we can replace existing keyshare if needed)
    pub fn new_creator_modifier(key_id: &str) -> Self {
        Self {
            key_id: key_id.to_string(),
            encryption: EncryptionOpts::None,
            write_access: WriteOpts::Modify,
            email: None,
        }
    }

    /// For new ghost share
    pub fn new_encryptor(key_id: &str, thread_index: usize) -> Self {
        Self {
            key_id: key_id.to_string(),
            encryption: EncryptionOpts::EncryptAndSaveWithSpecialIndex(thread_index),
            write_access: WriteOpts::CreateNewOnly,
            email: None,
        }
    }

    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    pub fn save_key<K: CurrentKeyshareFormat>(&self, keyshare: &K) -> Result<()> {
        match self.encryption {
            EncryptionOpts::None => {
                if let Some(email) = &self.email {
                    Keystore::save_key_with_email(keyshare, &self.key_id, email, &self.write_access)
                } else {
                    Keystore::save_key(keyshare, &self.key_id, &self.write_access)
                }
            }
            EncryptionOpts::EncryptAndSaveWithSpecialIndex(thread_index) => {
                if let Some(email) = &self.email {
                    Keystore::encrypt_and_save_key_with_email(
                        keyshare,
                        &self.key_id,
                        thread_index,
                        email,
                        &self.write_access
                    )
                } else {
                    Keystore::encrypt_and_save_key(
                        keyshare,
                        &self.key_id,
                        thread_index,
                        &self.write_access
                    )
                }
            }
        }
    }

    /// Only for use from keyshare accessor
    fn new_with_write_opts(key_id: &str, write_access: WriteOpts) -> Self {
        Self {
            key_id: key_id.to_string(),
            encryption: EncryptionOpts::None,
            write_access,
            email: None,
        }
    }
}
