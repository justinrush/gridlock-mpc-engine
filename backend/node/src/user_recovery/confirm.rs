use crate::auth::e2e_decrypt;
use crate::node::NodeIdentity;
use crate::storage::fs::{ FileSystem, WriteOpts };
use crate::storage::key_metadata_store::KeyMetadataStore;
use anyhow::Result;
use nats::Message;
use serde::{ Deserialize, Serialize };
use std::thread;
use tracing::{ error, info };

#[derive(Clone, Serialize, Deserialize)]
pub struct ConfirmRecoverySession {
    pub key_id: String,
    pub client_e2e_public_key: String,
    pub encrypted_recovery_confirmation: String,
    pub email: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RecoveryConfirmationData {
    recovery_challenge: String,
    client_identity_public_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryConfirmation {
    pub success: bool,
    pub access_key: Option<String>,
    pub error: Option<String>,
}

pub fn handle_new_session_message(app: &crate::App, message: Message) {
    let confirmation = match serde_json::from_slice::<ConfirmRecoverySession>(&message.data[..]) {
        Ok(confirmation) => confirmation,
        Err(err) => {
            error!("Incorrect recovery confirmation message format: {}", err);
            return;
        }
    };

    let nc = app.nc.clone();
    thread::Builder
        ::new()
        .name("user_recovery_confirmation".to_string())
        .spawn(move || {
            if let Err(err) = confirm_recovery_session(nc, confirmation) {
                error!("Recovery confirmation error: {}", err);
            }
        })
        .unwrap();
}

fn confirm_recovery_session(
    conn: nats::Connection,
    confirmation: ConfirmRecoverySession
) -> Result<()> {
    let node = match NodeIdentity::load() {
        Ok(node) => node,
        Err(err) => {
            error!("Failed to load node identity: {}", err);
            return Err(err.into());
        }
    };

    // Validate and extract the email address for recovery
    let recovery_email = if let Some(email) = &confirmation.email {
        info!("Processing recovery confirmation for email: {}", email);
        email.clone()
    } else {
        let err = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Email is required for recovery confirmation"
        );
        error!("{}", err);
        return Err(err.into());
    };

    // Decrypt and validate the recovery confirmation
    let decrypted_confirmation = e2e_decrypt(
        &confirmation.encrypted_recovery_confirmation,
        &node.e2e_private_key,
        &confirmation.client_e2e_public_key
    )?;

    let recovery_data: RecoveryConfirmationData = match
        serde_json::from_slice(&decrypted_confirmation)
    {
        Ok(recovery_data) => recovery_data,
        Err(err) => {
            error!("Failed to parse recovery confirmation data: {}", err);
            return Err(err.into());
        }
    };

    // Verify the recovery challenge
    let stored_challenge = match KeyMetadataStore::get_user_level("challenge", &recovery_email) {
        Ok(challenge) => challenge,
        Err(err) => {
            error!("Failed to load recovery challenge: {}", err);
            return Err(err.into());
        }
    };

    if recovery_data.recovery_challenge != stored_challenge {
        error!("Invalid recovery challenge provided");
        return Ok(());
    }

    // Store client's E2E public key for future communication
    if
        let Err(e) = KeyMetadataStore::save_user_level(
            &confirmation.client_e2e_public_key,
            "e2e_key",
            &recovery_email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to store client_e2e_public_key: {}", e);
    }

    // Store the new client identity public key
    if
        let Err(err) = KeyMetadataStore::save_user_level(
            &recovery_data.client_identity_public_key,
            "new_identity_key",
            &recovery_email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to save client identity public key: {}", err);
        return Err(err.into());
    }
    info!("Client identity public key saved successfully for key_id: {}", confirmation.key_id);

    // Retrieve the access key for the specified key_id
    let access_key = match KeyMetadataStore::get(&confirmation.key_id, "access", &recovery_email) {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to load access key: {}", err);
            return Err(err.into());
        }
    };

    info!("Recovery confirmed successfully for key_id: {}", confirmation.key_id);

    // Convert recovery key to signing key
    let recovery_key = match KeyMetadataStore::get_user_level("recovery", &recovery_email) {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to load recovery key: {}", err);
            return Err(err.into());
        }
    };

    let signing_key = recovery_key.replace("node_recovery_", "node_signing_");
    info!("Converted recovery key to signing key for key_id: {}", confirmation.key_id);

    // Update the access key with the new signing key
    if
        let Err(err) = KeyMetadataStore::save(
            &signing_key,
            &confirmation.key_id,
            "access",
            &recovery_email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to update access key: {}", err);
        return Err(err.into());
    }
    info!("Access key updated successfully for key_id: {}", confirmation.key_id);

    // Clean up temporary recovery files
    if let Err(err) = KeyMetadataStore::remove_user_level("challenge", &recovery_email) {
        error!("Failed to remove challenge file: {}", err);
    }
    if let Err(err) = KeyMetadataStore::remove_user_level("recovery", &recovery_email) {
        error!("Failed to remove recovery key file: {}", err);
    }

    Ok(())
}
