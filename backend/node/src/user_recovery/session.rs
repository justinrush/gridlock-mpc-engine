use crate::auth::{ e2e_decrypt, e2e_encrypt };
use crate::node::NodeIdentity;
use crate::storage::fs::{ FileSystem, WriteOpts };
use crate::storage::key_metadata_store::KeyMetadataStore;
use crate::App;
use anyhow::Result;
use nats::{ rustls::client, Message };
use serde::{ Deserialize, Serialize };
use std::thread;
use tracing::{ error, info };
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct NewUserRecoverySession {
    pub key_id: String,
    pub client_e2e_public_key: String,
    pub encrypted_recovery_key: String,
    pub email: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct E2EData {
    pub client_e2e_public_key: String,
    pub encrypted_recovery_key: String,
}

pub fn handle_new_session_message(app: &App, message: Message) {
    let session = match serde_json::from_slice::<NewUserRecoverySession>(&message.data[..]) {
        Ok(session) => session,
        Err(err) => {
            error!("Incorrect user recovery message format: {}", err);
            return;
        }
    };

    let nc = app.nc.clone();
    thread::Builder
        ::new()
        .name("user_recovery_session".to_string())
        .spawn(move || {
            if let Err(err) = recovery_session(nc, session) {
                error!("Recovery session error: {}", err);
            }
        })
        .unwrap();
}

fn recovery_session(conn: nats::Connection, session: NewUserRecoverySession) -> anyhow::Result<()> {
    let node = match NodeIdentity::load() {
        Ok(node) => node,
        Err(err) => {
            error!("Failed to load node identity: {}", err);
            return Err(err.into());
        }
    };

    // Validate and extract the email address for recovery
    let recovery_email = if let Some(email) = &session.email {
        info!("Processing recovery request for email: {}", email);
        email.clone()
    } else {
        let err = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Email is required for recovery"
        );
        error!("{}", err);
        return Err(err.into());
    };

    // Decrypt and store the recovery key
    let decrypted_recovery_key = e2e_decrypt(
        &session.encrypted_recovery_key,
        &node.e2e_private_key,
        &session.client_e2e_public_key
    )?;

    let recovery_key_str = String::from_utf8(decrypted_recovery_key)?;

    // Store client's E2E public key for future communication
    if
        let Err(e) = KeyMetadataStore::save_user_level(
            &session.client_e2e_public_key,
            "e2e_key",
            &recovery_email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to store client_e2e_public_key: {}", e);
    }

    // Save the recovery key for later use
    if
        let Err(e) = KeyMetadataStore::save_user_level(
            &recovery_key_str,
            "recovery",
            &recovery_email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to save recovery key: {}", e);
        return Err(e);
    }

    // Generate and encrypt recovery challenge
    let recovery_challenge = Uuid::new_v4().to_string();
    let challenge_bundle =
        serde_json::json!({
        "guardian_node_id": node.node_id,
        "recovery_challenge": recovery_challenge,
        "recovery_key": recovery_key_str,
    });

    let encrypted_bundle = match
        e2e_encrypt(
            challenge_bundle.to_string().as_bytes(),
            &session.client_e2e_public_key,
            &node.e2e_private_key
        )
    {
        Ok(bundle) => bundle,
        Err(err) => {
            error!("Failed to encrypt challenge bundle: {}", err);
            return Err(err);
        }
    };

    // Store the recovery challenge for verification
    if
        let Err(e) = KeyMetadataStore::save_user_level(
            &recovery_challenge,
            "challenge",
            &recovery_email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to save recovery challenge: {}", e);
        return Ok(());
    }

    // Send recovery email with encrypted challenge bundle
    match send_recovery_email(&recovery_email, &encrypted_bundle) {
        Ok(()) => info!("Recovery email sent to {} with encrypted bundle", recovery_email),
        Err(err) => {
            error!("Failed to send recovery email: {}", err);
            return Err(err);
        }
    }
    Ok(())
}

fn send_recovery_email(email: &str, encrypted_bundle: &str) -> anyhow::Result<()> {
    info!("(Dummy) Sending email to {}: recovery challenge: {}", email, encrypted_bundle);
    Ok(())
}
