use crate::auth::e2e_decrypt;
use crate::communication::nats::{
    BaseMessenger,
    NatsBaseMessenger,
    NatsBaseSession,
    NatsPeerMessenger,
};
use crate::communication::protocol::{ KeyGenAllRounds, KeySignEdDSAAllRounds, Topic };
use crate::keygen::eddsa::client::KeyGenClient;
use crate::keygen::ShareParams;
use crate::node::NodeIdentity;
use crate::signing::eddsa::client::EdDSAKeySignClient;
use crate::signing::eddsa::SignatureResult;
use crate::storage::fs::{ FileSystem, WriteOpts };
use crate::storage::KeyshareAccessor;
use crate::storage::EDDSA;
use crate::App;
use serde::{ Deserialize, Serialize };
use std::thread;
use tracing::{ error, info, instrument, warn };
use crate::storage::key_metadata_store::KeyMetadataStore;
use std::time::SystemTime;
use chrono::{ DateTime, Utc };
use hmac::{ Hmac, Mac, NewMac };
use sha2::Sha256;
use base64;
use hex;

#[instrument(skip_all)]
fn sign_session(conn: nats::Connection, session: NewEdDSAKeySignSession) -> anyhow::Result<()> {
    let session_id = session.session_id.clone();
    match keysign_session_inner(conn, session) {
        Ok(()) => info!("Signing completed successfully for session id: {}", session_id),
        Err(err) => error!("Error in EdDSA signing: session id: {}, error: {}", session_id, err),
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewEdDSAKeySignMessage {
    pub key_id: String,
    pub session_id: String,
    pub message: Vec<u8>,
    pub client_e2e_public_key: String,
    pub encrypted_signing_key: String,
    pub is_transfer_tx: Option<bool>,
    pub timestamp: Option<String>,
    pub message_hmac: Option<String>,
    pub email: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewEdDSAKeySignSession {
    pub key_id: String,
    pub session_id: String,
    pub message: Vec<u8>,
    pub email: Option<String>,
}

pub struct E2EData {
    pub client_e2e_public_key: String,
    pub encrypted_signing_key: String,
}

fn keysign_session_inner(
    conn: nats::Connection,
    session: NewEdDSAKeySignSession
) -> anyhow::Result<()> {
    let key_id = session.key_id.clone();
    let session_id = session.session_id.clone();
    let message = session.message.clone();
    info!("joining EdDSA keysign session key_id: {}", &key_id);

    let keyshare = if let Some(email) = &session.email {
        info!("Using email-based keyshare access for: {}", email);
        KeyshareAccessor::<EDDSA>::read_only_with_email(&key_id, email)?.key
    } else {
        info!("Using default keyshare access (no email provided)");
        KeyshareAccessor::<EDDSA>::read_only(&key_id)?.key
    };
    info!("Retrieved keyshare");

    let threshold = keyshare.threshold;
    let party_index = keyshare.party_index;

    let node = NodeIdentity::load()?;
    let node_id = node.node_id.to_string();
    let public_key = node.networking_public_key;
    info!("Retrieved node identity");

    let thread_index = 0; // Single keyshare per device

    let nats_session = NatsBaseSession {
        session_id,
        thread_index,
        node_id,
        public_key,
        party_index,
    };

    let keygen_messenger = NatsBaseMessenger::<KeyGenAllRounds>::new(
        Topic::EphemeralKeyGenEdDSA,
        conn.clone(),
        nats_session.clone()
    )?;

    let sign_messenger = NatsBaseMessenger::<KeySignEdDSAAllRounds>::new(
        Topic::KeySignEdDSA,
        conn.clone(),
        nats_session
    )?;

    let join_response = keygen_messenger.wait_for_confirmation(std::time::Duration::from_secs(10))?;
    info!("Got join response");

    let party_count = join_response.party_count;
    let mut all_party_indices = join_response.all_party_indices;
    all_party_indices.sort();

    let keygen_peer_messenger = NatsPeerMessenger::from(
        keygen_messenger,
        party_count,
        all_party_indices.clone()
    )?;

    let keygen_client = KeyGenClient {
        peer_messenger: keygen_peer_messenger,
        share_params: ShareParams {
            threshold,
            party_count,
            party_index,
        },
        all_party_indices: all_party_indices.clone(),
    };

    let ephemeral_keyshare = keygen_client.create_ephemeral_shared_key(&message)?;
    info!("Successfully created an ephemeral key");

    keygen_client.publish_result(ephemeral_keyshare.shared_key.R.clone())?;

    let sign_peer_messenger = NatsPeerMessenger::from(
        sign_messenger,
        party_count,
        all_party_indices.clone()
    )?;

    let keysign_client = EdDSAKeySignClient {
        peer_messenger: sign_peer_messenger,
        share_params: ShareParams {
            threshold,
            party_count,
            party_index,
        },
        all_party_indices,
    };

    let signature = keysign_client.create_shared_sig(&message, &ephemeral_keyshare, &keyshare)?;
    let sigma = hex::encode(&*signature.s.to_bytes());

    let R = hex::encode(&*signature.R.to_bytes(false));
    let signature = SignatureResult { sigma, R };
    keysign_client.publish_result(signature)?;
    info!("Signature published successfully");

    Ok(())
}

pub fn handle_new_session_message(app: &App, message: nats::Message) {
    let parsed_message = match serde_json::from_slice::<NewEdDSAKeySignMessage>(&message.data[..]) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!("Failed to parse message: {}", err);
            return;
        }
    };

    // Validate security fields
    if
        parsed_message.timestamp.is_none() ||
        parsed_message.message_hmac.is_none() ||
        parsed_message.email.is_none()
    {
        error!("Missing required security fields: timestamp, message_hmac, or email");
        return;
    }

    let node = match NodeIdentity::load() {
        Ok(node) => node,
        Err(err) => {
            error!("Failed to load node identity: {}", err);
            return;
        }
    };

    let decrypted_signing_key = match
        e2e_decrypt(
            &parsed_message.encrypted_signing_key,
            &node.e2e_private_key,
            &parsed_message.client_e2e_public_key
        )
    {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to decrypt signing key: {}", err);
            return;
        }
    };

    let node_signing_key = match String::from_utf8(decrypted_signing_key) {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to convert decrypted signing key to string: {}", err);
            return;
        }
    };

    let message_hmac = parsed_message.message_hmac.as_ref().unwrap();
    let timestamp = parsed_message.timestamp.as_ref().unwrap();

    let email = parsed_message.email.unwrap_or_default();

    // Security verification: HMAC then timestamp
    if !verify_hmac(message_hmac, timestamp, &email, &node_signing_key) {
        error!("HMAC verification failed");
        return;
    }

    if !verify_timestamp(&parsed_message.key_id, timestamp, &email) {
        error!("Timestamp verification failed");
        return;
    }
    info!("Timestamp verified");

    // Transfer transaction validation
    if parsed_message.is_transfer_tx.unwrap_or(false) {
        info!("Initiating ownership transfer");

        let message_str = match String::from_utf8(parsed_message.message.clone()) {
            Ok(s) => s,
            Err(err) => {
                error!("Failed to convert message to string: {}", err);
                return;
            }
        };

        if !message_str.starts_with("Authorizing ownership transfer to ") {
            error!("Invalid transfer message format: {}", message_str);
            return;
        }

        let target_client_key = message_str.replace("Authorizing ownership transfer to ", "");

        let stored_identity = match KeyMetadataStore::get_user_level("new_identity_key", &email) {
            Ok(identity) => identity,
            Err(err) => {
                error!("Failed to retrieve identity using KeyMetadataStore: {}", err);
                return;
            }
        };

        if stored_identity.trim() != target_client_key.trim() {
            error!(
                "Transfer target mismatch. Expected: {}, Actual: {}",
                stored_identity.trim(),
                target_client_key.trim()
            );
            return;
        }

        info!("Matched user identity, proceeding with ownership transfer transaction");

        // Delete the new_identity_key file after successful verification
        if let Err(err) = KeyMetadataStore::remove_user_level("new_identity_key", &email) {
            error!("Failed to remove new_identity_key: {}", err);
            return;
        }

        info!("Successfully removed new_identity_key after ownership verification");
    }

    // Validate access key
    let saved_access_key = match KeyMetadataStore::get(&parsed_message.key_id, "access", &email) {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to load saved access key: {}", err);
            return;
        }
    };

    if node_signing_key != saved_access_key {
        error!("Access key mismatch: decrypted key does not match saved access key");
        return;
    }

    // Store the client_e2e_public_key
    if
        let Err(err) = KeyMetadataStore::save_user_level(
            &parsed_message.client_e2e_public_key,
            "e2e_key",
            &email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to store client_e2e_public_key: {}", err);
        // Continue anyway as this is not critical
    }

    // Create session with the email for email-based storage access
    let session = NewEdDSAKeySignSession {
        key_id: parsed_message.key_id,
        session_id: parsed_message.session_id,
        message: parsed_message.message,
        email: Some(email.clone()),
    };

    // Create a new thread for this signing session
    info!("Spawning a thread to handle EdDSA signature generation");
    let thread_name = format!("sign_session_{}", session.session_id);
    let nc = app.nc.clone();
    match
        thread::Builder
            ::new()
            .name(thread_name)
            .spawn(move || sign_session(nc, session))
    {
        Ok(_) => info!("Started EdDSA signing thread"),
        Err(err) => error!("Failed to spawn thread for EdDSA signing: {}", err),
    };
}

// Verify that the timestamp is newer than the last one we've seen
fn verify_timestamp(key_id: &str, new_timestamp: &str, email: &str) -> bool {
    let timestamp_key = "timestamp";
    let new_dt = match DateTime::parse_from_rfc3339(new_timestamp) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(err) => {
            error!("Failed to parse timestamp: {}", err);
            return false;
        }
    };

    // It's fine if this fails - it just means first tx
    let previous_timestamp_result = KeyMetadataStore::get(key_id, timestamp_key, email);

    match previous_timestamp_result {
        Ok(prev_timestamp_str) => {
            let prev_dt = match DateTime::parse_from_rfc3339(&prev_timestamp_str) {
                Ok(dt) => dt.with_timezone(&Utc),
                Err(err) => {
                    error!("Failed to parse stored timestamp: {}", err);
                    return false;
                }
            };

            if new_dt <= prev_dt {
                error!(
                    "Timestamp validation failed: provided timestamp ({}) is not newer than stored timestamp ({})",
                    new_timestamp,
                    prev_timestamp_str
                );
                return false;
            }
        }
        Err(err) => {
            info!("No previous timestamp found, likely first transaction: {}", err);
        }
    }

    match KeyMetadataStore::save(new_timestamp, key_id, timestamp_key, email, &WriteOpts::Modify) {
        Ok(_) => true,
        Err(err) => {
            error!("Failed to save new timestamp: {}", err);
            false
        }
    }
}

// HMAC verification using SHA256(timestamp + email) with signing key
fn verify_hmac(provided_hmac: &str, timestamp: &str, email: &str, signing_key: &str) -> bool {
    type HmacSha256 = Hmac<Sha256>;
    let message_input = format!("{}{}", timestamp, email);

    let mut mac = match HmacSha256::new_from_slice(signing_key.as_bytes()) {
        Ok(m) => m,
        Err(err) => {
            error!("Failed to create HMAC instance: {}", err);
            return false;
        }
    };

    mac.update(message_input.as_bytes());
    let calculated_hmac_bytes = mac.finalize().into_bytes();

    // Use base64 encoding instead of hex to match TypeScript implementation
    let calculated_hmac = base64::encode(&calculated_hmac_bytes);

    if calculated_hmac != provided_hmac {
        error!("HMAC verification failed: expected {}, got {}", provided_hmac, calculated_hmac);
        return false;
    }

    info!("HMAC verified");
    true
}
