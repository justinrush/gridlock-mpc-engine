use crate::auth::e2e_decrypt;
use crate::communication::nats::{
    BaseMessenger,
    NatsBaseMessenger,
    NatsBaseSession,
    NatsPeerMessenger,
};
use crate::communication::protocol::{ KeyGenAllRounds, Topic };
use crate::keygen::eddsa::client::KeyGenClient;
use crate::keygen::eddsa::KeyGenResult;
use crate::keygen::ShareParams;
use crate::node::NodeIdentity;
use crate::storage::fs::{ FileSystem, WriteOpts };
use crate::storage::KeyshareSaver;
use crate::App;
use crate::storage::key_metadata_store::KeyMetadataStore;
use anyhow::bail;
use base32;
use serde::{ Deserialize, Serialize };
use std::thread;
use tracing::{ error, info, instrument };

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewKeyGenSession {
    pub key_id: String,
    pub share_indices: Vec<usize>,
    pub threshold: usize,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct E2EData {
    pub client_e2e_public_key: String,
    pub encrypted_signing_key: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewKeyGenMessage {
    pub key_id: String,
    pub share_indices: Vec<usize>,
    pub threshold: usize,
    pub client_e2e_public_key: String,
    pub encrypted_signing_key: String,
    pub email: String,
}

pub fn handle_new_session_message(app: &App, message: nats::Message) {
    let parsed_message = match serde_json::from_slice::<NewKeyGenMessage>(&message.data[..]) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!("Failed to parse message: {}", err);
            return;
        }
    };

    let session = NewKeyGenSession {
        key_id: parsed_message.key_id,
        share_indices: parsed_message.share_indices,
        threshold: parsed_message.threshold,
    };
    let e2e = E2EData {
        client_e2e_public_key: parsed_message.client_e2e_public_key.clone(),
        encrypted_signing_key: parsed_message.encrypted_signing_key,
    };

    let node = match NodeIdentity::load() {
        Ok(node) => node,
        Err(err) => {
            error!("Failed to load node identity: {}", err);
            return;
        }
    };

    let decrypted_signing_key = match
        e2e_decrypt(&e2e.encrypted_signing_key, &node.e2e_private_key, &e2e.client_e2e_public_key)
    {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to decrypt signing key: {}", err);
            return;
        }
    };

    let node_signing_key = match String::from_utf8(decrypted_signing_key.clone()) {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to convert decrypted signing key to string: {}", err);
            return;
        }
    };

    let recovery_email = parsed_message.email.clone();

    // Save node_signing_key to file with email
    if
        let Err(e) = KeyMetadataStore::save(
            &node_signing_key,
            &session.key_id,
            "access",
            &recovery_email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to save access key file: {}", e);
    }

    // Also save the client's e2e public key
    if
        let Err(e) = KeyMetadataStore::save_user_level(
            &e2e.client_e2e_public_key,
            "e2e_key",
            &recovery_email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to save client's e2e public key: {}", e);
    } else {
        info!("Saved client e2e public key for email: {}", recovery_email);
    }

    for (thread_index, party_index) in session.share_indices.clone().iter().enumerate() {
        let key = session.key_id.clone();
        let nc = app.nc.clone();
        let session = session.clone();
        let party_index = party_index.clone();
        let recovery_email = recovery_email.clone();

        let mut keyshare_saver = KeyshareSaver::new_creator(&key).with_email(&recovery_email);
        if thread_index > 0 {
            keyshare_saver = KeyshareSaver::new_encryptor(&key, thread_index).with_email(
                &recovery_email
            );
        }

        match
            thread::Builder
                ::new()
                .name(format!("key_gen_session_{}_{}", key, thread_index))
                .spawn(move ||
                    keygen_session(nc, session, party_index, thread_index, keyshare_saver)
                )
        {
            Ok(_) => info!("Spawned a thread to handle key gen"),
            Err(_) => error!("Failed to spawn thread for keygen session {}", key),
        };
    }
}

#[instrument(skip_all)]
fn keygen_session(
    conn: nats::Connection,
    session: NewKeyGenSession,
    party_index: usize,
    thread_index: usize,
    keysaver: KeyshareSaver
) -> anyhow::Result<()> {
    let session_id = session.key_id.clone();
    match keygen_session_inner(conn, session, party_index, thread_index, keysaver) {
        Ok(_) => {
            info!("EdDSA key generation completed sucessfully, key id: {}", session_id);
        }
        Err(err) => error!("Error in key generation: session id: {}, error: {}", session_id, err),
    }
    Ok(())
}

fn keygen_session_inner(
    conn: nats::Connection,
    session: NewKeyGenSession,
    party_index: usize,
    thread_index: usize,
    keysaver: KeyshareSaver
) -> anyhow::Result<()> {
    let node = NodeIdentity::load()?;
    let node_id = node.node_id.to_string();
    let public_key = node.networking_public_key;

    let key_id = session.key_id.clone();

    let nats_session = NatsBaseSession {
        session_id: key_id.clone(),
        thread_index,
        node_id,
        public_key,
        party_index,
    };

    let messenger = NatsBaseMessenger::<KeyGenAllRounds>::new(
        Topic::KeyGenEdDSA,
        conn.clone(),
        nats_session
    )?;
    let join_response = messenger.wait_for_confirmation(std::time::Duration::from_secs(10))?;

    let party_count = join_response.party_count;
    let mut all_party_indices = join_response.all_party_indices;
    all_party_indices.sort();

    let peer_messenger = NatsPeerMessenger::from(
        messenger,
        party_count,
        all_party_indices.clone()
    )?;

    let keygen_client = KeyGenClient {
        peer_messenger,
        share_params: ShareParams {
            threshold: session.threshold,
            party_count,
            party_index,
        },
        all_party_indices,
    };

    let keyshare = keygen_client.create_shared_key()?;

    match keysaver.save_key(&keyshare) {
        Ok(()) => {
            info!("Saved new key to file: {}", &key_id);
        }
        Err(err) => {
            bail!("Unable to save key to file: {}", err);
        }
    }

    let y_sum = hex::encode(&*keyshare.y_sum.to_bytes(false));

    let y_sum = KeyGenResult { y_sum };
    keygen_client.publish_result(y_sum)?;

    Ok(())
}
