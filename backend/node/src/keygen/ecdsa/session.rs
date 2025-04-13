use crate::communication::ecdsa::JoinMessage;
use crate::keygen::ecdsa::client::{
    AllRoundSubscriptions,
    KeygenClient,
    SessionJoinParams,
    THRESHOLD,
};
use crate::keygen::ecdsa::{
    KeyGenContext,
    KeyGenParams,
    KeyGenResult,
    NewKeyGenSession,
    NewKeyGenMessage,
    Sum,
};
use crate::keygen::ShareParams;
use crate::storage::KeyshareSaver;
use crate::App;
use anyhow::anyhow;
use curv::arithmetic::Converter;
use std::thread;
use std::time::Duration;
use tracing::{ error, info, instrument };
use crate::auth::e2e_decrypt;
use crate::node::NodeIdentity;
use crate::storage::fs::WriteOpts;
use crate::storage::key_metadata_store::KeyMetadataStore;

#[instrument(skip_all)]
fn keygen_session(app: App, session: NewKeyGenSession, extra_share_index: usize) {
    info!("Joining keygen session key_id: {:?}", &session.key_id);
    let received_params = match keygen_session_join(&app, &session, extra_share_index) {
        Ok(rp) => rp,
        Err(e) => {
            error!("Problem joining the keygen session: {:?}", e);
            return;
        }
    };
    info!("Successfully joined the ECDSA key generation session");

    let ready_subject = &format!("network.gridlock.nodes.keyGen.session.{}.ready", session.key_id);

    let context = KeyGenContext {
        nc: app.nc.clone(),
        share_params: ShareParams {
            threshold: THRESHOLD,
            party_count: received_params.parties,
            party_index: received_params.party_id,
        },
        key_id: &session.key_id,
    };
    //tell hub we are ready to begin keygen
    match app.nc.publish(ready_subject, "ready") {
        Ok(()) => (),
        Err(e) => {
            error!("Failed to publish \"ready to keygen\" message: {:?}", e);
            return;
        }
    }

    if received_params.session_start.next().is_some() {
        let kg_client = match KeygenClient::new(context, received_params.all_round_subs) {
            Ok(kg_client) => kg_client,
            Err(err) => {
                error!("Failed to create a key: {}", err);
                return;
            }
        };

        let mut keyshare_saver = KeyshareSaver::new_creator(&session.key_id);
        if extra_share_index > 0 {
            keyshare_saver = KeyshareSaver::new_encryptor(&session.key_id, extra_share_index);
        }

        // Add email to keyshare_saver
        keyshare_saver = keyshare_saver.with_email(session.email.as_deref().unwrap_or_default());

        match kg_client.save_to_file(&keyshare_saver) {
            Ok(()) => (),
            Err(err) => {
                error!("Unable to save key to file: {}", err);
                return;
            }
        }

        match
            app.nc.publish(
                &format!("network.gridlock.nodes.keyGen.session.{}.result", &session.key_id),
                serde_json
                    ::to_string(
                        &(KeyGenResult {
                            y_sum: Sum {
                                x: kg_client.y_sum.x_coord().unwrap().to_hex(),
                                y: kg_client.y_sum.y_coord().unwrap().to_hex(),
                            },
                        })
                    )
                    .unwrap()
            )
        {
            Ok(()) =>
                info!("Key gen result successfully published for key id: {:?}", &session.key_id),
            Err(err) => {
                error!("Failed to publish keygen result: {}", err);
                return;
            }
        }
    }
}

fn keygen_session_join(
    app: &App,
    session: &NewKeyGenSession,
    extra_share_index: usize
) -> anyhow::Result<SessionJoinParams> {
    let start_subject = &format!("network.gridlock.nodes.keyGen.session.{}.start", session.key_id);
    let session_start = app.nc.subscribe(&start_subject)?;

    let join_subject = format!("network.gridlock.nodes.keyGen.session.{}.join", &session.key_id);

    let join_message = serde_json::to_string(
        &JoinMessage::new(session.key_id.clone(), extra_share_index)
    )?;

    let resp = app.nc.request_timeout(&join_subject, &join_message, Duration::from_secs(20))?;

    let resp_data = &String::from_utf8_lossy(&resp.data);
    let params_w_id: KeyGenParams = serde_json
        ::from_str(&resp_data)
        .map_err(|err| {
            anyhow!(
                "Unable to parse response received on join session: error: {}, data: {}",
                err,
                resp_data
            )
        })?;
    let party_index = params_w_id.party_num;
    let all_round_subs = AllRoundSubscriptions::subscribe_to_all_rounds(
        session,
        (party_index + 1) as u16,
        &app.nc
    )?;

    Ok(SessionJoinParams {
        parties: params_w_id.num_parties,
        party_id: party_index + 1,
        session_start,
        all_round_subs,
    })
}

pub fn handle_new_session_message(app: &App, message: nats::Message) {
    let parsed_message = match serde_json::from_slice::<NewKeyGenMessage>(&message.data) {
        Ok(session) => session,
        Err(e) => {
            error!("Unable to deserialize NewKeyGenMessage message - {e}");
            return;
        }
    };

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

    let node_signing_key = match String::from_utf8(decrypted_signing_key.clone()) {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to convert decrypted signing key to string: {}", err);
            return;
        }
    };
    // Save node_signing_key to file with email
    if
        let Err(e) = KeyMetadataStore::save(
            &node_signing_key,
            &parsed_message.key_id,
            "access",
            &parsed_message.email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to save access key file: {}", e);
    }

    // Also save the client's e2e public key
    if
        let Err(e) = KeyMetadataStore::save_user_level(
            &parsed_message.client_e2e_public_key,
            "e2e_key",
            &parsed_message.email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to save client's e2e public key: {}", e);
    } else {
        info!("Saved client e2e public key for email: {}", parsed_message.email);
    }

    let session = NewKeyGenSession {
        key_id: parsed_message.key_id.clone(),
        extra_shares: parsed_message.extra_shares.clone(),
        client_e2e_public_key: Some(parsed_message.client_e2e_public_key.clone()),
        encrypted_signing_key: Some(parsed_message.encrypted_signing_key.clone()),
        email: Some(parsed_message.email.clone()),
    };

    let num_extra_shares = session.extra_shares.len();

    for index in 0..=num_extra_shares {
        let key = session.key_id.clone();
        let session = session.clone();
        let app = app.clone();
        info!("Spawning ECDSA key gen session thread");
        match
            thread::Builder
                ::new()
                .name(format!("key_gen_session_{}_{}", key, index))
                .spawn(move || keygen_session(app, session, index))
        {
            Ok(_) => (),
            Err(_) => error!("Failed to spawn thread for keygen session {}", key),
        };
    }
}
