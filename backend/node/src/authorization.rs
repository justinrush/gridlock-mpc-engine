use anyhow::bail;
use anyhow::Result;
use nats::{ Connection as NatsConnection, Message };
use std::thread;
use tracing::{ error, info };
use uuid::Uuid;

use serde::{ Deserialize, Serialize };

#[derive(Deserialize, Serialize, Debug)]
pub struct NodeAuthRequest {
    pub session: Uuid,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthMsg {
    pub encrypted_msg: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub session_id: Uuid,
    pub session_type: String,
}

impl AuthResponse {
    pub fn new(session_type: &str) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            session_type: String::from(session_type),
        }
    }
}

#[allow(dead_code)]
fn sign_auth_message(message: &str, node_id: &Uuid) -> Result<AuthMsg> {
    let msg = "".as_bytes().to_vec();
    let encr_msg = AuthMsg { encrypted_msg: msg };
    return Ok(encr_msg);
}

#[allow(dead_code)]
pub fn perform_auth_session(
    conn: &NatsConnection,
    node_id: Uuid,
    session_id: Uuid,
    msg_string: &str
) -> anyhow::Result<Message> {
    info!("start sign node auth message process");

    let signed_msg = sign_auth_message(&msg_string, &node_id)?;
    let serialized_msg = serde_json::to_string(&signed_msg)?;
    info!("auth message signed");

    let pub_subject = format!("network.gridlock.nodes.{}.authorize", &session_id);
    info!("publish signed auth message on session: {:?}", session_id);

    let response = match
        conn.request_timeout(&pub_subject, serialized_msg, std::time::Duration::from_secs(10))
    {
        Ok(resp) => resp,
        Err(_) => bail!("Timeout waiting for Auth response"),
    };
    Ok(response)
}

pub fn handle_node_auth_message(connection: NatsConnection, message: Message, node_id: Uuid) {
    let auth_req = serde_json::from_slice::<NodeAuthRequest>(&message.data[..]).unwrap();
    let thread_error_message = format!(
        "Failed to spawn thread for auth session {}",
        auth_req.session
    );
    info!("spawn Node Authorization thread");
    match
        thread::Builder
            ::new()
            .name(format!("node_auth_session{}", &auth_req.session))
            .spawn(move || {
                perform_auth_session(&connection, node_id, auth_req.session, &auth_req.message)
            })
    {
        Ok(_) => (),
        Err(e) => error!("{}", &thread_error_message),
    };
}
