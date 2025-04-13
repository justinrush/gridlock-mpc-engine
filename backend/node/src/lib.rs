#![allow(dead_code)]
#![allow(non_snake_case)]

pub mod auth;
pub mod command;
pub mod communication;
pub mod config;
pub mod eject;
pub mod encryption;
pub mod ghost_shares;
pub mod key_info;
pub mod keygen;
pub mod logging;
pub mod node;
pub mod recovery;
mod security;
pub mod signing;
pub mod storage;
pub mod user_recovery;

use crate::{ config::*, node::NodeIdentity };
use anyhow::{ anyhow, bail, Result };
use keygen::eddsa;
use std::sync::atomic::{ AtomicBool, Ordering };
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;
use tracing::{ info, warn };

const NATS_ROLE: &str = "node";
const NATS_PASS: &str = "68da8b26e61039cff90bb9ca5bc78a239b049bb9c4e5cc79147364f3653f8f";

#[derive(Clone)]
pub struct App {
    pub nc: nats::Connection,
    pub node: NodeIdentity,
}

pub static NATS_CONNECTED: AtomicBool = AtomicBool::new(false);

impl App {
    pub fn new() -> Result<App> {
        let node = match node::NodeIdentity::load() {
            Ok(node) => node,
            Err(_) => { create_new_node_identity()? }
        };
        info!("Version: {}", env!("CARGO_PKG_VERSION"));
        info!("-----------------------------------");
        info!("Hello, you can call me \x1b[34m\x1b[1m{}\x1b[0m", node.name);
        info!("Node ID: \x1b[34m\x1b[1m{}\x1b[0m", &node.node_id);
        info!("Networking Public Key: \x1b[34m\x1b[1m{}\x1b[0m", &node.networking_public_key);
        info!("E2E Public Key: \x1b[34m\x1b[1m{}\x1b[0m", &node.e2e_public_key);
        info!("-----------------------------------");
        info!(
            "{{\"name\":\"{}\",\"nodeId\":\"{}\",\"networkingPublicKey\":\"{}\",\"e2ePublicKey\":\"{}\"}}",
            node.name,
            node.node_id,
            node.networking_public_key,
            node.e2e_public_key
        );
        info!("-----------------------------------");
        let nc = get_nats_connection()?;

        Ok(App { nc, node })
    }

    pub fn try_reconnect(&mut self) -> Result<()> {
        warn!("Try reconnect NATs");
        self.nc = get_nats_connection()?;
        Ok(())
    }
}

pub fn start() -> Result<App> {
    if Config::create_data_dirs().is_err() {
        bail!("Failed to create application data directories");
    }
    LogInitiator::init();
    App::new()
}

pub fn get_nats_connection() -> Result<nats::Connection> {
    let address = Config::get_nats_address();
    let conn = nats::Options
        ::with_user_pass(NATS_ROLE, NATS_PASS)
        .disconnect_callback(|| {
            warn!("NATs disconnected");
            NATS_CONNECTED.store(false, Ordering::Relaxed);
        })
        .reconnect_callback(|| {
            warn!("NATs reconnected");
            NATS_CONNECTED.store(true, Ordering::Relaxed);
        })
        .retry_on_failed_connect()
        .connect(&address)
        .map_err(|err| {
            anyhow!("Failed to connect to NATS at \"{}\" due to error: {}", address, err)
        })?;

    NATS_CONNECTED.store(true, Ordering::Relaxed);
    info!("Connected to NATS successfully at: {:?}", &address);

    Ok(conn)
}

pub fn create_new_node_identity() -> Result<NodeIdentity> {
    //no json file exists
    info!("No pre-existing data, creating new node identity");
    let node = NodeIdentity::new();
    node.save()?;
    Ok(node)
}

pub fn handle_message(app: &App, message: nats::Message) {
    info!("Received a message with subject \"{}\"", message.subject);

    if message.subject.starts_with("network.gridlock.nodes.keyGen.") {
        info!("start keygen process");
        keygen::ecdsa::session::handle_new_session_message(app, message);
    } else if message.subject.starts_with("network.gridlock.nodes.keySign.") {
        signing::ecdsa::session::handle_new_session_message(app, message);
    } else if message.subject.starts_with("network.gridlock.nodes.KeyGenEdDSA.") {
        eddsa::session::handle_new_session_message(app, message);
    } else if message.subject.starts_with("network.gridlock.nodes.KeySignEdDSA.") {
        signing::eddsa::session::handle_new_session_message(app, message);
    } else if message.subject.starts_with("network.gridlock.nodes.KeySignSr25519.") {
        signing::sr25519_musign::handle_new_session_message(app, message);
    } else if message.subject.starts_with("network.gridlock.nodes.Message.") {
        //TODO: access to this topic should have admin privileges.
        // To be able manage partner, user and gridlock nodes
        let _ = command::handle_nats_command(app, message);
    } else if message.subject.starts_with("network.gridlock.nodes.KeyShareRecovery.") {
        recovery::recovery_session::handle_new_session_message(app, message);
    } else if message.subject.starts_with("network.gridlock.nodes.UserRecovery.") {
        user_recovery::session::handle_new_session_message(app, message);
    } else if message.subject.starts_with("network.gridlock.nodes.UserRecoveryConfirm.") {
        user_recovery::confirm::handle_new_session_message(app, message);
    } else {
        warn!("Received message with an unrecognized subject: {}", message.subject);
    }
}

pub fn start_sending_ready_as_cancellable_task_on_thread(
    conn: nats::Connection,
    node_id: String,
    rx: mpsc::Receiver<()>,
    interval_duration: Duration
) -> Result<()> {
    let subject = format!("network.gridlock.nodes.ready.{}", &node_id);
    let _ = std::thread::spawn(move || {
        loop {
            match rx.try_recv() {
                Ok(_) | Err(TryRecvError::Disconnected) => {
                    break;
                }
                Err(TryRecvError::Empty) => {}
            }
            let _ = conn.publish(&subject, &node_id);
            std::thread::sleep(interval_duration);
        }
    });
    Ok(())
}
