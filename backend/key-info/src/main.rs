mod storage;

use crate::storage::{ get_updates_for, mark_updated, save, NodeUpdateData };
use anyhow::{ anyhow, bail, Context, Result };
use futures::TryFutureExt;
use log::{ error, info, LevelFilter };
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{ Appender, Root };
use log4rs::Config;
use nats::asynk::{ Connection, Message, Options, Subscription };
use serde::{ Deserialize, Serialize };
use shared::key_info::{ NodeId, UpdateKeyInfoCommand };
use shared::recovery::{
    ReceiveRecoveryPackages,
    UpdatePaillierKeysCommand,
    UpdateSinglePaillierKeyCommand,
};
use std::collections::HashMap;
use std::time::{ Duration, SystemTime };
use strum_macros::Display as macroDisplay;
use tokio::signal::unix::{ signal, SignalKind };
use tokio::time::timeout;
use tokio::{ select, signal };
use uuid::Uuid;

const NATS_ROLE: &str = "node";
const NATS_PASS: &str = "68da8b26e61039cff90bb9ca5bc78a239b049bb9c4e5cc79147364f3653f8f";

const SAVE_CMD_TIMEOUT_SEC: u64 = 5;

async fn subscribe_to(subject: &str) -> Result<(Connection, Subscription)> {
    let address = get_nats_address();
    let nc = Options::with_user_pass(NATS_ROLE, NATS_PASS).connect(address).await?;
    let sub = nc
        .subscribe(subject).await
        .map_err(|_| anyhow!("Failed to subscribe to subject \"{}\"", subject))?;
    info!("Subscribed to NATS subject \"{}\"", subject);

    Ok((nc, sub))
}

fn get_nats_address() -> String {
    let env_override = std::env::var("NATS_ADDRESS");
    if env_override.is_ok() {
        let env_override = env_override.unwrap();
        if !env_override.is_empty() {
            return env_override;
        }
    }

    String::from("nats://stagingnats.gridlock.network:4222")
}

async fn message_loop() -> Result<()> {
    let (nc, sub) = subscribe_to("network.gridlock.nodes.async.Message.new.*").await?;
    while let Some(msg) = sub.next().await {
        match serde_json::from_slice::<UpdateCommand>(&msg.data) {
            Ok(cmd) => {
                let nc = nc.clone();
                let Some(node_id) = msg.subject.split('.').next_back() else {
                    error!("Unable to obtain node id - subject: {}", msg.subject);
                    continue;
                };
                let node_id = NodeId::new(node_id.to_string());
                tokio::spawn(process_cmd(cmd, nc, node_id).inspect_err(|e| error!("{}", e)));
            }
            Err(e) => {
                error!("Unable to deserializes async command! - {}", e);
            }
        };
    }
    Ok(())
}

async fn process_cmd(cmd: UpdateCommand, nc: Connection, node_id: NodeId) -> Result<()> {
    info!("Processing command - {}", &node_id);
    let reply = nc.new_inbox();
    let rsub = nc.subscribe(&reply).await?;
    let msg = serde_json::to_string(&cmd)?;
    nc.publish_request(
        &format!("network.gridlock.nodes.Message.new.{}", &node_id),
        &reply,
        msg
    ).await?;
    match timeout(std::time::Duration::from_secs(SAVE_CMD_TIMEOUT_SEC), rsub.next()).await {
        Err(_) => {
            info!("Command wasn't delivered. Saving node update data - node_id: {}", &node_id);
            let upd_data = NodeUpdateData::new(cmd, node_id.clone());
            match save(upd_data).await {
                Ok(_) => {
                    info!("Node update data saved - node_id: {}", &node_id);
                }
                Err(e) => {
                    error!("Unable to save node update data - node_id: {}\n{}", node_id, e);
                }
            };
        }
        Ok(_) => {
            info!("Command delivered successfully - node_id: {}", node_id);
        }
    }
    Ok(())
}

const READY_MSG_INTERVAL: Duration = Duration::from_millis(200 * 2);

async fn update_loop() -> Result<()> {
    let mut node_id_to_upd_time = HashMap::new();
    let (nc, sub) = subscribe_to("network.gridlock.nodes.ready.*").await?;
    while let Some(msg) = sub.next().await {
        match String::from_utf8(msg.data) {
            Ok(node_id) => {
                let Ok(node_id): Result<Uuid> = NodeId::new(node_id.clone()).try_into() else {
                    error!("Unable to decode ready message - node_id: {}", node_id);
                    continue;
                };

                match node_id_to_upd_time.insert(node_id, std::time::Instant::now()) {
                    None => {}
                    Some(upd_time) => {
                        if upd_time.elapsed() < READY_MSG_INTERVAL {
                            continue;
                        }
                    }
                }

                info!("Processing ready message - node_id: {}", node_id);

                let node_id = NodeId::new_from_uuid(node_id);
                let nc = nc.clone();
                tokio::spawn(
                    deliver_updates_to(node_id, nc).inspect_err(|e|
                        error!("Failed to deliver updates\n{e}")
                    )
                );
            }
            Err(e) => {
                error!("Unable to decode ready message - {}", e);
            }
        };
    }

    Ok(())
}

async fn deliver_updates_to(node_id: NodeId, nc: Connection) -> Result<()> {
    info!("Retrieving updates - node_id: {}", node_id);
    let update_packages = get_updates_for(&node_id).await?;
    info!("Updates count: {} - node_id: {}", update_packages.len(), node_id);
    for upd_data in update_packages {
        let cmd = upd_data.update_cmd;
        let reply = nc.new_inbox();
        let rsub = nc.subscribe(&reply).await?;
        let msg = serde_json::to_string(&cmd)?;
        nc.publish_request(
            &format!("network.gridlock.nodes.Message.new.*.{}", node_id.clone()),
            &reply,
            msg
        ).await?;
        match timeout(Duration::from_secs(10), rsub.next()).await? {
            None => {}
            Some(_) => mark_updated(&node_id).await?,
        };
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger()?;

    //TODO#q: add migration loop for saving existing key information. Take examples from existing mongodb
    select! {
        res = message_loop() => res,
        res = update_loop() => res,
        res = wait_termination() => res,
    }
}

async fn wait_termination() -> Result<()> {
    signal(SignalKind::terminate())?.recv().await.context("SIGTERM received")
}

fn init_logger() -> Result<()> {
    let stdout = ConsoleAppender::builder().build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Info))?;
    log4rs::init_config(config)?;
    Ok(())
}

#[derive(Serialize, Deserialize, macroDisplay)]
#[serde(untagged)]
pub enum UpdateCommand {
    KeyshareRecovery(ReceiveRecoveryPackages),
    UpdatePaillierKeys(UpdatePaillierKeysCommand),
    UpdateSinglePaillierKey(UpdateSinglePaillierKeyCommand),
    UpdateKeyInfo(UpdateKeyInfoCommand),
}
