use crate::command::MsgContext;
use crate::communication::nats::{ BroadcastMessage, JoinMessage, JoinResponse };
use crate::recovery::recovery_session::NewKeyShareRecoverySession;
use crate::recovery::{ Key, NodeId, RecoveryCommand, RecoveryRole, RecoveryValidationResult };
use crate::storage::KeyInfoStore;
use anyhow::{ anyhow, bail, Context, Result };
use shared::recovery::{
    EncryptedData,
    PublicKeysEnum,
    ReceiveRecoveryPackages,
    RecoveryPackageInfo,
    UpdatePaillierKeysCommand,
};

use shared::key_info::{ KeyInfo, NodeInfo, UpdateKeyInfoCommand };
use tracing::{ error, info, instrument };

static THRESHOLD: usize = 2;

#[instrument(skip_all)]
pub fn orchestrate(cmd: RecoveryCommand, ctx: MsgContext) -> Result<()> {
    let app = ctx.get_app()?;
    let nc = app.nc;

    let RecoveryCommand {
        kind,
        key_id,
        session_id,
        new_node_id,
        new_node_public_key,
        old_node_id,
        party_nodes,
        email,
    } = cmd;

    let key_info = KeyInfoStore::get_key_info(&key_id).map_err(|_| {
        let msg = format!("Key info is not found - key_id: {}", &key_id);
        error!("{}", &msg);
        anyhow!("{msg}\n
            Try node that has information about the key")
    })?;

    let recovery_share_index = key_info.node_pool
        .iter()
        .find(|&n| n.node_id == old_node_id)
        .ok_or_else(|| {
            let msg = format!("Old node id was not found - old_node_id: {old_node_id}");
            error!("{}", &msg);
            anyhow!("{}", &msg)
        })?.share_index;

    let key_info = enrich_key_info(key_info, &new_node_id, &new_node_public_key, &old_node_id);

    // Reorder public keys to be in order of the share index they hold
    let mut rearranged_keys = Vec::new();
    for node in &key_info.node_pool {
        rearranged_keys.push((node.share_index, node.networking_public_key.clone()));
    }

    let helper_message = NewKeyShareRecoverySession {
        key_id: key_id.to_string(),
        session_id: session_id.to_string(),
        kind: kind.clone(),
        threshold: THRESHOLD,
        recovery_index: recovery_share_index,
        public_keys: PublicKeysEnum::Map(rearranged_keys.clone()),
        role: RecoveryRole::Helper,
        email: Some(email.clone()),
    };

    let join_key = format!("network.gridlock.nodes.KeyShareRecovery.{}.Join", &session_id);
    let join_sub = nc.subscribe(&join_key)?;

    let package_key = format!(
        "network.gridlock.nodes.KeyShareRecovery.{}.DeliverRecoveryPackage",
        &session_id
    );
    let package_sub = nc.subscribe(&package_key)?;

    let recovery_new_helper_message = serde_json::to_string(&helper_message)?;

    for node_id in &party_nodes {
        let recovery_new_key = format!("network.gridlock.nodes.KeyShareRecovery.new.{node_id}");
        nc.publish(&recovery_new_key, &recovery_new_helper_message)?;
    }

    let mut join_msgs = Vec::new();
    let party_count = party_nodes.len();
    for _ in 0..party_count {
        let join_msg = join_sub.next().context("Waiting for parties to join")?;
        join_msgs.push(join_msg);
    }

    if join_msgs.len() < party_count {
        bail!("Not all nodes joined to recovery session");
    }

    let mut share_indices = Vec::new();
    for m in join_msgs.iter() {
        let confirmation = serde_json::from_slice::<JoinMessage>(&m.data)?;
        share_indices.push(confirmation.party_index);
    }
    share_indices.sort();

    info!("Parties joined to recovery orchestration - share_indices: {:?}", &share_indices);
    let join_resp = JoinResponse {
        party_count: share_indices.len(),
        all_party_indices: share_indices.clone(),
    };
    for m in &join_msgs {
        m.respond(&serde_json::to_string(&join_resp)?)?;
    }
    nc.flush()?;

    // Gather regeneration packages
    let mut encrypted_packages = Vec::new();
    for _ in 0..party_count {
        let m = package_sub.next().unwrap();
        let resp = serde_json::from_slice::<BroadcastMessage<EncryptedData>>(&m.data).unwrap();

        encrypted_packages.push(resp);
    }
    info!("Encrypted packages received - encrypted packages count: {}", encrypted_packages.len());

    encrypted_packages.sort_by_key(|x| x.sender_id);
    let encrypted_packages: Vec<EncryptedData> = encrypted_packages
        .iter()
        .map(|x| x.message.clone())
        .collect();

    let message = ReceiveRecoveryPackages {
        recovery_info: RecoveryPackageInfo {
            key_id: key_id.to_string(),
            recovery_index: recovery_share_index,
            threshold: THRESHOLD,
            peers: share_indices.clone(),
            public_keys: PublicKeysEnum::Map(rearranged_keys.clone()),
            encrypted_packages,
        },
        kind: kind.clone(),
    };
    let msg = serde_json::to_string(&message)?;
    let message_new_key = format!("network.gridlock.nodes.async.Message.new.{new_node_id}");
    let res = nc.request(&message_new_key, msg)?;
    info!("Validating recovery result");
    match kind {
        // TODO#q: move recovery validation result logic to the node that receives it
        Key::EDDSA | Key::Sr25519 | Key::TwoFA => {
            let validation_msg = serde_json::from_slice::<RecoveryValidationResult>(&res.data)?;
            match validation_msg {
                RecoveryValidationResult::EDDSA(_) => {
                    info!("{} recovery validated", kind);
                }
                RecoveryValidationResult::Error(err) => {
                    bail!("{}", err);
                }
                _ => {
                    bail!("Wrong validation result");
                }
            }
        }
        Key::ECDSA => {
            let validation_msg = serde_json::from_slice::<RecoveryValidationResult>(&res.data)?;
            if let RecoveryValidationResult::ECDSA(res) = validation_msg {
                info!("ECDSA recovery validated");

                info!("Updating paillier keys");
                let update = UpdatePaillierKeysCommand {
                    key_id: key_id.to_string(),
                    new_eks: vec![res.eks()],
                };

                let node_ids_to_update = party_nodes
                    .iter()
                    .filter(|&node_id| *node_id != old_node_id);

                for node_id in node_ids_to_update {
                    let message_new_key = format!(
                        "network.gridlock.nodes.async.Message.new.{node_id}"
                    );
                    let msg = serde_json::to_string(&update)?;
                    nc.publish(&message_new_key, msg)?;
                }
                info!("Paillier keys updated");
            }
        }
    }

    info!("Publishing key info updates");
    for node in &key_info.node_pool {
        nc.publish(
            &format!("network.gridlock.nodes.async.Message.new.{}", node.node_id),
            &serde_json::to_string(
                &(UpdateKeyInfoCommand {
                    key_id: key_id.to_string(),
                    key_info: key_info.clone(),
                })
            )?
        )?;
    }
    info!("Key info updated");

    Ok(())
}

/// Enrich key info with new recovery node id and public key
fn enrich_key_info(
    key_info: KeyInfo,
    new_node_id: &NodeId,
    new_node_networking_public_key: &str,
    old_node_id: &NodeId
) -> KeyInfo {
    let mut key_info = key_info;
    let old_node_index = key_info.node_pool
        .iter()
        .position(|n| n.node_id == *old_node_id)
        .unwrap();

    key_info.node_pool[old_node_index] = NodeInfo {
        node_id: new_node_id.clone(),
        networking_public_key: new_node_networking_public_key.to_string(),
        kind: key_info.node_pool[old_node_index].kind.clone(),
        share_index: key_info.node_pool[old_node_index].share_index,
    };

    key_info
}
