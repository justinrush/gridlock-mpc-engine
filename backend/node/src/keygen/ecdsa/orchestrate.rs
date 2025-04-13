use crate::command::MsgContext;
use crate::communication::ecdsa::JoinMessage;
use crate::keygen::ecdsa::{ KeyGenParams, KeyGenResult, NewKeyGenSession };
use crate::keygen::{ KeyGenCommand, KeyGenResponse };
use crate::storage::fs::WriteOpts;
use crate::storage::KeyInfoStore;
use anyhow::{ bail, Result };
use shared::key_info::{ Key, KeyInfo, Node, NodeInfo, UpdateKeyInfoCommand };
use tracing::instrument;

#[instrument(skip_all)]
pub fn orchestrate(cmd: KeyGenCommand, ctx: MsgContext) -> Result<KeyGenResponse> {
    let app = ctx.get_app()?;
    let nc = app.nc;

    let party_nodes = cmd.party_nodes;
    let key_id = cmd.key_id;

    let party_count = party_nodes.len();
    if party_count < 3 {
        bail!("Not enough nodes in party");
    }

    let join_key = format!("network.gridlock.nodes.keyGen.session.{}.join", &key_id);
    let join_sub = nc.subscribe(&join_key)?;

    let result_key = format!("network.gridlock.nodes.keyGen.session.{}.result", &key_id);
    let result_sub = nc.subscribe(&result_key)?;

    let gen_new_data_key = serde_json::to_vec(
        &(NewKeyGenSession {
            key_id: key_id.clone(),
            extra_shares: vec![],
            client_e2e_public_key: None,
            encrypted_signing_key: None,
            email: None,
        })
    )?;

    let mut node_ids = Vec::new();
    for node_id in party_nodes.iter() {
        node_ids.push(node_id.clone());
        let gen_new_key = format!("network.gridlock.nodes.keyGen.new.{node_id}");
        nc.publish(&gen_new_key, &gen_new_data_key)?;
    }

    let mut node_pool = Vec::new();
    for i in 0..party_count {
        // accept a new party
        let next = join_sub.next().unwrap();
        let msg = serde_json::from_slice::<JoinMessage>(&next.data).unwrap();
        let node_id = msg.node_id.clone().try_into()?;

        node_pool.push(NodeInfo {
            node_id: msg.node_id,
            networking_public_key: msg.networking_public_key,
            kind: {
                if app.node.node_id == node_id { Node::Owner } else { Node::Guardian }
            },
            share_index: i + 1,
        });

        next.respond(
            &serde_json
                ::to_string(
                    &(KeyGenParams {
                        num_parties: party_count,
                        party_num: i,
                    })
                )
                .unwrap()
        ).unwrap();
        nc.flush().unwrap();
    }

    nc.publish(
        &format!("network.gridlock.nodes.keyGen.session.{key_id}.start"),
        &serde_json::to_string(&party_count).unwrap()
    )?;

    let mut res_vec = Vec::new();

    for _ in 0..party_count {
        // accept a new party
        let res = result_sub.next().unwrap();
        res_vec.push(res);
    }

    let key_gen_result = serde_json::from_slice::<KeyGenResult>(&res_vec[0].data)?;

    let key_info = KeyInfo {
        kind: Key::ECDSA {
            y_sum: key_gen_result.y_sum.clone(),
        },
        node_pool: node_pool.clone(),
    };

    for node in node_pool {
        nc.publish(
            &format!("network.gridlock.nodes.Message.new.{}", node.node_id),
            &serde_json::to_string(
                &(UpdateKeyInfoCommand {
                    key_id: key_id.to_string(),
                    key_info: key_info.clone(),
                })
            )?
        )?;
    }

    KeyInfoStore::save_key_info(&key_info, &key_id, &WriteOpts::CreateNewOnly)?;

    Ok(KeyGenResponse::ECDSA(key_gen_result))
}
