use crate::command::MsgContext;
use crate::communication::nats::{ BroadcastMessage, JoinMessage, JoinResponse };
use crate::keygen::eddsa::session::NewKeyGenSession;
use crate::keygen::eddsa::KeyGenResult;
use crate::keygen::{ KeyGenCommand, KeyGenResponse };
use anyhow::{ bail, Result };
use shared::key_info::{ Key, KeyInfo, Node, NodeInfo, UpdateKeyInfoCommand };
use tracing::{ error, info, instrument };

static THRESHOLD: usize = 2;

#[instrument(skip_all)]
pub fn orchestrate(cmd: KeyGenCommand, ctx: MsgContext) -> Result<KeyGenResponse> {
    let app = ctx.get_app()?;
    let nc = app.nc;
    // TODO: where should session be used??
    let session_id = cmd.session_id.clone();

    let party_nodes = cmd.party_nodes;
    let key_id = cmd.key_id;

    let party_count = party_nodes.len();
    if party_count < 3 {
        bail!("Not enough nodes in party");
    }

    let join_key = format!("network.gridlock.nodes.KeyGenEdDSA.{}.Join", &key_id);
    let join_sub = nc.subscribe(&join_key)?;

    let result_key = format!("network.gridlock.nodes.KeyGenEdDSA.{}.Result", &key_id);
    let result_sub = nc.subscribe(&result_key)?;

    let shares1 = vec![1];
    let shares2 = vec![2];
    let shares3 = vec![3];
    let shares4 = vec![4];
    let shares5 = vec![5];

    let all_shares = vec![shares1, shares2, shares3, shares4, shares5];

    for (node_id, shares) in party_nodes.iter().zip(all_shares) {
        let key_gen_new = format!("network.gridlock.nodes.KeyGenEdDSA.new.{node_id}");
        let key_gen_new_data = serde_json
            ::to_string(
                &(NewKeyGenSession {
                    key_id: key_id.to_owned(),
                    threshold: THRESHOLD,
                    share_indices: shares.to_vec(),
                })
            )
            .unwrap();
        nc.publish(&key_gen_new, &key_gen_new_data)?;
    }

    let mut msg_vec = Vec::new();

    for _ in 0..party_count {
        info!("Someone joined");
        let next = join_sub.next().unwrap();
        msg_vec.push(next);
    }

    let mut node_pool = Vec::new();
    if msg_vec.len() >= 3 {
        let mut indices = Vec::new();
        for m in msg_vec.iter() {
            let confirmation = serde_json::from_slice::<JoinMessage>(&m.data)?;
            let node_id = confirmation.node_id.clone().try_into()?;
            node_pool.push(NodeInfo {
                node_id: confirmation.node_id,
                networking_public_key: confirmation.networking_public_key,
                kind: {
                    if app.node.node_id == node_id { Node::Owner } else { Node::Guardian }
                },
                share_index: confirmation.party_index,
            });
            indices.push(confirmation.party_index);
        }
        indices.sort();
        info!("indices: {:?}", &indices);
        let join_resp = JoinResponse {
            party_count: indices.len(),
            all_party_indices: indices,
        };
        for (_, m) in msg_vec.iter().enumerate() {
            match m.respond(&serde_json::to_string(&join_resp).unwrap()) {
                Ok(_) => {}
                Err(err) => {
                    error!("Error: {}", err);
                }
            }
        }
        nc.flush()?;
    }

    let mut res_vec = Vec::new();
    for _ in 0..party_count {
        // accept a new party
        let res = result_sub.next().unwrap();
        res_vec.push(res);
    }

    let pk = serde_json::from_slice::<BroadcastMessage<KeyGenResult>>(&res_vec[0].data)?.message;

    let key_info = KeyInfo {
        kind: Key::EDDSA {
            y_sum: pk.y_sum.clone(),
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
    Ok(KeyGenResponse::EDDSA(pk))
}
