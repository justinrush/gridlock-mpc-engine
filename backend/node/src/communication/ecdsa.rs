use crate::node::NodeIdentity;
use anyhow::{ anyhow, bail };
use serde::de::DeserializeOwned;
use serde::{ Deserialize, Serialize };
use shared::key_info::NodeId;
use std::any::type_name;
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::error;

#[derive(Serialize, Deserialize)]
pub struct JoinMessage {
    pub session_id: String,
    pub node_id: NodeId,
    pub networking_public_key: String,
}

impl JoinMessage {
    pub fn new(session_id: String, index: usize) -> Self {
        let node = match NodeIdentity::load() {
            Ok(node) => node,
            Err(err) => {
                let err_msg = format!("Node id is not retrievable: {}", err);
                error!("{}", err_msg);
                panic!("{}", err_msg);
            }
        };
        let mut node_id = node.node_id.to_string();
        if index > 0 {
            node_id.push_str(&format!("--{}", &index.to_string()));
        }
        let pk = node.networking_public_key.to_string();

        JoinMessage {
            session_id,
            node_id: NodeId::new(node_id),
            networking_public_key: pk,
        }
    }
}

pub trait HasSenderId {
    fn get_sender_id(&self) -> usize;
}

pub trait HasTargetId {
    fn get_target_id(&self) -> usize;
}

fn collect_messages<T>(
    sub: &nats::Subscription,
    party_count: usize,
    receiver_id: Option<usize>
) -> anyhow::Result<Vec<T>>
    where T: DeserializeOwned + HasSenderId + Clone
{
    let message_count = party_count - (if receiver_id.is_some() { 1 } else { 0 });

    let mut map: BTreeMap<usize, T> = BTreeMap::new();
    while map.len() < message_count {
        let data = get_next_item::<T>(sub).map_err(|err|
            anyhow!("{}, recieved responses from parties {:?}", err, map.keys())
        )?;

        let sender_id = data.get_sender_id();

        if let Some(id) = receiver_id {
            if id == sender_id {
                let err_msg = format!("Received a \"{}\" message from ourselves", type_name::<T>());
                bail!("{}", err_msg);
            }
        }

        if map.contains_key(&sender_id) {
            let err_msg = format!(
                "Received more than one \"{}\" message from sender #{}",
                type_name::<T>(),
                sender_id
            );
            bail!("{}", err_msg);
        }

        map.insert(sender_id, data);
    }

    for i in 0..party_count {
        if let Some(id) = receiver_id {
            if i == id {
                map.remove(&i);
            }
        }
    }
    let values = map.values().cloned().collect();

    Ok(values)
}

pub fn collect_messages_ordered<T>(
    sub: &nats::Subscription,
    expected_count: usize
) -> anyhow::Result<Vec<T>>
    where T: DeserializeOwned + HasSenderId + Clone
{
    collect_messages(sub, expected_count, None)
}

pub fn collect_messages_p2p<T>(
    sub: &nats::Subscription,
    party_count: usize,
    receiver_id: usize
) -> anyhow::Result<Vec<T>>
    where T: DeserializeOwned + HasSenderId + Clone
{
    collect_messages(sub, party_count, Some(receiver_id))
}

pub fn collect_message<T>(sub: &nats::Subscription) -> anyhow::Result<T>
    where T: DeserializeOwned + Clone
{
    get_next_item::<T>(sub)
}

fn get_next_item<T>(sub: &nats::Subscription) -> anyhow::Result<T> where T: DeserializeOwned + Clone {
    let mesg = match sub.next_timeout(Duration::from_secs(30)) {
        Ok(msg) => msg,
        Err(_) => {
            let err_msg = format!("Timeout while waiting on {:?}", &sub);
            bail!("{}", err_msg);
        }
    };
    serde_json::from_slice::<T>(&mesg.data).map_err(|_| {
        let err_msg = format!(
            "Failed to deserialize message into a \"{}\" struct, message was {:?}",
            type_name::<T>(),
            String::from_utf8(mesg.data).unwrap()
        );
        anyhow!("{}", err_msg)
    })
}
