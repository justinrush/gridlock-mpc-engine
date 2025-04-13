use crate::ecdsa::Sum;
use anyhow::Context;
use anyhow::Result;
use derive_more::Display;
use serde::{ Deserialize, Serialize };
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct UpdateKeyInfoCommand {
    pub key_id: String,
    pub key_info: KeyInfo,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeyInfo {
    #[serde(flatten)]
    pub kind: Key,
    pub node_pool: Vec<NodeInfo>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeInfo {
    pub node_id: NodeId,
    pub networking_public_key: String,
    pub kind: Node,
    pub share_index: usize,
}

#[derive(Clone, Serialize, Deserialize, Debug, Display, PartialEq)]
pub struct NodeId(String);

impl TryFrom<NodeId> for Uuid {
    type Error = anyhow::Error;

    fn try_from(value: NodeId) -> Result<Self> {
        value.0.parse().context("node_id should be valid uuid")
    }
}

impl NodeId {
    pub fn new(str: String) -> Self {
        NodeId(str)
    }

    pub fn new_from_uuid(str: Uuid) -> Self {
        NodeId(str.to_string())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "key_type")]
pub enum Key {
    ECDSA {
        y_sum: Sum,
    },
    EDDSA {
        y_sum: String,
    },
    Sr25519 {
        pk: String,
    },
    TwoFA,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum Node {
    Owner,
    ServerGuardian,
    Guardian,
}
