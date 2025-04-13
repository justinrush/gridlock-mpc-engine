pub mod ecdsa;
pub mod eddsa;
pub mod key_import;
pub mod sr25519;

use crate::command::{ JsonCommand, MsgContext };
use anyhow::Result;
use serde::{ Deserialize, Serialize };
use shared::key_info::NodeId;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeyGenCommand {
    #[serde(flatten)]
    pub kind: Key,
    pub party_nodes: Vec<NodeId>,
    pub key_id: String,
    pub session_id: String,
}

impl KeyGenCommand {
    pub fn share_count(&self) -> usize {
        self.party_nodes.len()
    }
}

impl JsonCommand for KeyGenCommand {
    type Response = KeyGenResponse;

    fn execute_message(self, ctx: MsgContext) -> Result<Self::Response> where Self: Sized {
        match self.kind {
            Key::ECDSA => ecdsa::orchestrate::orchestrate(self, ctx),
            Key::EDDSA => eddsa::orchestrate::orchestrate(self, ctx),
            Key::Sr25519 => { todo!() }
            Key::TwoFA => { todo!() }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "key_type")]
pub enum Key {
    ECDSA,
    EDDSA,
    Sr25519,
    TwoFA,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyGenResponse {
    ECDSA(ecdsa::KeyGenResult),
    EDDSA(eddsa::KeyGenResult),
    Sr25519(String),
    TwoFA(String),
}

pub struct ShareParams {
    pub party_count: usize,
    pub party_index: usize,
    pub threshold: usize,
}
