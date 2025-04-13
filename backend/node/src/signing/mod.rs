use crate::command::{ JsonCommand, MsgContext };
use anyhow::Result;
use serde::{ Deserialize, Serialize };
use shared::key_info::NodeId;

pub mod ecdsa;
pub mod eddsa;
pub mod sr25519;
pub mod sr25519_musign;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SigningCommand {
    #[serde(flatten)]
    pub kind: Key,
    pub key_id: String,
    pub session_id: String,
    pub party_nodes: Vec<NodeId>,
    pub msg: Vec<u8>,
}

impl JsonCommand for SigningCommand {
    type Response = SigningResponse;

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

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SigningResponse {
    ECDSA(ecdsa::SigningResult),
    EDDSA(eddsa::SignatureResult),
}
