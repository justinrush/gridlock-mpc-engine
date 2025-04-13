pub mod client;
pub mod orchestrate;
pub mod session;

use serde::{ Deserialize, Serialize };

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignatureResult {
    pub sigma: String,
    pub R: String,
}
