use serde::{ Deserialize, Serialize };

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Sum {
    pub x: String,
    pub y: String,
}
