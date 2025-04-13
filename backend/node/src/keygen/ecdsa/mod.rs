mod client;
pub mod orchestrate;
pub mod session;

use crate::communication::ecdsa::HasSenderId;
use crate::keygen::ShareParams;
use nats::Connection;
use serde::{ Deserialize, Serialize };
use shared::ecdsa::Sum;

#[cfg(test)]
mod tests {
    use curv::arithmetic::Converter;
    use curv::elliptic::curves::{ Scalar, Secp256k1 };
    use curv::BigInt;
    #[test]
    fn can_convert_scalar_to_bn() {
        let x = Scalar::<Secp256k1>::random();
        let plaintext = BigInt::to_bytes(&x.to_bigint());

        let out_bn = BigInt::from_bytes(&plaintext[..]);
        let out_fe = Scalar::from(&out_bn);

        assert_eq!(x, out_fe)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenResult {
    pub y_sum: Sum,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewKeyGenSession {
    pub key_id: String,
    pub extra_shares: Vec<Option<String>>,
    pub client_e2e_public_key: Option<String>,
    pub encrypted_signing_key: Option<String>,
    pub email: Option<String>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenParams {
    pub num_parties: usize,
    pub party_num: usize,
}

pub struct KeyGenContext<'a> {
    pub nc: Connection,
    pub share_params: ShareParams,
    pub key_id: &'a String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct KeyGenMessage {
    pub sender_id: usize,
    pub msg: String,
}

impl HasSenderId for KeyGenMessage {
    fn get_sender_id(&self) -> usize {
        return self.sender_id;
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewKeyGenMessage {
    pub key_id: String,
    pub extra_shares: Vec<Option<String>>,
    pub client_e2e_public_key: String,
    pub encrypted_signing_key: String,
    pub email: String,
}

#[test]
#[allow(non_snake_case)]
fn can_deserialize_NewKeyGenSession() {
    let data =
        "{\"key_id\":\"26401131-3982-9438-0871-391502152815\",\"extra_shares\":[\"641ebc3e7b5bcddf9affbd0b871095ad0883334cca1530f53e17bd513cfc811a\", null]}";
    let result = serde_json::from_str::<NewKeyGenSession>(&data);
    assert_eq!(result.is_ok(), true);
}
