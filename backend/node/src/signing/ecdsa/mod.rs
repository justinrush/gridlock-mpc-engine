pub mod orchestrate;
pub mod session;

use crate::communication::ecdsa::{ HasSenderId, HasTargetId };
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::elliptic::curves::{ Point, Scalar, Secp256k1 };
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    LocalSignature,
    SignBroadcastPhase1,
    SignDecommitPhase1,
};
use multi_party_ecdsa::utilities::mta::{ MessageA, MessageB };
use serde::{ Deserialize, Serialize };
use sha2::Sha256;

#[derive(Clone, Deserialize, Serialize)]
pub struct NewSignSession {
    pub session_id: String,
    pub key_id: String,
    pub message: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct NewSignMessage {
    pub session_id: String,
    pub key_id: String,
    pub message: Vec<u8>,
    pub client_e2e_public_key: String,
    pub encrypted_signing_key: String,
    pub is_transfer_tx: Option<bool>,
    pub timestamp: Option<String>,
    pub message_hmac: Option<String>,
    pub email: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct JoinSignSessionResponse {
    pub id_in_session: usize,
    pub message: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
pub struct JoinSignSessionErrorResponse {
    pub error: String,
}

#[derive(Deserialize, PartialEq, Serialize, Clone, Debug)]
pub struct SigningResult {
    pub r: String,
    pub s: String,
    pub recid: u8,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Phase0Identity {
    pub id_in_session: usize,
    pub shareholder_id: usize,
}

impl HasSenderId for Phase0Identity {
    fn get_sender_id(&self) -> usize {
        self.id_in_session
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Phase1Commitment {
    pub sender_id: usize,
    pub commitment: SignBroadcastPhase1,
    pub message: MessageA,
}

impl HasSenderId for Phase1Commitment {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Phase2Gamma {
    pub sender_id: usize,
    pub target_id: usize,
    pub gamma: MessageB,
    pub w: MessageB,
}

impl HasSenderId for Phase2Gamma {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}

impl HasTargetId for Phase2Gamma {
    fn get_target_id(&self) -> usize {
        self.target_id
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Phase3Broadcast {
    pub sender_id: usize,
    pub delta: Scalar<Secp256k1>,
    pub t: Point<Secp256k1>,
}

impl HasSenderId for Phase3Broadcast {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Phase4Decommit {
    pub sender_id: usize,
    pub decommit: SignDecommitPhase1,
}

impl HasSenderId for Phase4Decommit {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Phase5RDash {
    pub sender_id: usize,
    pub r_dash: Point<Secp256k1>,
}

impl HasSenderId for Phase5RDash {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Phase6Broadcast {
    pub sender_id: usize,
    pub s: Point<Secp256k1>,
    pub zk_proof: HomoELGamalProof<Secp256k1, Sha256>,
    pub r: Point<Secp256k1>,
}

impl HasSenderId for Phase6Broadcast {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Phase7Signature {
    pub sender_id: usize,
    pub signature: LocalSignature,
}

impl HasSenderId for Phase7Signature {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}
