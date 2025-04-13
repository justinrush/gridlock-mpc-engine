use crate::common::config::Config;
use crate::common::helpers::{ delete_file, get_nats_connection, is_file_exist, FileKind };
use crate::common::protocol_runner::new_uuid;
use crate::function;
use anyhow::{ bail, Result };
use derive_more::From;
use serde::{ Deserialize, Serialize };
use sha3::{ Digest, Sha3_256 };
use std::time::Duration;

const FILE_EXIST_TIMEOUT: u64 = 100;
static NATS_TIMEOUT: u64 = 5;

#[ctor::ctor]
fn init() {
    // We need to wait a bit until all nodes connect to NAT's and retrieve their identities
    std::thread::sleep(Duration::from_millis(500));
}

#[ctor::dtor]
fn shutdown() {
    // Waiting for node containers to process NAT's messages
    std::thread::sleep(Duration::from_millis(500));
}

// #[tokio::test]
async fn ecdsa_orchestrate() -> Result<()> {
    println!("\ntest {}", function!());

    // KEY GENERATION
    let party_nodes = [1usize, 2, 3, 4];
    let owner_node = *party_nodes.first().expect("Owner node");
    let session_id = new_uuid().to_string();
    let key_id = session_id.clone();
    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;

    let owner_node_id = config.nodes.get_node_by_index(owner_node).unwrap().node_id;
    let party_node_ids: Vec<_> = party_nodes
        .into_iter()
        .map(|i| NodeId(config.nodes.get_node_by_index(i).unwrap().node_id))
        .collect();

    let message_new_key = format!("network.gridlock.nodes.Message.new.{owner_node_id}");
    let cmd: TaggedCommand = (KeyGenCommand {
        kind: Key::ECDSA,
        party_nodes: party_node_ids.clone(),
        key_id: key_id.clone(),
        session_id: session_id.clone(),
    }).into();
    let msg = serde_json::to_string(&cmd).expect("Serialized keygen cmd");
    let resp = tokio::time::timeout(
        Duration::from_secs(NATS_TIMEOUT),
        nc.request(&message_new_key, &msg)
    ).await??;
    let keygen_resp: KeyGenResponse = serde_json::from_slice(&resp.data)?;
    let KeyGenResponse::ECDSA(pk) = keygen_resp else {
        bail!("Not ecdsa response");
    };

    // wait till key info files will be written to file system
    tokio::time::sleep(Duration::from_millis(FILE_EXIST_TIMEOUT)).await;
    for node_indx in party_nodes {
        assert!(is_file_exist(FileKind::Info, node_indx, &key_id.clone()));
    }

    // SIGNING
    let msg_to_sign = "Sign this please".to_string().into_bytes();
    let mut hasher = Sha3_256::new();
    hasher.update(&msg_to_sign);
    let hashed_msg = hasher.finalize();

    let party_nodes = [1usize, 2, 3];
    let party_node_ids: Vec<_> = party_nodes
        .into_iter()
        .map(|i| NodeId(config.nodes.get_node_by_index(i).unwrap().node_id))
        .collect();
    let message_new_key = format!("network.gridlock.nodes.Message.new.{owner_node_id}");
    let cmd: TaggedCommand = (SigningCommand {
        kind: Key::ECDSA,
        party_nodes: party_node_ids.clone(),
        key_id: key_id.clone(),
        session_id: session_id.clone(),
        msg: hashed_msg.to_vec(),
    }).into();
    let msg = serde_json::to_string(&cmd).expect("Serialized keygen cmd");
    let resp = tokio::time::timeout(
        Duration::from_secs(NATS_TIMEOUT),
        nc.request(&message_new_key, &msg)
    ).await??;
    let SigningResponse::ECDSA(sig) = serde_json::from_slice(&resp.data)? else {
        bail!("Not ecdsa response");
    };

    verify_ecdsa_sig(pk, sig, &hashed_msg)?;

    // RECOVERY
    let party_nodes = [1usize, 2, 3];
    let owner_node_id = config.nodes.get_node_by_index(owner_node).unwrap().node_id;
    let party_node_ids: Vec<_> = party_nodes
        .into_iter()
        .map(|i| NodeId(config.nodes.get_node_by_index(i).unwrap().node_id))
        .collect();

    let new_index = 5;
    let new_node_identity = config.nodes.get_node_by_index(new_index)?;
    let new_node_id = NodeId(new_node_identity.node_id);
    let new_node_public_key = new_node_identity.public_key;

    let old_index = 4;
    let old_node_identity = config.nodes.get_node_by_index(old_index)?;
    let old_node_id = NodeId(old_node_identity.node_id);

    let message_new_key = format!("network.gridlock.nodes.Message.new.{owner_node_id}");
    let cmd: TaggedCommand = (RecoveryCommand {
        kind: Key::ECDSA,
        key_id: key_id.clone(),
        session_id: session_id.clone(),
        new_node_id,
        new_node_public_key,
        old_node_id,
        party_nodes: party_node_ids,
    }).into();
    let msg = serde_json::to_string(&cmd).expect("Serialized keygen cmd");
    let resp = tokio::time::timeout(
        Duration::from_secs(NATS_TIMEOUT),
        nc.request(&message_new_key, &msg)
    ).await??;
    let RecoveryResponse::Completed = serde_json::from_slice(&resp.data)?;

    tokio::time::sleep(Duration::from_millis(FILE_EXIST_TIMEOUT)).await;
    assert!(is_file_exist(FileKind::Key, new_index, &key_id.clone()));
    assert!(is_file_exist(FileKind::Info, new_index, &key_id.clone()));

    Ok(())
}

// #[tokio::test]
async fn ecdsa_async_recovery_orchestrate() -> Result<()> {
    println!("\ntest {}", function!());

    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;
    let key_id = "001dd60e-ebac-4363-b915-b76e7624622d".to_string();
    let session_id = key_id.clone();

    // RECOVERY
    let party_nodes = [1usize, 2, 3];
    let owner_node = *party_nodes.first().unwrap();
    let owner_node_id = config.nodes.get_node_by_index(owner_node).unwrap().node_id;
    let party_node_ids: Vec<_> = party_nodes
        .into_iter()
        .map(|i| NodeId(config.nodes.get_node_by_index(i).unwrap().node_id))
        .collect();

    //TODO#q: use sixth node for this purpose that should be shutdown beforehand
    let new_index = 7;
    let new_node_identity = config.nodes.get_node_by_index(new_index)?;
    let new_node_id = NodeId(new_node_identity.node_id);
    let new_node_public_key = new_node_identity.public_key;

    let old_index = 5;
    let old_node_identity = config.nodes.get_node_by_index(old_index)?;
    let old_node_id = NodeId(old_node_identity.node_id);

    let message_new_key = format!("network.gridlock.nodes.Message.new.{owner_node_id}");
    let cmd: TaggedCommand = (RecoveryCommand {
        kind: Key::ECDSA,
        key_id: key_id.clone(),
        session_id: session_id.clone(),
        new_node_id,
        new_node_public_key,
        old_node_id,
        party_nodes: party_node_ids,
    }).into();
    let msg = serde_json::to_string(&cmd).expect("Serialized keygen cmd");
    let resp = tokio::time::timeout(
        Duration::from_secs(NATS_TIMEOUT),
        nc.request(&message_new_key, &msg)
    ).await??;
    let RecoveryResponse::Completed = serde_json::from_slice(&resp.data)?;

    tokio::time::sleep(Duration::from_millis(FILE_EXIST_TIMEOUT)).await;
    assert!(is_file_exist(FileKind::Key, new_index, &key_id.clone()));
    assert!(is_file_exist(FileKind::Info, new_index, &key_id.clone()));

    Ok(())
}

// #[tokio::test]
async fn eddsa_orchestrate() -> Result<()> {
    println!("\ntest {}", function!());

    // KEY GENERATION
    let party_nodes = [1usize, 2, 3, 4];
    let owner_node = *party_nodes.first().expect("Owner node");
    let session_id = new_uuid().to_string();
    let key_id = session_id.clone();
    let config = Config::new_local()?;
    let nc = get_nats_connection(&config).await?;

    let owner_node_id = config.nodes.get_node_by_index(owner_node).unwrap().node_id;
    let party_node_ids: Vec<_> = party_nodes
        .into_iter()
        .map(|i| NodeId(config.nodes.get_node_by_index(i).unwrap().node_id))
        .collect();

    let message_new_key = format!("network.gridlock.nodes.Message.new.{owner_node_id}");
    let cmd: TaggedCommand = (KeyGenCommand {
        kind: Key::EDDSA,
        party_nodes: party_node_ids.clone(),
        key_id: key_id.clone(),
        session_id: session_id.clone(),
    }).into();
    let msg = serde_json::to_string(&cmd).expect("Serialized keygen cmd");
    let resp = tokio::time::timeout(
        Duration::from_secs(NATS_TIMEOUT),
        nc.request(&message_new_key, &msg)
    ).await??;

    // wait till key info files will be written to file system
    tokio::time::sleep(Duration::from_millis(FILE_EXIST_TIMEOUT)).await;
    for node_indx in party_nodes {
        assert!(is_file_exist(FileKind::Info, node_indx, &key_id.clone()));
    }

    let keygen_resp: KeyGenResponse = serde_json::from_slice(&resp.data)?;
    let KeyGenResponse::EDDSA(pk) = keygen_resp else {
        bail!("Not ecdsa response");
    };

    // SIGNING
    let msg_to_sign = "Sign this please".to_string().into_bytes();
    let mut hasher = Sha3_256::new();
    hasher.update(&msg_to_sign);
    let hashed_msg = hasher.finalize();

    let message_new_key = format!("network.gridlock.nodes.Message.new.{owner_node_id}");
    let cmd: TaggedCommand = (SigningCommand {
        kind: Key::EDDSA,
        party_nodes: party_node_ids,
        key_id: key_id.clone(),
        session_id: session_id.clone(),
        msg: hashed_msg.to_vec(),
    }).into();
    let msg = serde_json::to_string(&cmd).expect("Serialized keygen cmd");
    let resp = tokio::time::timeout(
        Duration::from_secs(NATS_TIMEOUT),
        nc.request(&message_new_key, &msg)
    ).await??;
    let SigningResponse::EDDSA(sig) = serde_json::from_slice(&resp.data)? else {
        bail!("Not ecdsa response");
    };

    verify_eddsa_sig(pk, sig, &hashed_msg)?;

    // RECOVERY
    let party_nodes = [1usize, 2, 3];
    let owner_node_id = config.nodes.get_node_by_index(owner_node).unwrap().node_id;
    let party_node_ids: Vec<_> = party_nodes
        .into_iter()
        .map(|i| NodeId(config.nodes.get_node_by_index(i).unwrap().node_id))
        .collect();

    let new_index = 5;
    let new_node_identity = config.nodes.get_node_by_index(new_index)?;
    let new_node_id = NodeId(new_node_identity.node_id);
    let new_node_public_key = new_node_identity.public_key;

    let old_index = 4;
    let old_node_identity = config.nodes.get_node_by_index(old_index)?;
    let old_node_id = NodeId(old_node_identity.node_id);

    let message_new_key = format!("network.gridlock.nodes.Message.new.{owner_node_id}");
    let cmd: TaggedCommand = (RecoveryCommand {
        kind: Key::EDDSA,
        key_id: key_id.clone(),
        session_id: session_id.clone(),
        new_node_id,
        new_node_public_key,
        old_node_id,
        party_nodes: party_node_ids,
    }).into();
    let msg = serde_json::to_string(&cmd).expect("Serialized keygen cmd");
    let resp = tokio::time::timeout(
        Duration::from_secs(NATS_TIMEOUT),
        nc.request(&message_new_key, &msg)
    ).await??;
    let RecoveryResponse::Completed = serde_json::from_slice(&resp.data)?;

    tokio::time::sleep(Duration::from_millis(FILE_EXIST_TIMEOUT)).await;
    assert!(is_file_exist(FileKind::Key, new_index, &key_id.clone()));
    assert!(is_file_exist(FileKind::Info, new_index, &key_id.clone()));

    Ok(())
}

fn verify_ecdsa_sig(
    pk: ecdsa::KeyGenResult,
    sig: ecdsa::SigningResult,
    message: &[u8]
) -> Result<()> {
    use libsecp256k1::{ verify, Message, PublicKey, Signature };

    let pk_fmt = format!("{:0>64}", pk.y_sum.x) + &*format!("{:0>64}", pk.y_sum.y);
    let pk_bytes = hex::decode(pk_fmt.as_bytes())?;
    let pk = PublicKey::parse_slice(&pk_bytes, None)?;

    let mut s = hex::decode(sig.r)?;
    let sigma = &hex::decode(sig.s)?;
    s.extend_from_slice(sigma);

    let signature: Signature = Signature::parse_overflowing_slice(&s)?;

    let msg = Message::parse_slice(message)?;
    if !verify(&msg, &signature, &pk) {
        bail!("Signature not verified");
    }

    println!("Signature verified");
    Ok(())
}

fn verify_eddsa_sig(
    pk: eddsa::KeyGenResult,
    sig: eddsa::SignatureResult,
    message: &[u8]
) -> Result<()> {
    use ed25519_dalek::{ PublicKey, Signature, Verifier };

    let pub_key = PublicKey::from_bytes(&hex::decode(pk.y_sum)?).unwrap();

    let mut s = hex::decode(sig.R).unwrap();

    let sigma = &hex::decode(sig.sigma).unwrap();

    s.extend_from_slice(sigma);

    let signature: Signature = Signature::try_from(&*s)?;

    pub_key.verify(message, &signature)?;
    println!("Signature verified");
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, From)]
#[serde(tag = "cmd")]
pub enum TaggedCommand {
    OrchestrateKeyGen(KeyGenCommand),
    OrchestrateSigning(SigningCommand),
    OrchestrateRecovery(RecoveryCommand),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct KeyGenCommand {
    #[serde(flatten)]
    pub kind: Key,
    pub party_nodes: Vec<NodeId>,
    pub key_id: String,
    pub session_id: String,
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
pub struct NodeId(String);

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyGenResponse {
    ECDSA(ecdsa::KeyGenResult),
    EDDSA(eddsa::KeyGenResult),
    Sr25519(String),
    TwoFA(String),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SigningCommand {
    #[serde(flatten)]
    pub kind: Key,
    pub key_id: String,
    pub session_id: String,
    pub party_nodes: Vec<NodeId>,
    pub msg: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SigningResponse {
    ECDSA(ecdsa::SigningResult),
    EDDSA(eddsa::SignatureResult),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RecoveryCommand {
    #[serde(flatten)]
    kind: Key,
    key_id: String,
    session_id: String,
    new_node_id: NodeId,
    new_node_public_key: String,
    old_node_id: NodeId,
    party_nodes: Vec<NodeId>,
}

#[derive(Serialize, Deserialize)]
pub enum RecoveryResponse {
    Completed,
}

mod ecdsa {
    use serde::{ Deserialize, Serialize };

    #[derive(Serialize, Deserialize, Debug)]
    pub struct KeyGenResult {
        pub y_sum: Sum,
    }

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct Sum {
        pub x: String,
        pub y: String,
    }

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct SigningResult {
        pub r: String,
        pub s: String,
        pub recid: u8,
    }
}

mod eddsa {
    use serde::{ Deserialize, Serialize };

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct KeyGenResult {
        pub y_sum: String,
    }

    #[derive(Clone, Serialize, Deserialize, Debug)]
    pub struct SignatureResult {
        pub sigma: String,
        pub R: String,
    }
}
