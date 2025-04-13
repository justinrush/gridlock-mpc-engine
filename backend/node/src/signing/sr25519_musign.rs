use crate::communication::nats::{
    BaseMessenger,
    NatsBaseMessenger,
    NatsBaseSession,
    NatsPeerMessenger,
    PeerMessenger,
};
use crate::communication::protocol::{ AllRounds, KeySignSr25519AllRounds, Topic };
use crate::node::NodeIdentity;
use crate::storage::{ KeyshareAccessor, Sr25519 };
use crate::App;
use anyhow::{ anyhow, Context, Error, Result };
use schnorrkel::{ signing_context, ExpansionMode, Keypair, MiniSecretKey, SecretKey };
use serde::{ Deserialize, Serialize };
use std::thread;
use tracing::{ error, info };

fn sign_session(conn: nats::Connection, session: NewSr25519KeySignSession) -> Result<()> {
    let session_id = session.session_id.clone();
    match keysign_session_inner(conn, session) {
        Ok(()) => info!("Signing completed successfully for session id: {}", session_id),
        Err(err) => error!("Error in Sr25519 signing: session id: {}, error: {}", session_id, err),
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewSr25519KeySignSession {
    pub key_id: String,
    pub session_id: String,
    pub message: Vec<u8>,
    pub party_index: usize,
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct PublicKey(String);

impl From<schnorrkel::PublicKey> for PublicKey {
    fn from(f: schnorrkel::PublicKey) -> Self {
        PublicKey(hex::encode(f.to_bytes()))
    }
}

impl From<PublicKey> for schnorrkel::PublicKey {
    fn from(f: PublicKey) -> Self {
        let r_bytes = hex::decode(f.0).expect("Hex encoded PublicKey");
        schnorrkel::PublicKey::from_bytes(&r_bytes).expect("Failed to create public key from bytes")
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Commitment(String);

impl From<schnorrkel::musig::Commitment> for Commitment {
    fn from(f: schnorrkel::musig::Commitment) -> Self {
        Commitment(hex::encode(f.0))
    }
}

impl From<Commitment> for schnorrkel::musig::Commitment {
    fn from(f: Commitment) -> Self {
        let r_bytes = hex::decode(f.0).expect("Hex encoded Commitment");
        schnorrkel::musig::Commitment(
            r_bytes.try_into().expect("Wrong length of encoded Commitment")
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Reveal(String);

impl From<schnorrkel::musig::Reveal> for Reveal {
    fn from(f: schnorrkel::musig::Reveal) -> Self {
        Reveal(hex::encode(f.0))
    }
}

impl From<Reveal> for schnorrkel::musig::Reveal {
    fn from(f: Reveal) -> Self {
        let r_bytes = hex::decode(f.0).expect("Hex encoded Reveal");
        schnorrkel::musig::Reveal(r_bytes.try_into().expect("Wrong length of encoded Reveal"))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Cosign(String);

impl From<schnorrkel::musig::Cosignature> for Cosign {
    fn from(f: schnorrkel::musig::Cosignature) -> Self {
        Cosign(hex::encode(f.0))
    }
}

impl From<Cosign> for schnorrkel::musig::Cosignature {
    fn from(f: Cosign) -> Self {
        let r_bytes = hex::decode(f.0).expect("Hex encoded Cosignature");
        schnorrkel::musig::Cosignature(
            r_bytes.try_into().expect("Wrong length of encoded Cosignature")
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Signature(String);

impl From<schnorrkel::Signature> for Signature {
    fn from(f: schnorrkel::Signature) -> Self {
        Signature(hex::encode(f.to_bytes()))
    }
}

impl From<Signature> for schnorrkel::Signature {
    fn from(f: Signature) -> Self {
        let r_bytes = hex::decode(f.0).expect("Hex encoded Cosignature");
        schnorrkel::Signature
            ::from_bytes(&r_bytes)
            .expect("Unable to recreate schnorrkel signature from bytes")
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommitmentMsg {
    pub public_key: PublicKey,
    pub commitment: Commitment,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RevealMsg {
    pub public_key: PublicKey,
    pub reveal: Reveal,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CosignMsg {
    pub public_key: PublicKey,
    pub cosign: Cosign,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ResultMsg {
    pub musig_public_key: PublicKey,
    pub sig: Signature,
}

fn keysign_session_inner(conn: nats::Connection, session: NewSr25519KeySignSession) -> Result<()> {
    let key_id = session.key_id.clone();
    let session_id = session.session_id.clone();
    let message = session.message.clone();
    info!("joining Sr25519 keysign session key_id: {}", &key_id);

    let key = KeyshareAccessor::<Sr25519>::read_only(&key_id)?.key;
    let keypair = retrieve_keypair(&key)?;
    let public_key: PublicKey = keypair.public.into();

    let threshold = key.threshold;
    let party_index = session.party_index;

    let node = NodeIdentity::load()?;
    let node_id = node.node_id.to_string();
    let public_key = node.networking_public_key;
    info!("Retrieved node identity");

    // We are not currently signing with more than one keyshare per device
    let thread_index = 0;
    let nats_session = NatsBaseSession {
        session_id,
        thread_index,
        node_id,
        public_key: public_key.clone(),
        party_index,
    };

    let sign_messenger = NatsBaseMessenger::<KeySignSr25519AllRounds>::new(
        Topic::KeySignSr25519,
        conn.clone(),
        nats_session
    )?;

    let join_response = sign_messenger.wait_for_confirmation(std::time::Duration::from_secs(10))?;

    info!("Got join response");

    let party_count = join_response.party_count;
    let mut all_party_indices = join_response.all_party_indices;
    all_party_indices.sort();

    let sign_peer_messenger = NatsPeerMessenger::from(
        sign_messenger,
        party_count,
        all_party_indices.clone()
    )?;

    let t = signing_context(b"gridlock").bytes(&message);

    // Commit stage
    let mut commit = keypair.musig(t.clone());
    let commit_msg = CommitmentMsg {
        public_key: PublicKey(public_key.clone()),
        commitment: commit.our_commitment().into(),
    };
    let other_commit_msgs = sign_peer_messenger.broadcast_and_collect_messages(
        &<KeySignSr25519AllRounds as AllRounds>::BroadcastRound::Commit,
        commit_msg
    )?;
    info!("Other parties commits received - msg count: {}", other_commit_msgs.len());
    for other_commit_msg in other_commit_msgs {
        if other_commit_msg.public_key == PublicKey(public_key.clone()) {
            continue;
        }

        commit
            .add_their_commitment(
                other_commit_msg.public_key.into(),
                other_commit_msg.commitment.into()
            )
            .map_err(Error::msg)?;
    }
    info!("Commit stage passed");

    // Reveal stage
    let mut reveal = commit.reveal_stage();
    let our_reveal = reveal.our_reveal().clone();
    let reveal_msg = RevealMsg {
        public_key: PublicKey(public_key.clone()),
        reveal: our_reveal.into(),
    };
    let other_reveal_msgs = sign_peer_messenger.broadcast_and_collect_messages(
        &<KeySignSr25519AllRounds as AllRounds>::BroadcastRound::Reveal,
        reveal_msg.clone()
    )?;
    info!("Other parties reveals received - msg count: {}", other_reveal_msgs.len());
    for other_reveal_msg in other_reveal_msgs {
        if other_reveal_msg.public_key.0 == public_key {
            continue;
        }

        reveal
            .add_their_reveal(other_reveal_msg.public_key.into(), other_reveal_msg.reveal.into())
            .map_err(Error::msg)?;
    }
    let musig_public_key = reveal.public_key();
    info!("Reveal stage passed");

    // Cosign stage
    let mut cosign = reveal.cosign_stage();
    let cosign_msg = CosignMsg {
        public_key: PublicKey(public_key.clone()),
        cosign: cosign.our_cosignature().into(),
    };
    let other_cosign_msgs = sign_peer_messenger.broadcast_and_collect_messages(
        &<KeySignSr25519AllRounds as AllRounds>::BroadcastRound::Cosign,
        cosign_msg
    )?;
    info!("Other parties cosignatures received - msg count: {}", other_cosign_msgs.len());
    for other_cosign_msg in other_cosign_msgs {
        if other_cosign_msg.public_key.0 == public_key {
            continue;
        }

        debug_assert_eq!(musig_public_key, cosign.public_key());
        cosign
            .add_their_cosignature(
                other_cosign_msg.public_key.into(),
                other_cosign_msg.cosign.into()
            )
            .map_err(Error::msg)?;
        debug_assert_eq!(musig_public_key, cosign.public_key());
    }
    info!("Cosign stage passed");

    let signature = cosign.sign().context(anyhow!("Unbalte to git signature from cosignature"))?;

    // Result stage
    let result_msg = ResultMsg {
        musig_public_key: musig_public_key.into(),
        sig: cosign.sign().expect("Signature generated from cosign").into(),
    };

    sign_peer_messenger.broadcast_message(
        &<KeySignSr25519AllRounds as AllRounds>::BroadcastRound::Result,
        result_msg
    )?;

    info!("Cosignature result published successfully");
    Ok(())
}

fn retrieve_keypair(key: &Sr25519) -> Result<Keypair, Error> {
    let secret = key.secret_key
        .clone()
        .context("Can not sign. This user is not the owner of this key")?;
    let mini_secret: MiniSecretKey = secret.try_into().map_err(anyhow::Error::msg)?;
    info!("Retrieved keyshare");

    let public = mini_secret.expand_to_public(ExpansionMode::Ed25519);
    let secret: SecretKey = mini_secret.expand(ExpansionMode::Ed25519);
    Ok(Keypair { public, secret })
}

pub fn handle_new_session_message(app: &App, message: nats::Message) {
    let session = match serde_json::from_slice::<NewSr25519KeySignSession>(&message.data[..]) {
        Ok(session) => session,
        Err(err) => {
            error!("Incorrect key sign message format: {}", err);
            return;
        }
    };

    let nc = app.nc.clone();
    let session = session;
    let session_id = session.session_id.clone();

    match
        thread::Builder
            ::new()
            .name(format!("signing_gen_session_{}", &session_id))
            .spawn(move || sign_session(nc, session))
    {
        Ok(_) => info!("Spawned a thread to handle Sr25519 signature generation"),
        Err(_) => error!("Failed to spawn thread for keysign session {}", &session_id),
    };
}
