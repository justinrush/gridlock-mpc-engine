use crate::communication::nats::{
    BaseMessenger,
    NatsBaseMessenger,
    NatsBaseSession,
    NatsPeerMessenger,
};
use crate::communication::protocol::{ AllRounds, Topic };
use crate::node::NodeIdentity;
use anyhow::{ anyhow, Result };
use tracing::info;

pub struct Nats;
impl Nats {
    pub fn new_session<R: AllRounds>(
        conn: nats::Connection,
        session_id: &str,
        node: &NodeIdentity,
        key_id: &str,
        party_index: usize,
        topic: Topic
    ) -> Result<(NatsPeerMessenger<R>, Vec<usize>)> {
        // We are not attempting more than one keyshare per device
        let thread_index = 0;

        let nats_session = NatsBaseSession {
            session_id: session_id.to_string(),
            thread_index,
            node_id: node.node_id.to_string(),
            public_key: node.networking_public_key.to_string(),
            party_index,
        };

        info!("Joining {} session for key id: {}", &topic.to_string(), &key_id);

        let regen_messenger = NatsBaseMessenger::<R>::new(
            topic,
            conn.clone(),
            nats_session.clone()
        )?;

        let join_response = regen_messenger.wait_for_confirmation(
            std::time::Duration::from_secs(10)
        )?;

        info!("Got join response");

        let party_count = join_response.party_count;
        let mut all_party_indices = join_response.all_party_indices;
        all_party_indices.sort();

        let messenger = NatsPeerMessenger::from(
            regen_messenger,
            party_count,
            all_party_indices.clone()
        ).map_err(|err| anyhow!("Unable to create peer messenger: {}", err))?;

        Ok((messenger, all_party_indices))
    }
}
