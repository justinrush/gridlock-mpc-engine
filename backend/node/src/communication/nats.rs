use crate::communication::ecdsa::{
    collect_message,
    collect_messages_ordered,
    collect_messages_p2p,
    HasSenderId,
};
use crate::communication::protocol::{ AllRounds, Topic };
use crate::communication::round_subscriptions::RoundSubscriber;
use anyhow::{ bail, Result };
use nats::Connection;
use serde::{ de::DeserializeOwned, Deserialize, Serialize };
use shared::key_info::NodeId;
use std::marker::PhantomData;

pub trait PeerMessenger<R> where R: AllRounds {
    fn broadcast_message<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::BroadcastRound,
        message: T
    ) -> Result<()>;
    fn collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::BroadcastRound
    ) -> Result<Vec<T>>;
    fn collect_message<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::BroadcastRound
    ) -> Result<T>;
    fn broadcast_and_collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::BroadcastRound,
        message: T
    ) -> Result<Vec<T>>;
    fn send_p2p_and_collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::P2PRound,
        messages: Vec<T>
    ) -> Result<Vec<T>>;
}

pub trait BaseMessenger<R> where R: AllRounds {
    fn wait_for_confirmation(&self, time: std::time::Duration) -> Result<JoinResponse>;
}

pub struct NatsBaseMessenger<R> {
    pub session: NatsBaseSession,
    nc: Connection,
    subs: RoundSubscriber,
    rounds: PhantomData<*const R>,
}

impl<R> NatsBaseMessenger<R> where R: AllRounds {
    pub fn new(topic: Topic, nc: Connection, session: NatsBaseSession) -> Result<Self> {
        let mut subs = RoundSubscriber::new(topic, &nc, &session);
        subs.subscribe::<R>()?;
        Ok(Self {
            nc,
            subs,
            session,
            rounds: PhantomData,
        })
    }
}

impl<R> BaseMessenger<R> for NatsBaseMessenger<R> where R: AllRounds {
    fn wait_for_confirmation(&self, time: std::time::Duration) -> Result<JoinResponse> {
        let join_subject = self.subs.format_round_subject(&"Join");

        let join_message = serde_json::to_string(
            &JoinMessage::new(
                self.session.session_id.clone(),
                self.session.node_id.clone(),
                self.session.public_key.clone(),
                self.session.thread_index,
                self.session.party_index
            )
        )?;

        let resp = match self.nc.request_timeout(&join_subject, &join_message, time) {
            Ok(resp) => resp,
            Err(_) => bail!("No response from the 'Join' session"),
        };

        let confirmation = serde_json::from_slice::<JoinResponse>(&resp.data)?;
        Ok(confirmation)
    }
}

pub struct NatsPeerMessenger<R> {
    nc: Connection,
    subs: RoundSubscriber,
    session: NatsPeerSession,
    rounds: PhantomData<*const R>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BroadcastMessage<T> {
    pub sender_id: usize,
    pub message: T,
}

impl<T> HasSenderId for BroadcastMessage<T> {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}

#[derive(Clone)]
pub struct NatsBaseSession {
    pub session_id: String,
    pub thread_index: usize,
    pub node_id: String,
    pub public_key: String,
    pub party_index: usize,
}

#[derive(Clone)]
pub struct NatsPeerSession {
    pub session_id: String,
    pub thread_index: usize,
    pub node_id: String,
    pub party_index: usize,
    pub party_count: usize,
    pub all_party_indices: Vec<usize>,
    pub other_party_indices: Vec<usize>,
}

impl<R> NatsPeerMessenger<R> where R: AllRounds {
    pub fn from(
        base_messenger: NatsBaseMessenger<R>,
        party_count: usize,
        party_indices: Vec<usize>
    ) -> Result<Self> {
        let party_index = base_messenger.session.party_index;
        let mut other_party_indices = party_indices.clone();
        other_party_indices.retain(|x| *x != party_index);

        let peer_session = NatsPeerSession {
            session_id: base_messenger.session.session_id,
            thread_index: base_messenger.session.thread_index,
            node_id: base_messenger.session.node_id,
            party_index,
            party_count,
            all_party_indices: party_indices,
            other_party_indices,
        };

        Ok(Self {
            nc: base_messenger.nc,
            subs: base_messenger.subs,
            session: peer_session,
            rounds: PhantomData,
        })
    }
}

impl<R> PeerMessenger<R> for NatsPeerMessenger<R> where R: AllRounds {
    fn broadcast_message<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::BroadcastRound,
        message: T
    ) -> Result<()> {
        let round_subscription = self.subs.get_subscription(&round.to_string())?;
        let broadcast_message = BroadcastMessage::<T> {
            sender_id: self.session.party_index,
            message,
        };
        let _ = &self.nc.publish(
            &round_subscription.subject,
            serde_json::to_string(&broadcast_message)?
        )?;
        Ok(())
    }

    fn collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::BroadcastRound
    ) -> Result<Vec<T>> {
        let round_subscription = self.subs.get_subscription(&round.to_string())?;
        let mut messages = Vec::new();
        let recieved_broadcasts = collect_messages_ordered::<BroadcastMessage<T>>(
            &round_subscription.subscription,
            self.session.party_count
        )?;

        for broadcast in recieved_broadcasts {
            let recieved_message = broadcast.message;
            messages.push(recieved_message);
        }
        Ok(messages)
    }

    fn collect_message<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::BroadcastRound
    ) -> Result<T> {
        let round_subscription = self.subs.get_subscription(&round.to_string())?;
        let msg = collect_message::<BroadcastMessage<T>>(&round_subscription.subscription)?;
        Ok(msg.message)
    }

    fn broadcast_and_collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::BroadcastRound,
        message: T
    ) -> Result<Vec<T>> {
        self.broadcast_message(round, message)?;
        self.collect_messages(round)
    }

    fn send_p2p_and_collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        round: &R::P2PRound,
        messages: Vec<T>
    ) -> Result<Vec<T>> {
        let round_subscription = self.subs.get_subscription(&round.to_string())?;

        let mut return_messages = Vec::new();

        let msg_count = messages.len();
        let mut outgoing_messages = messages.iter();
        for party_index in &self.session.other_party_indices {
            let broadcast_message = BroadcastMessage::<T> {
                sender_id: self.session.party_index,
                message: outgoing_messages
                    .next()
                    .ok_or_else(|| {
                        format!(
                            "Incorrect number of outgoing messages, expected {}, but found {}",
                            &self.session.other_party_indices.len(),
                            msg_count
                        )
                    })
                    .map_err(anyhow::Error::msg)?
                    .clone(),
            };
            //TODO: move this to round subscription code
            let mut round_subject = round_subscription.subject.to_owned();
            round_subject.push_str(&format!(".{}", party_index));
            let _ = &self.nc.publish(&round_subject, serde_json::to_string(&broadcast_message)?)?;
        }

        let recieved_broadcasts = collect_messages_p2p::<BroadcastMessage<T>>(
            &round_subscription.subscription,
            self.session.party_count,
            self.session.party_index
        )?;

        for broadcast in recieved_broadcasts {
            let recieved_message = broadcast.message;
            return_messages.push(recieved_message);
        }
        Ok(return_messages)
    }
}

pub struct DummyMessenger<R> {
    rounds: PhantomData<*const R>,
}

impl<R> DummyMessenger<R> where R: AllRounds {
    pub fn new(_: Topic) -> Result<Self> {
        Ok(Self {
            rounds: PhantomData,
        })
    }
}

impl<R> PeerMessenger<R> for DummyMessenger<R> where R: AllRounds {
    fn broadcast_message<T: Serialize + DeserializeOwned + Clone>(
        &self,
        _: &<R as AllRounds>::BroadcastRound,
        _: T
    ) -> Result<()> {
        unimplemented!()
    }

    fn collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        _: &<R as AllRounds>::BroadcastRound
    ) -> Result<Vec<T>> {
        unimplemented!()
    }

    fn collect_message<T: Serialize + DeserializeOwned + Clone>(
        &self,
        _: &<R as AllRounds>::BroadcastRound
    ) -> Result<T> {
        unimplemented!()
    }

    fn broadcast_and_collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        _: &<R as AllRounds>::BroadcastRound,
        _: T
    ) -> Result<Vec<T>> {
        unimplemented!()
    }

    fn send_p2p_and_collect_messages<T: Serialize + DeserializeOwned + Clone>(
        &self,
        _: &<R as AllRounds>::P2PRound,
        _: Vec<T>
    ) -> Result<Vec<T>> {
        unimplemented!()
    }
}

#[derive(Serialize, Deserialize)]
pub struct JoinMessage {
    pub session_id: String,
    pub node_id: NodeId,
    pub party_index: usize,
    pub networking_public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct JoinResponse {
    pub party_count: usize,
    pub all_party_indices: Vec<usize>,
}

impl JoinMessage {
    pub fn new(
        session_id: String,
        mut node_id: String,
        networking_public_key: String,
        index: usize,
        party_index: usize
    ) -> Self {
        if index > 0 {
            node_id.push_str(&format!("--{}", &index.to_string()));
        }

        JoinMessage {
            session_id,
            node_id: NodeId::new(node_id),
            party_index,
            networking_public_key,
        }
    }
}
