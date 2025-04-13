use crate::communication::nats::NatsBaseSession;
use crate::communication::protocol::{ AllRounds, Topic };
use anyhow::Result;
use nats::Subscription;
use std::collections::HashMap;
use strum::IntoEnumIterator;

pub struct RoundSubscription {
    pub subscription: Subscription,
    pub subject: String,
}

pub struct RoundSubscriber {
    subscriptions: HashMap<String, RoundSubscription>,
    connection: nats::Connection,
    topic: Topic,
    node_id: String,
    session_id: String,
    party_index: usize,
}

impl RoundSubscriber {
    pub fn new(topic: Topic, conn: &nats::Connection, session: &NatsBaseSession) -> Self {
        let subscriptions = HashMap::new();

        Self {
            subscriptions,
            topic,
            connection: conn.clone(),
            node_id: session.node_id.clone(),
            session_id: session.session_id.clone(),
            party_index: session.party_index,
        }
    }

    pub fn subscribe<R: AllRounds>(&mut self) -> Result<()> {
        for round in R::BroadcastRound::iter() {
            let round_name = round.to_string();
            let round_sub = self.broadcast_round_subscribe(&round_name)?;
            self.subscriptions.insert(round_name, round_sub);
        }

        for round in R::P2PRound::iter() {
            let round_name = round.to_string();
            let round_sub = self.p2p_round_subscribe(&round_name)?;
            self.subscriptions.insert(round_name, round_sub);
        }

        Ok(())
    }

    pub fn get_subscription(&self, name: &str) -> Result<&RoundSubscription> {
        let sub = self.subscriptions
            .get(name)
            .ok_or_else(|| format!("No subscription found"))
            .map_err(anyhow::Error::msg)?;
        Ok(sub)
    }

    fn broadcast_round_subscribe(&self, round_name: &str) -> Result<RoundSubscription> {
        let subject = self.format_round_subject(round_name);
        let subscription = self.connection.subscribe(&subject)?;
        Ok(RoundSubscription {
            subscription,
            subject,
        })
    }

    fn p2p_round_subscribe(&self, round_name: &str) -> Result<RoundSubscription> {
        let subscribe_name = self.format_round_subject(round_name);
        let subscribe_subject = self.format_round_subject(
            &format!("{}.{}", round_name, &self.party_index)
        );
        let subscription = self.connection.subscribe(&subscribe_subject)?;
        Ok(RoundSubscription {
            subscription,
            subject: subscribe_name,
        })
    }

    pub fn format_round_subject(&self, round_name: &str) -> String {
        return format!(
            "network.gridlock.nodes.{}.{}.{}",
            self.topic.to_string(),
            self.session_id,
            &round_name
        );
    }
}
