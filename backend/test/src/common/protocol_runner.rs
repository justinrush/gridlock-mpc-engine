use super::config::*;
use anyhow::{ anyhow, bail, Context, Result };
use derive_more::Deref;
use libsecp256k1::Message;
use log::{ error, info };
use nats::asynk::Connection;
use schnorrkel::signing_context;
use serde::{ Deserialize, Serialize };
use sha3::{ Digest, Sha3_256 };
use std::fmt::Debug;
use thiserror::Error;
use uuid::Uuid;

pub struct ProtocolRunner {
    config: Config,
}

impl ProtocolRunner {
    pub fn new(config: Config) -> Self {
        ProtocolRunner { config }
    }

    pub async fn customisable(&self, nc: &Connection, node_id: usize, msg: String) -> Result<()> {
        let node_id = self.config.nodes.get_node_by_index(node_id)?.node_id;
        let message_new = format!("network.gridlock.nodes.Message.new.{node_id}");

        let resp = nc.request(&message_new, msg.into_bytes()).await?;
        println!("Received message is:\n{}", String::from_utf8(resp.data)?);
        Ok(())
    }

    pub async fn twofa_import(
        &mut self,
        nc: &Connection,
        key_id: &str,
        two_factor_code: &str,
        threshold: usize,
        share_count: usize,
        _party_nodes: &NodeIndices,
        owner_node: usize
    ) -> Result<()> {
        let node_id = self.config.nodes.get_node_by_index(owner_node).unwrap().node_id;
        let message_new_key = format!("network.gridlock.nodes.Message.new.{node_id}");
        let msg = format!(
            "{{\"key_id\":\"{key_id}\",\"key_type\":\"2fa\",\"key\":\"{two_factor_code}\",\"threshold\":{threshold},\"share_count\":{share_count}}}"
        );

        let resp = nc.request(&message_new_key, &msg).await?;

        // Now we need to deliver the keys to other nodes
        let shares: Vec<KeyImportShareCommand> = serde_json::from_slice(&resp.data)?;
        for (i, share) in shares.iter().enumerate() {
            let msg_share = serde_json::to_string(&share)?;
            let node_id = self.config.nodes.get_node_by_index(i + 1).unwrap().node_id;
            let message_new = format!("network.gridlock.nodes.Message.new.{node_id}");
            nc.request(&message_new, &msg_share).await?;
        }

        //add into db
        let key_info = KeyInfo {
            public_key: "NA".to_string(),
            key_type: KeyType::TwoFA,
            node_to_share_indices: vec![(1, 0), (2, 1), (3, 2), (4, 3), (5, 4)],
        };

        self.config.keys.update(key_id, key_info)?;

        println!("Key id {}", &key_id);

        Ok(())
    }

    pub async fn sr25519_wallet_gen(
        &mut self,
        nc: &Connection,
        key_id: &str,
        threshold: usize,
        share_count: usize,
        _party_nodes: &NodeIndices,
        owner_node: usize
    ) -> Result<()> {
        println!("Starting wallet generation");
        println!("Sr25519 signature owner node id: {owner_node}");
        let node_id = self.config.nodes.get_node_by_index(owner_node).unwrap().node_id;
        println!("Node identity retrieved - node_id: {node_id}");

        let message_new_key = format!("network.gridlock.nodes.Message.new.{node_id}");
        let msg = format!(
            "{{\"key_id\":\"{key_id}\",\"key_type\":\"sr25519\",\"threshold\":{threshold},\"share_count\":{share_count}}}"
        );

        let resp = nc.request(&message_new_key, &msg).await?;

        // Now we need to deliver the keys to other nodes
        let resp: KeyGenResponse = serde_json::from_slice(&resp.data)?;
        for (i, share) in resp.import_cmd.iter().enumerate() {
            let msg_share = serde_json::to_string(&share)?;
            let node_id = self.config.nodes.get_node_by_index(i + 1).unwrap().node_id;
            let message_new = format!("network.gridlock.nodes.Message.new.{node_id}");
            nc.request(&message_new, &msg_share).await?;
        }

        let key_info = KeyInfo {
            public_key: resp.pk.clone(),
            key_type: KeyType::Sr25519,
            node_to_share_indices: vec![(1, 0), (2, 1), (3, 2), (4, 3), (5, 4)],
        };
        self.config.keys.update(key_id, key_info)?;
        println!("Wallet generated - public key: {0}", resp.pk);
        Ok(())
    }

    pub async fn sr25519_wallet_sign_and_verify(
        &mut self,
        nc: &Connection,
        key_id: &str,
        owner_node: usize,
        msg_to_sign: String
    ) -> Result<()> {
        println!("Starting sr25519 signing and verification");
        println!("Sr25519 signature owner node id: {owner_node}");
        println!("Message to sign - '{msg_to_sign}'");

        let node_id = self.config.nodes.get_node_by_index(owner_node).unwrap().node_id;
        println!("Node identity retrieved - node_id: {node_id}");

        let message_new_key = format!("network.gridlock.nodes.Message.new.{node_id}");
        let msg_to_sign_json = serde_json::to_string(msg_to_sign.as_bytes())?;
        let msg = format!(
            "{{\"key_id\":\"{key_id}\",\"key_type\":\"sr25519\",\"message\":{msg_to_sign_json}}}"
        );

        println!();
        println!("Starting signing");
        let resp = nc.request(&message_new_key, &msg).await?;
        let str_signature = serde_json::from_slice::<String>(&resp.data)?;
        println!("Sr25519 signature created - hex: '{str_signature}'");
        let raw_signature = hex::decode(str_signature)?;
        let signature = schnorrkel::sign::Signature
            ::from_bytes(&raw_signature)
            .map_err(anyhow::Error::msg)?;

        println!();
        println!("Starting verification");
        let pk_hex = self.config.keys.get_public_key(key_id)?;
        println!("Publick key - hex '{pk_hex}'");
        let pk = hex::decode(pk_hex)?;
        let pk = schnorrkel::PublicKey::from_bytes(&pk).map_err(anyhow::Error::msg)?;

        const CTX: &'static [u8] = b"substrate";
        let ctx = signing_context(CTX);
        pk
            .verify(ctx.bytes(msg_to_sign.as_bytes()), &signature)
            .map_err(anyhow::Error::msg)
            .context("Sr25519 signature verification failed")?;
        let hex_signature = hex::encode(signature.to_bytes());
        println!("Sr25519 signature is verified - hex: '{hex_signature}' ");
        Ok(())
    }

    pub async fn sr25519_wallet_multi_sign_and_verify(
        &mut self,
        nc: &Connection,
        key_id: &str,
        party_key_ids: PartyKeys,
        party_nodes: &NodeIndices,
        owner_node: usize,
        msg_to_sign: String
    ) -> Result<()> {
        println!("Starting sr25519 multi signing and verification");

        let session_id = key_id;
        let signers = party_nodes.0
            .iter()
            .map(|x| self.config.nodes.get_node_by_index(*x))
            .collect::<Result<Vec<NodeIdentity>>>()?;
        let parties = signers.len();

        let t = signing_context(b"gridlock").bytes(msg_to_sign.as_bytes());

        let result_key = format!("network.gridlock.nodes.KeySignEdDSA.{}.Result", &session_id);
        let result_sub = nc.subscribe(&result_key).await?;
        let result_timeout = 3;

        for (party_key_id, node) in party_key_ids.iter().zip(signers.iter()) {
            let sign_new_key = format!(
                "network.gridlock.nodes.KeySignSr25519.new.{}",
                node.node_id
            );
            let key_sign_new_data = serde_json
                ::to_string(
                    &(NewSr25519KeySignSession {
                        key_id: party_key_id.to_owned(),
                        session_id: session_id.to_owned(),
                        message: msg_to_sign.as_bytes().to_owned(),
                        party_index: node.index,
                    })
                )
                .unwrap();
            nc.publish(&sign_new_key, key_sign_new_data).await?;
        }

        let mut res_vec = Vec::new();
        tokio::time
            ::timeout(std::time::Duration::from_secs(result_timeout), async {
                for _ in 0..parties {
                    // accept a new party
                    let res = result_sub.next().await.unwrap();
                    res_vec.push(res);
                }
            }).await
            .with_context(|| timeout_mes(result_key, result_timeout))
            .with_context(|| anyhow!("Results so far: {:?}", res_vec))?;

        let result_msgs = res_vec
            .iter()
            .map(|mes| serde_json::from_slice::<ResultMsg>(&mes.data).map_err(anyhow::Error::msg))
            .collect::<Result<Vec<_>>>()
            .expect("ResultMsg received");

        let pk: schnorrkel::PublicKey = result_msgs[0].musig_public_key.clone().into();
        let sig: schnorrkel::Signature = result_msgs[0].sig.clone().into();

        for result_msg in result_msgs {
            assert_eq!(pk, result_msg.musig_public_key.into());
        }

        assert!(pk.verify(t, &sig).is_ok());
        Ok(())
    }

    pub async fn ecdsa_wallet_gen(
        &mut self,
        nc: &Connection,
        party_nodes: &NodeIndices,
        key_id: &str
    ) -> Result<()> {
        let party_count = party_nodes.0.len();
        if party_count < 3 {
            bail!("Not enough nodes in party");
        }

        let join_key = format!("network.gridlock.nodes.keyGen.session.{}.join", &key_id);
        let join_sub = nc.subscribe(&join_key).await?;
        let join_timeout = 5;

        let result_key = format!("network.gridlock.nodes.keyGen.session.{}.result", &key_id);
        let result_sub = nc.subscribe(&result_key).await?;
        let result_timeout = 5;

        //let result_sub = nc.subscribe(format!("network.gridlock.nodes.keyGen.session.{}", &key_id)).unwrap();
        let gen_new_data_key = format!("{{\"key_id\":\"{key_id}\",\"extra_shares\":[]}}");

        let mut node_ids = Vec::new();
        for node_index in party_nodes.0.iter() {
            let node_id = self.config.nodes.get_node_by_index(*node_index)?.node_id;
            node_ids.push(node_id.clone());
            let gen_new_key = format!("network.gridlock.nodes.keyGen.new.{node_id}");
            nc.publish(&gen_new_key, &gen_new_data_key).await?;
        }

        let mut node_share_index = Vec::new();
        tokio::time
            ::timeout(std::time::Duration::from_secs(join_timeout), async {
                // for each party we want
                for i in 0..party_count {
                    // accept a new party
                    let next = join_sub.next().await.unwrap();
                    let node_id = serde_json
                        ::from_slice::<WalletJoinMessage>(&next.data)
                        .unwrap().node_id;
                    if let Some(node_index_pos) = node_ids.iter().position(|x| x == &node_id) {
                        node_share_index.push((*party_nodes.0.get(node_index_pos).unwrap(), i + 1));
                    } else {
                        println!("Something wrong!");
                    }
                    // respond to that party with the keygen params
                    next.respond(
                        &serde_json
                            ::to_string(
                                &(KeyGenParams {
                                    num_parties: party_count as u8,
                                    party_num: i as u8,
                                })
                            )
                            .unwrap()
                    ).await.unwrap();
                    nc.flush().await.unwrap();
                }
            }).await
            .with_context(|| timeout_mes(join_key, join_timeout))?;

        nc.publish(
            &format!("network.gridlock.nodes.keyGen.session.{key_id}.start"),
            &serde_json::to_string(&party_count).unwrap()
        ).await?;

        let mut res_vec = Vec::new();

        tokio::time
            ::timeout(std::time::Duration::from_secs(result_timeout), async {
                for _ in 0..party_count {
                    // accept a new party
                    let res = result_sub.next().await.unwrap();
                    res_vec.push(res);
                }
            }).await
            .with_context(|| timeout_mes(result_key, result_timeout))?;

        let pk = serde_json::from_slice::<ECDSAKeyGenResult>(&res_vec[0].data)?.y_sum;

        let pk = format!("{:0>64}", pk.x) + &*format!("{:0>64}", pk.y);

        let key_info = KeyInfo {
            public_key: pk,
            key_type: KeyType::ECDSA,
            node_to_share_indices: node_share_index.clone(),
        };

        self.config.keys.update(key_id, key_info)?;

        Ok(())
    }

    pub async fn ecdsa_wallet_sign_and_verify(
        &self,
        nc: &Connection,
        party_nodes: &NodeIndices,
        key_id: &str,
        session_id: &str,
        msg_to_sign: String
    ) -> Result<()> {
        let party_count = party_nodes.0.len();
        if party_count != 3 {
            bail!("Not enough nodes in party");
        }

        // TODO: remove .session. after moving orchestration to backend side
        let join_key = format!("network.gridlock.nodes.keySign.session.{session_id}.join");
        let join_sub = nc.subscribe(&join_key).await?;
        let join_timeout = 5;

        let result_key = format!("network.gridlock.nodes.keySign.session.{}.result", &session_id);
        let result_sub = nc.subscribe(&result_key).await?;
        let result_timeout = 5;

        let sign_new_data_key = format!(
            "{{\"session_id\":\"{session_id}\",\"key_id\":\"{key_id}\"}}"
        );
        for node_index in party_nodes.0.iter() {
            let node_id = self.config.nodes.get_node_by_index(*node_index)?.node_id;
            let gen_new_key = format!("network.gridlock.nodes.keySign.new.{node_id}");
            nc.publish(&gen_new_key, &sign_new_data_key).await?;
        }

        let mut hasher = Sha3_256::new();
        hasher.update(&msg_to_sign);
        let hashed_msg = hasher.finalize();

        tokio::time
            ::timeout(std::time::Duration::from_secs(join_timeout), async {
                // for each party we want
                for i in 0..party_count {
                    // accept a new party
                    let next = join_sub.next().await.unwrap();

                    // respond to that party with the keygen params
                    next.respond(
                        &serde_json
                            ::to_string(
                                &(JoinSignSessionResponse {
                                    id_in_session: i,
                                    message: hashed_msg.to_vec().clone(),
                                })
                            )
                            .unwrap()
                    ).await.unwrap();
                    nc.flush().await.unwrap();
                }
            }).await
            .with_context(|| timeout_mes(join_key, join_timeout))?;

        nc.publish(
            &format!("network.gridlock.nodes.keySign.session.{session_id}.start"),
            &serde_json::to_string(&party_count).unwrap()
        ).await?;

        let mut res_vec = Vec::new();

        tokio::time
            ::timeout(std::time::Duration::from_secs(result_timeout), async {
                for _ in 0..party_count {
                    let res = result_sub.next().await.unwrap();
                    res_vec.push(res);
                }
            }).await
            .with_context(|| timeout_mes(result_key, result_timeout))?;

        let pk = self.config.keys.get_public_key(key_id)?;

        let sig = serde_json::from_slice::<SigningResult>(&res_vec[0].data)?;

        verify_ecdsa_sig(&pk, &hashed_msg, sig)?;

        Ok(())
    }

    pub async fn eddsa_wallet_gen(
        &mut self,
        nc: &Connection,
        party_nodes: &NodeIndices,
        key_id: &str
    ) -> Result<String> {
        let party_count = party_nodes.0.len();
        if party_count < 3 {
            bail!("Not enough nodes in party");
        }

        let join_key = format!("network.gridlock.nodes.KeyGenEdDSA.{}.Join", &key_id);
        let join_sub = nc.subscribe(&join_key).await?;
        let join_timeout = 5;

        let result_key = format!("network.gridlock.nodes.KeyGenEdDSA.{}.Result", &key_id);
        let result_sub = nc.subscribe(&result_key).await?;
        let result_timeout = 3;

        for index in &party_nodes.0 {
            let node_id = self.config.nodes.get_node_by_index(*index)?.node_id;
            let key_gen_new = format!("network.gridlock.nodes.KeyGenEdDSA.new.{node_id}");
            let key_gen_new_data = serde_json
                ::to_string(
                    &(NewEdDSAKeyGenSession {
                        key_id: key_id.to_owned(),
                        threshold: 2,
                        share_indices: vec![*index],
                    })
                )
                .unwrap();
            nc.publish(&key_gen_new, &key_gen_new_data).await?;
        }

        let mut msg_vec = Vec::new();

        tokio::time
            ::timeout(std::time::Duration::from_secs(join_timeout), async {
                // for each party we want
                for _i in 0..party_count {
                    // accept a new party
                    info!("Someone joined");
                    let next = join_sub.next().await.unwrap();
                    msg_vec.push(next);
                }
            }).await
            .with_context(|| timeout_mes(join_key, join_timeout))?;

        if msg_vec.len() >= 3 {
            let mut indices = Vec::new();
            for m in msg_vec.iter() {
                let confirmation = serde_json::from_slice::<JoinMessage>(&m.data)?;
                indices.push(confirmation.party_index);
            }
            indices.sort();
            info!("indices: {:?}", &indices);
            let join_resp = JoinResponse {
                party_count: indices.len(),
                all_party_indices: indices,
            };
            for (_, m) in msg_vec.iter().enumerate() {
                match m.respond(&serde_json::to_string(&join_resp).unwrap()).await {
                    Ok(_) => {}
                    Err(err) => {
                        error!("Error: {}", err);
                    }
                }
            }
            nc.flush().await?;
        }

        let mut res_vec = Vec::new();

        tokio::time
            ::timeout(std::time::Duration::from_secs(result_timeout), async {
                for _ in 0..party_count {
                    // accept a new party
                    let res = result_sub.next().await.unwrap();
                    res_vec.push(res);
                }
            }).await
            .with_context(|| timeout_mes(result_key, result_timeout))?;

        let pk = serde_json::from_slice::<NatsMessage>(&res_vec[0].data)?.message.y_sum;

        let key_info = KeyInfo {
            public_key: pk.to_string(),
            key_type: KeyType::EdDSA,
            node_to_share_indices: vec![(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)],
        };

        self.config.keys.update(key_id, key_info)?;

        Ok(pk)
    }

    pub async fn eddsa_wallet_sign_and_verify(
        &self,
        nc: &Connection,
        party_nodes: &NodeIndices,
        key_id: &str,
        session_id: &str,
        msg_to_sign: String
    ) -> Result<()> {
        let signers = party_nodes.0
            .iter()
            .map(|x| self.config.nodes.get_node_by_index(*x))
            .collect::<Result<Vec<NodeIdentity>>>()?;

        let parties = signers.len();

        let join_key = format!("network.gridlock.nodes.EphemeralKeyGenEdDSA.{}.Join", &session_id);
        let join_sub = nc.subscribe(&join_key).await?;
        let join_timeout = 5;

        let result_key = format!("network.gridlock.nodes.KeySignEdDSA.{}.Result", &session_id);
        let result_sub = nc.subscribe(&result_key).await?;
        let result_timeout = 3;

        let msg_to_sign = msg_to_sign.into_bytes();
        for node in signers.iter() {
            let sign_new_key = format!("network.gridlock.nodes.KeySignEdDSA.new.{}", node.node_id);
            let key_sign_new_data = serde_json
                ::to_string(
                    &(NewEdDSAKeySignSession {
                        key_id: key_id.to_owned(),
                        session_id: session_id.to_owned(),
                        message: msg_to_sign.clone(),
                    })
                )
                .unwrap();
            nc.publish(&sign_new_key, key_sign_new_data).await?;
        }

        let mut msg_vec = Vec::new();

        tokio::time
            ::timeout(std::time::Duration::from_secs(join_timeout), async {
                // for each party we want
                for _i in 0..parties {
                    // accept a new party
                    let next = join_sub.next().await.unwrap();
                    // println!("somebody joined");
                    msg_vec.push(next);
                }
            }).await
            .with_context(|| timeout_mes(join_key, join_timeout))?;

        if msg_vec.len() == parties {
            let mut indices = Vec::new();
            for m in msg_vec.iter() {
                let confirmation = serde_json::from_slice::<JoinMessage>(&m.data)?;
                indices.push(confirmation.party_index);
            }
            indices.sort();
            // println!("indices: {:?}", &indices);
            let join_resp = JoinResponse {
                party_count: indices.len(),
                all_party_indices: indices,
            };
            // println!("responding as sufficient parties have joined");
            for (_, m) in msg_vec.iter().enumerate() {
                match m.respond(&serde_json::to_string(&join_resp).unwrap()).await {
                    Ok(_) => {}
                    Err(err) => {
                        println!("Error: {err}");
                    }
                }
            }
            nc.flush().await?;
        }

        let mut res_vec = Vec::new();

        tokio::time
            ::timeout(std::time::Duration::from_secs(result_timeout), async {
                for _ in 0..parties {
                    // accept a new party
                    let res = result_sub.next().await.unwrap();
                    res_vec.push(res);
                }
            }).await
            .with_context(|| timeout_mes(result_key, result_timeout))
            .with_context(|| anyhow!("Results so far: {:?}", res_vec))?;

        let res = serde_json::from_slice::<NatsSigMessage>(&res_vec[0].data)?;

        let pk = self.config.keys.get_public_key(key_id)?;

        verify_eddsa_sig(&pk, &msg_to_sign, res.message)?;

        Ok(())
    }

    pub async fn recovery(
        &self,
        nc: &Connection,
        key_id: &str,
        session_id: &str,
        target_node_index: usize,
        threshold: usize,
        helper_nodes: NodeIndices,
        key_type: KeyType
    ) -> Result<()> {
        // now we need to reorder public keys to be in order of the share index they hold
        let mut rearranged_keys = Vec::new();
        for node in self.config.nodes.nodes.iter() {
            if
                let Ok(share_index) = self.config.keys.get_share_index_by_node_index(
                    key_id,
                    node.index
                )
            {
                rearranged_keys.push((share_index, node.public_key.clone()));
            }
        }
        println!("Rearranged pks: {rearranged_keys:?}");

        let recovery_index = self.config.keys.get_share_index_by_node_index(
            key_id,
            target_node_index
        )?;
        let target_node_id = self.config.nodes.get_node_by_index(target_node_index)?.node_id;

        let helper_message = NewKeyShareRegenSession {
            key_id: key_id.to_string(),
            session_id: session_id.to_string(),
            key_type: key_type.clone(),
            threshold,
            recovery_index,
            public_keys: PublicKeysEnum::Map(rearranged_keys.clone()),
            role: RecoveryRole::Helper,
        };

        let party_count = helper_nodes.0.len();

        let join_key = format!("network.gridlock.nodes.KeyShareRecovery.{}.Join", &session_id);
        let join_sub = nc.subscribe(&join_key).await?;
        let join_timeout = 8;

        let package_key = format!(
            "network.gridlock.nodes.KeyShareRecovery.{}.DeliverRecoveryPackage",
            &session_id
        );
        let package_sub = nc.subscribe(&package_key).await?;
        let package_timeout = 5;

        let recovery_new_helper_message = serde_json::to_string(&helper_message).unwrap();

        for &node_index in helper_nodes.0.iter() {
            let node_id = self.config.nodes.get_node_by_index(node_index)?.node_id;
            let recovery_new_key = format!("network.gridlock.nodes.KeyShareRecovery.new.{node_id}");
            nc.publish(&recovery_new_key, &recovery_new_helper_message).await?;
        }

        let mut msg_vec = Vec::new();

        tokio::time
            ::timeout(std::time::Duration::from_secs(join_timeout), async {
                // for each party we want
                for _ in 0..party_count {
                    // accept a new party
                    let next = join_sub.next().await.unwrap();
                    // println!("somebody joined");
                    msg_vec.push(next);
                }
            }).await
            .with_context(|| timeout_mes(join_key, join_timeout))?;

        println!("party_count: {party_count}");

        if msg_vec.len() >= party_count {
            let mut indices = Vec::new();
            let mut target_present = false;
            for m in msg_vec.iter() {
                let confirmation = serde_json::from_slice::<JoinMessage>(&m.data)?;
                if confirmation.party_index == recovery_index {
                    target_present = true;
                } else {
                    indices.push(confirmation.party_index);
                }
            }

            // should check whether target is present here
            //also check no indices have joined twice
            indices.sort();
            let join_resp = JoinResponse {
                party_count: indices.len(),
                all_party_indices: indices.clone(),
            };
            // println!("responding as sufficient parties have joined");
            for m in &msg_vec {
                match m.respond(&serde_json::to_string(&join_resp).unwrap()).await {
                    Ok(_) => {}
                    Err(err) => {
                        println!("Error: {err}");
                    }
                }
            }
            nc.flush().await?;

            // Here we must gather regeneration packages
            let mut resp_vec = Vec::new();

            tokio::time
                ::timeout(std::time::Duration::from_secs(package_timeout), async {
                    for _ in 0..party_count {
                        let m = package_sub.next().await.unwrap();
                        let resp = serde_json::from_slice::<NatsPackageMessage>(&m.data).unwrap();

                        resp_vec.push(resp);
                    }
                }).await
                .with_context(|| timeout_mes(package_key, package_timeout))?;

            resp_vec.sort_by_key(|x| x.sender_id);
            let package_vec: Vec<EncryptedData> = resp_vec
                .iter()
                .map(|x| x.message.clone())
                .collect();

            //  and deliver them

            let data = RecoveryPackageInfo {
                key_id: key_id.to_string(),
                recovery_index,
                threshold,
                peers: indices.clone(),
                public_keys: PublicKeysEnum::Map(rearranged_keys.clone()),
                encrypted_packages: package_vec.clone(),
            };

            let message = RecieveRecoveryPackages {
                recovery_info: data,
                key_type: key_type.clone(),
            };
            let msg = serde_json::to_string(&message)?;
            let message_new_key = format!("network.gridlock.nodes.Message.new.{target_node_id}");
            let res = nc.request(&message_new_key, msg).await?;
            match key_type {
                KeyType::EdDSA | KeyType::Sr25519 | KeyType::TwoFA => {
                    let validation_msg = serde_json::from_slice::<EdDSARecoveryValidationResult>(
                        &res.data
                    )?;
                    match validation_msg {
                        EdDSARecoveryValidationResult::Validated => {
                            println!("{key_type} recovery validated");
                        }
                        EdDSARecoveryValidationResult::ValidationError(err) => {
                            bail!(err);
                        }
                    }
                }
                KeyType::ECDSA => {
                    let validation_msg = serde_json::from_slice::<ECDSARecoveryValidationResult>(
                        &res.data
                    )?;
                    if let ECDSARecoveryValidationResult::Validated(eks) = validation_msg {
                        println!("ECDSA recovery validated");
                        let update = UpdatePaillierKeysCommand {
                            key_id: key_id.to_string(),
                            new_eks: vec![eks.clone()],
                        };

                        // node id's of nodes not invloved
                        let indices_to_update = [1usize, 2usize, 3usize, 4usize, 5usize]
                            .into_iter()
                            .filter(|x| *x != target_node_index)
                            .collect::<Vec<usize>>();
                        println!("indices to update {:?}", &indices_to_update);
                        let node_ids_to_update: Vec<String> = indices_to_update
                            .iter()
                            .map(|x| self.config.nodes.get_node_by_index(*x).unwrap().node_id)
                            .collect();
                        println!("Node ids to update: {node_ids_to_update:?}");

                        for node_id in node_ids_to_update.iter() {
                            let message_new_key = format!(
                                "network.gridlock.nodes.Message.new.{node_id}"
                            );
                            let msg = serde_json::to_string(&update)?;
                            nc.publish(&message_new_key, msg).await?;
                        }
                    }
                }
                _ => panic!("Unsupported KeyType!"),
            }

            Ok(())
        } else {
            Err(anyhow!("Didn't work"))
        }
    }
}

fn timeout_mes(sub_key: String, timeout: u64) -> String {
    format!(
        "Failed subscription response by timeout!\n  subscription: {sub_key},\n  timeout: {timeout}"
    )
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NewKeyShareRegenSession {
    pub key_id: String,
    pub session_id: String,
    pub key_type: KeyType,
    pub recovery_index: usize,
    pub threshold: usize,
    pub public_keys: PublicKeysEnum,
    pub role: RecoveryRole,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum PublicKeysEnum {
    Vec(Vec<String>),
    Map(Vec<(usize, String)>),
}

#[derive(Clone, Serialize, Deserialize)]
pub enum RecoveryRole {
    Helper,
    Target,
}

fn verify_ecdsa_sig(pk: &str, message: &[u8], sig: SigningResult) -> Result<()> {
    use libsecp256k1::{ verify, PublicKey, Signature };

    let pk_bytes = hex::decode(pk.as_bytes())?;
    let pk = PublicKey::parse_slice(&pk_bytes, None)?;

    let mut s = hex::decode(sig.r)?;

    let sigma = &hex::decode(sig.s)?;

    s.extend_from_slice(sigma);

    let msg = Message::parse_slice(message)?;

    let signature: Signature = Signature::parse_overflowing_slice(&s)?;

    if !verify(&msg, &signature, &pk) {
        bail!("Signature not verified");
    }

    println!("Signature verified");
    Ok(())
}

fn verify_eddsa_sig(pk: &str, message: &[u8], sig: SignatureResult) -> Result<()> {
    use ed25519_dalek::{ PublicKey, Signature, Verifier };

    let pub_key = PublicKey::from_bytes(&hex::decode(pk)?).unwrap();

    let mut s = hex::decode(sig.R).unwrap();

    let sigma = &hex::decode(sig.sigma).unwrap();

    s.extend_from_slice(sigma);

    let signature: Signature = Signature::try_from(&*s)?;

    pub_key.verify(message, &signature)?;
    println!("Signature verified");
    Ok(())
}

async fn publish_to_forbidden_subjects(nc: &Connection) -> Result<()> {
    println!("Attempting to publish to keygen new");
    let key_id = "6c2a2b82-b0e9-45e2-b7b4-80c5db73de97";
    //local node
    let node_id = "79509c20-dac1-4288-a480-b3db333d367f";

    let key_gen_new = format!("network.gridlock.nodes.keyGen.new.{node_id}");
    let key_gen_new_data = format!("{{\"key_id\":\"{key_id}\",\"extra_shares\":[]}}");

    nc.publish(&key_gen_new, &key_gen_new_data).await?;

    println!("Attempting to publish to keygen start");
    Ok(())
}

pub fn new_uuid() -> Uuid {
    Uuid::new_v4()
}

#[derive(Error, Debug)]
pub enum ParseKeyTypeError {
    #[error("Invalid keytype (expected `ed` or `ec` or `twofa`, got {found:?})")] InvalidString {
        found: String,
    },
}

#[derive(Default)]
pub struct NodeIndices(Vec<usize>);

impl NodeIndices {
    pub fn new(vec: Vec<usize>) -> Self {
        NodeIndices(vec)
    }
}

impl FromIterator<usize> for NodeIndices {
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        NodeIndices(iter.into_iter().collect())
    }
}

impl<const T: usize> From<[usize; T]> for NodeIndices {
    fn from(value: [usize; T]) -> Self {
        NodeIndices(value.into_iter().collect())
    }
}

#[derive(Default, Deref)]
pub struct PartyKeys(Vec<String>);

impl PartyKeys {
    pub fn new(vec: Vec<String>) -> Self {
        PartyKeys(vec)
    }
}

#[derive(Error, Debug)]
pub enum ParseProtocolError {
    #[error(
        "Invalid protocol (expected `wa` (wallet generation), `si`(signature) or `re` (key regeneration), got {found:?})"
    )] InvalidString {
        found: String,
    },
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyGenParams {
    pub num_parties: u8,
    pub party_num: u8,
}

#[derive(Deserialize)]
pub struct WalletJoinMessage {
    pub session_id: String,
    pub node_id: String,
}

#[derive(Deserialize)]
pub struct JoinMessage {
    pub session_id: String,
    pub node_id: String,
    pub party_index: usize,
}

#[derive(Serialize)]
pub struct JoinResponse {
    pub party_count: usize,
    pub all_party_indices: Vec<usize>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewEdDSAKeySignSession {
    pub key_id: String,
    pub session_id: String,
    pub message: Vec<u8>,
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub enum EdDSARecoveryValidationResult {
    Validated,
    ValidationError(String),
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncryptedData {
    pub aead_pack: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecieveRecoveryPackages {
    #[serde(flatten)]
    pub recovery_info: RecoveryPackageInfo,
    pub key_type: KeyType,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RecoveryPackageInfo {
    pub key_id: String,
    pub recovery_index: usize,
    pub threshold: usize,
    pub peers: Vec<usize>,
    pub public_keys: PublicKeysEnum,
    pub encrypted_packages: Vec<EncryptedData>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewEdDSAKeyGenSession {
    pub key_id: String,
    pub share_indices: Vec<usize>,
    pub threshold: usize,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct EDDSAKeyGenResult {
    pub y_sum: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ECDSAKeyGenResult {
    pub y_sum: Sum,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Sum {
    x: String,
    y: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignatureResult {
    pub sigma: String,
    pub R: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NatsMessage {
    pub sender_id: usize,
    pub message: EDDSAKeyGenResult,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NatsPackageMessage {
    pub sender_id: usize,
    pub message: EncryptedData,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NatsValidationMessage {
    pub sender_id: usize,
    pub message: ECDSARecoveryValidationResult,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NatsSigMessage {
    pub sender_id: usize,
    pub message: SignatureResult,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewRegenSession {
    pub key_id: String,
    pub share_indices: Vec<usize>,
    pub keyshare_index: usize,
    pub owner_public_key: String,
}

#[derive(Deserialize, Serialize)]
pub struct JoinSignSessionResponse {
    pub id_in_session: usize,
    pub message: Vec<u8>,
}

#[derive(Deserialize, PartialEq, Serialize)]
pub struct SigningResult {
    pub r: String,
    pub s: String,
    pub recid: u8,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UpdatePaillierKeysCommand {
    pub key_id: String,
    pub new_eks: Vec<EncryptionKey>,
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub enum ECDSARecoveryValidationResult {
    Validated(EncryptionKey),
    ValidationError(String),
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub struct EncryptionKey {
    pub n: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenResponse {
    pub pk: String,
    pub import_cmd: Vec<KeyImportShareCommand>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyImportShareCommand {
    key_id: String,
    key_type: String,
    key_share: String,
    vss: String,
    threshold: usize,
    index: usize,
    key: Option<String>,
}

// TODO: move to shared library

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NewSr25519KeySignSession {
    pub key_id: String,
    pub session_id: String,
    pub message: Vec<u8>,
    pub party_index: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ResultMsg {
    pub musig_public_key: PublicKey,
    pub sig: Signature,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKey(String);

impl From<schnorrkel::PublicKey> for PublicKey {
    fn from(r: schnorrkel::PublicKey) -> Self {
        PublicKey(hex::encode(r.to_bytes()))
    }
}

impl From<PublicKey> for schnorrkel::PublicKey {
    fn from(r: PublicKey) -> Self {
        let r_bytes = hex::decode(r.0).expect("Hex encoded PublicKey");
        schnorrkel::PublicKey::from_bytes(&r_bytes).expect("Failed to create public key from bytes")
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
