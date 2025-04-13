use crate::communication::ecdsa::HasSenderId;
use crate::communication::nats::PeerMessenger;
use crate::communication::protocol::{ AllRounds, KeyGenAllRounds };
use crate::encryption::{ aes_decrypt, aes_encrypt, encryption_key_for_aes };
use crate::keygen::ShareParams;
use crate::storage::EDDSA;
use anyhow::anyhow;
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{ Ed25519, Point, Scalar };
use curv::BigInt;
use itertools::Itertools;
use multi_party_eddsa::protocols::thresholdsig::{
    EphemeralKey,
    EphemeralSharedKeys,
    KeyGenBroadcastMessage1,
    Keys,
    Parameters as ThresholdParameters,
};
use serde::de::DeserializeOwned;
use serde::{ Deserialize, Serialize };

pub struct KeyGenClient<C> {
    pub peer_messenger: C,
    pub share_params: ShareParams,
    pub all_party_indices: Vec<usize>,
}

impl<C> KeyGenClient<C> where C: PeerMessenger<KeyGenAllRounds> {
    pub fn create_shared_key(&self) -> anyhow::Result<EDDSA> {
        let params = ThresholdParameters {
            threshold: self.share_params.threshold as u16,
            share_count: self.share_params.party_count as u16,
        };

        let key = Keys::phase1_create(self.share_params.party_index as u16);

        let (commitment_to_y_i, blind) = key.phase1_broadcast();

        let commitments = self.exchange_commitments_to_y_i(commitment_to_y_i)?;

        let decommitment_for_y_i = Decommitment {
            blind,
            y_i: key.keypair.public_key.clone(),
        };

        let (blindings, y_vec) = self.exchange_decommitments(decommitment_for_y_i)?;

        let all_party_indices = &*self.all_party_indices
            .iter()
            .map(|&i| i as u16)
            .collect_vec();
        let (local_vss, local_secrets) = key.phase1_verify_com_phase2_distribute(
            &params,
            &blindings,
            &y_vec,
            &commitments,
            all_party_indices
        )?;

        let enc_vec = Self::encryption_keys_from_y_vec(
            &self,
            &y_vec,
            &key.keypair.expanded_private_key.private_key
        )?;

        let secret_shares = self.exchange_secret_shares(&enc_vec, &local_secrets)?;

        let vss_scheme_vec = self.exchange_vss(&local_vss)?;

        let shared_key = key
            .phase2_verify_vss_construct_keypair(
                &params,
                &y_vec,
                &secret_shares,
                &vss_scheme_vec,
                self.share_params.party_index as u16
            )
            .map_err(|_| anyhow!("Not able to verify VSS"))?;

        Ok(EDDSA {
            x_i: shared_key.x_i.into(),
            y_sum: shared_key.y.into(),
            party_index: key.party_index as usize,
            vss_scheme_vec,
            threshold: self.share_params.threshold,
        })
    }

    pub fn create_ephemeral_shared_key(&self, message: &[u8]) -> anyhow::Result<EphemeralEdDSAKey> {
        let params = ThresholdParameters {
            threshold: self.share_params.threshold as u16,
            share_count: self.share_params.party_count as u16,
        };

        let key = Keys::phase1_create(self.share_params.party_index as u16);
        let key = EphemeralKey::ephermeral_key_create_from_deterministic_secret(
            &key,
            message,
            self.share_params.party_index as u16
        );

        let (commitment_to_y_i, blind) = key.phase1_broadcast();

        let commitments = self.exchange_commitments_to_y_i(commitment_to_y_i)?;

        let decommitment_for_y_i = Decommitment {
            blind,
            y_i: key.R_i.clone(),
        };

        let (blindings, y_vec) = self.exchange_decommitments(decommitment_for_y_i)?;

        let all_party_indices = &*self.all_party_indices
            .iter()
            .map(|&i| i as u16)
            .collect_vec();
        let (local_vss, local_secrets) = key.phase1_verify_com_phase2_distribute(
            &params,
            &blindings,
            &y_vec,
            &commitments,
            all_party_indices
        )?;

        let enc_vec = Self::encryption_keys_from_y_vec(&self, &y_vec, &key.r_i)?;

        let secret_shares = self.exchange_secret_shares(&enc_vec, &local_secrets)?;

        let vss_scheme_vec = self.exchange_vss(&local_vss)?;

        let shared_key = key
            .phase2_verify_vss_construct_keypair(
                &params,
                &y_vec,
                &secret_shares,
                &vss_scheme_vec,
                key.party_index
            )
            .map_err(|_| anyhow!("Not able to verify VSS"))?;

        Ok(EphemeralEdDSAKey {
            key,
            shared_key,
            vss_scheme_vec,
        })
    }

    pub fn publish_result<T: Serialize + DeserializeOwned + Clone>(
        &self,
        y_sum: T
    ) -> anyhow::Result<()> {
        let _ = self.peer_messenger.broadcast_and_collect_messages(
            &<KeyGenAllRounds as AllRounds>::BroadcastRound::Result,
            y_sum
        )?;
        Ok(())
    }

    fn exchange_commitments_to_y_i(
        &self,
        com: KeyGenBroadcastMessage1
    ) -> anyhow::Result<Vec<KeyGenBroadcastMessage1>> {
        self.peer_messenger.broadcast_and_collect_messages(
            &<KeyGenAllRounds as AllRounds>::BroadcastRound::Commit,
            com
        )
    }

    fn exchange_decommitments(
        &self,
        decommitment: Decommitment
    ) -> anyhow::Result<(Vec<BigInt>, Vec<Point<Ed25519>>)> {
        let decommitments = self.peer_messenger.broadcast_and_collect_messages(
            &<KeyGenAllRounds as AllRounds>::BroadcastRound::Decommit,
            decommitment
        )?;
        let mut blinding_factors = Vec::new();
        let mut y_vec = Vec::new();
        for decom in decommitments {
            blinding_factors.push(decom.blind);
            let fixed_y_i = decom.y_i;
            y_vec.push(fixed_y_i);
        }
        Ok((blinding_factors, y_vec))
    }

    fn exchange_vss(
        &self,
        vss_scheme: &VerifiableSS<Ed25519>
    ) -> anyhow::Result<Vec<VerifiableSS<Ed25519>>> {
        let vss_schemes = self.peer_messenger.broadcast_and_collect_messages(
            &<KeyGenAllRounds as AllRounds>::BroadcastRound::VSS,
            vss_scheme.clone()
        )?;
        let mut vss_schemes_fixed = Vec::new();
        for vss in vss_schemes {
            let fixed_vss = vss;
            vss_schemes_fixed.push(fixed_vss);
        }
        Ok(vss_schemes_fixed)
    }

    fn encryption_keys_from_y_vec(
        &self,
        y_vec: &Vec<Point<Ed25519>>,
        u_i: &Scalar<Ed25519>
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        y_vec
            .iter()
            .map(|y_j| encryption_key_for_aes(y_j, u_i))
            .collect()
    }

    fn exchange_secret_shares(
        &self,
        enc_vec: &Vec<Vec<u8>>,
        secret_shares: &[Scalar<Ed25519>]
    ) -> anyhow::Result<Vec<Scalar<Ed25519>>> {
        let mut outgoing_messages = Vec::new();

        for (i, party_index) in self.all_party_indices.iter().enumerate() {
            if *party_index != self.share_params.party_index {
                let enc_key = &enc_vec[i];
                let plaintext = BigInt::to_bytes(&secret_shares[i].to_bigint());
                let send_data = aes_encrypt(&plaintext, &enc_key)?;

                outgoing_messages.push(send_data);
            }
        }
        let msg_vec = self.peer_messenger.send_p2p_and_collect_messages(
            &<KeyGenAllRounds as AllRounds>::P2PRound::ShareSecret,
            outgoing_messages
        )?;
        let mut party_shares = Vec::new();
        let mut encrypted_data = msg_vec.into_iter();

        for (index, party_index) in self.all_party_indices.iter().enumerate() {
            if *party_index != self.share_params.party_index {
                let key = &enc_vec[index];
                let plaintext = aes_decrypt(&encrypted_data.next().unwrap(), &key)?;
                let bn = BigInt::from_bytes(&plaintext[..]);
                let secret = Scalar::from(&bn);
                party_shares.push(secret);
            } else {
                party_shares.push(secret_shares[index].clone());
            }
        }

        Ok(party_shares)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Decommitment {
    blind: BigInt,
    y_i: Point<Ed25519>,
}

#[derive(Serialize, Deserialize)]
struct BroadcastMessage<T> {
    pub sender_id: usize,
    pub message: T,
}

impl<T> HasSenderId for BroadcastMessage<T> {
    fn get_sender_id(&self) -> usize {
        self.sender_id
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize, Deserialize)]
pub struct EphemeralEdDSAKey {
    pub key: EphemeralKey,
    pub shared_key: EphemeralSharedKeys,
    pub vss_scheme_vec: Vec<VerifiableSS<Ed25519>>,
}
