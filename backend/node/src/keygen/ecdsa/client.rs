use crate::communication::ecdsa::{ collect_messages_ordered, collect_messages_p2p };
use crate::encryption::{ aes_decrypt, aes_encrypt, AES_KEY_BYTES_LEN };
use crate::keygen::ecdsa::KeyGenMessage;
use crate::keygen::ecdsa::{ KeyGenContext, NewKeyGenSession };
use crate::security::check_for_small_primes;
use crate::storage::KeyshareSaver;
use crate::storage::ECDSA;
use anyhow::{ anyhow, bail };
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{ Point, Scalar, Secp256k1 };
use curv::BigInt;
use itertools::Itertools;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1,
    KeyGenDecommitMessage1,
    Keys,
    Parameters as ThresholdParameters,
    SharedKeys,
};
use nats::Subscription;
use paillier::EncryptionKey;
use sha2::Sha256;
use shared::recovery::EncryptedData;
use zk_paillier::zkproofs::DLogStatement;

/**
 * NOTE: There are two competing definitions of what the threshold is.
 * a) The minimum number of parties needed to sign a message,
 *    i.e. (t) parties can sign, (t-1) cannot.
 * b) The maximum number of parties unable to sign a message,
 *    i.e. (t+1) parties can sign, (t) cannot.
 *
 * The MVP code follows the definition as stated in a),
 * whereas the multi-party-ecdsa library we use underneath follows the b) definition.
 * As such, the -1 is needed to convert from a) to b).
 */

//set to one below threshold, see note.

pub const THRESHOLD: usize = 2;

pub struct KeygenClient {
    party_count: usize,
    party_id: usize,
    private_keys: Keys,
    commit_vec: Vec<KeyGenBroadcastMessage1>,
    h1_h2_n_tilde_vec: Vec<DLogStatement>,
    shared_keys: SharedKeys,
    pub y_sum: Point<Secp256k1>,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    dlog_proof_vec: Vec<DLogProof<Secp256k1, Sha256>>,
}

pub struct SessionJoinParams {
    pub parties: usize,
    pub party_id: usize,
    pub session_start: Subscription,
    pub all_round_subs: AllRoundSubscriptions,
}

struct RoundSubscription {
    subscription: Subscription,
    subject: String,
}

pub struct AllRoundSubscriptions {
    round1: RoundSubscription,
    round2: RoundSubscription,
    round3: RoundSubscription,
    round4: RoundSubscription,
    round5: RoundSubscription,
}

struct Phase1Part1Data {
    pub keys: Keys,
    pub commit_i: KeyGenBroadcastMessage1,
    pub decom_i: KeyGenDecommitMessage1,
}

struct Phase1Part2Data {
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
}

struct Phase2Part1Data {
    pub y_sum: Point<Secp256k1>,
    vss_scheme: VerifiableSS<Secp256k1>,
    secret_shares: Vec<Scalar<Secp256k1>>,
}

struct Phase2Part2Data {
    pub shared_keys: SharedKeys,
    pub dlog_proof: DLogProof<Secp256k1, Sha256>,
}

impl KeygenClient {
    pub fn new(
        context: KeyGenContext,
        all_round_subs: AllRoundSubscriptions
    ) -> anyhow::Result<Self> {
        let phase1_part1_data = Self::phase1_part1(&context);

        let commit_vec = Self::phase1_round1(
            &context,
            &phase1_part1_data.commit_i,
            all_round_subs.round1
        )?;

        // Security issue: CVE-2023-33241
        for commit in &commit_vec {
            check_for_small_primes(&commit.e)?;
        }

        let (decom_vec, point_vec, enc_key_vec) = Self::phase1_round2(
            &context,
            &phase1_part1_data.decom_i,
            &phase1_part1_data.keys,
            all_round_subs.round2
        )?;

        let phase1_part2_data = Self::phase1_part2(&commit_vec);
        // ***************** PHASE 2 ************************* //
        let phase2_part1_data = Self::phase2_part1(
            &context,
            &phase1_part1_data,
            &decom_vec,
            &point_vec,
            &commit_vec
        )?;

        Self::phase2_send_shares(&context, &enc_key_vec, &phase2_part1_data.secret_shares)?;

        let party_shares = Self::phase2_receive_shares(
            &context,
            &enc_key_vec,
            &phase2_part1_data.secret_shares,
            all_round_subs.round3
        )?;

        let vss_scheme_vec = Self::phase2_send_and_receive_vss_commitments(
            &context,
            &phase2_part1_data.vss_scheme,
            all_round_subs.round4
        )?;

        let phase2_part2_data = Self::phase2_part2(
            &context,
            &phase1_part1_data,
            &point_vec,
            &party_shares,
            &vss_scheme_vec
        )?;

        let dlog_proof_vec = Self::phase3_send_and_receive_dlog_proof(
            &context,
            &phase2_part2_data.dlog_proof,
            all_round_subs.round5
        )?;

        Self::phase3(&context, &point_vec, &dlog_proof_vec, &vss_scheme_vec)?;

        Ok(Self {
            party_count: context.share_params.party_count as usize,
            party_id: context.share_params.party_index as usize,
            private_keys: phase1_part1_data.keys,
            commit_vec,
            h1_h2_n_tilde_vec: phase1_part2_data.h1_h2_n_tilde_vec,
            shared_keys: phase2_part2_data.shared_keys,
            y_sum: phase2_part1_data.y_sum,
            vss_scheme_vec,
            dlog_proof_vec,
        })
    }
    fn phase1_round1(
        params: &KeyGenContext,
        commit_i: &KeyGenBroadcastMessage1,
        round1: RoundSubscription
    ) -> anyhow::Result<Vec<KeyGenBroadcastMessage1>> {
        let mut commit_vec = Vec::new();
        let message = KeyGenMessage {
            sender_id: (params.share_params.party_index - 1) as usize,
            msg: serde_json::to_string(commit_i).unwrap(),
        };
        params.nc.publish(&round1.subject, serde_json::to_string(&message).unwrap()).unwrap();
        let msg_vec = collect_messages_ordered::<KeyGenMessage>(
            &round1.subscription,
            params.share_params.party_count as usize
        )?;
        for phase1 in msg_vec {
            commit_vec.push(serde_json::from_str::<KeyGenBroadcastMessage1>(&phase1.msg).unwrap());
        }
        Ok(commit_vec)
    }

    fn phase1_round2(
        params: &KeyGenContext,
        decom_i: &KeyGenDecommitMessage1,
        party_keys: &Keys,
        round2: RoundSubscription
    ) -> anyhow::Result<(Vec<KeyGenDecommitMessage1>, Vec<Point<Secp256k1>>, Vec<Vec<u8>>)> {
        let mut point_vec: Vec<Point<Secp256k1>> = Vec::new();
        let mut enc_keys: Vec<Vec<u8>> = Vec::new();
        let mut decom_vec = Vec::new();

        let message = KeyGenMessage {
            sender_id: (params.share_params.party_index - 1) as usize,
            msg: serde_json::to_string(decom_i).unwrap(),
        };

        params.nc.publish(&round2.subject, serde_json::to_string(&message).unwrap()).unwrap();
        let msg_vec = collect_messages_ordered::<KeyGenMessage>(
            &round2.subscription,
            params.share_params.party_count as usize
        )?;

        for (index, phase2) in msg_vec.into_iter().enumerate() {
            let phase2 = serde_json::from_str::<KeyGenDecommitMessage1>(&phase2.msg).unwrap();
            decom_vec.push(phase2.clone());
            point_vec.push(phase2.y_i.clone());
            if index != ((params.share_params.party_index - 1) as usize) {
                let x_coord = (&phase2.y_i * &party_keys.u_i).x_coord().unwrap();
                let key_bytes: Vec<u8> = BigInt::to_bytes(&x_coord);
                match AES_KEY_BYTES_LEN - key_bytes.len() {
                    x if x == 0 => {
                        enc_keys.push(key_bytes);
                    }
                    x if x > 0 => {
                        let mut encryption_key: Vec<u8> = vec![0u8; x];
                        encryption_key.extend_from_slice(&key_bytes[..]);
                        enc_keys.push(encryption_key);
                    }
                    _ => {
                        bail!("encryption key length is too long");
                    }
                }
            }
        }
        Ok((decom_vec, point_vec, enc_keys))
    }

    fn phase1_part1(params: &KeyGenContext) -> Phase1Part1Data {
        let keys = Keys::create(params.share_params.party_index as usize);
        let (commit_i, decom_i) =
            keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();
        return Phase1Part1Data {
            keys,
            commit_i,
            decom_i,
        };
    }
    fn phase1_part2(commit_vec: &Vec<KeyGenBroadcastMessage1>) -> Phase1Part2Data {
        let h1_h2_n_tilde_vec = Self::phase1_calculate_h1_h2_n_tilde_vec(commit_vec);

        return Phase1Part2Data { h1_h2_n_tilde_vec };
    }

    fn phase1_calculate_h1_h2_n_tilde_vec(
        commit_vec: &Vec<KeyGenBroadcastMessage1>
    ) -> Vec<DLogStatement> {
        return commit_vec
            .iter()
            .map(|bc1| bc1.dlog_statement.clone())
            .collect::<Vec<DLogStatement>>();
    }

    // ****** PHASE 2 functions ****** //
    fn phase2_part1(
        params: &KeyGenContext,
        phase1_part1: &Phase1Part1Data,
        decom_vec: &Vec<KeyGenDecommitMessage1>,
        point_vec: &Vec<Point<Secp256k1>>,
        commit_vec: &Vec<KeyGenBroadcastMessage1>
    ) -> anyhow::Result<Phase2Part1Data> {
        let (y_sum, vss_scheme, secret_shares) = Self::phase2_generate_shares(
            params,
            phase1_part1,
            commit_vec,
            decom_vec,
            &point_vec
        )?;

        Ok(Phase2Part1Data {
            y_sum,
            vss_scheme,
            secret_shares,
        })
    }

    fn phase2_send_shares(
        params: &KeyGenContext,
        enc_key_vec: &Vec<Vec<u8>>,
        secret_shares: &Vec<Scalar<Secp256k1>>
    ) -> anyhow::Result<()> {
        let party_count = params.share_params.party_count as usize;
        let mut j = 0;
        for (k, i) in (1..=party_count).enumerate() {
            if i != (params.share_params.party_index as usize) {
                let key_i = &enc_key_vec[j];
                let plaintext = BigInt::to_bytes(&secret_shares[k].to_bigint());

                let send_data = aes_encrypt(&plaintext, &key_i)?;

                let share_send = KeyGenMessage {
                    sender_id: (params.share_params.party_index - 1) as usize,
                    msg: serde_json::to_string(&send_data).unwrap(),
                };
                let subject = format_round_subject(&params.key_id, &format!("round3.{}", i));

                params.nc.publish(&subject, serde_json::to_string(&share_send).unwrap()).unwrap();
                j += 1;
            }
        }
        Ok(())
    }

    fn phase2_receive_shares(
        params: &KeyGenContext,
        enc_key_vec: &Vec<Vec<u8>>,
        secret_shares: &Vec<Scalar<Secp256k1>>,
        receive_share_sub: RoundSubscription
    ) -> anyhow::Result<Vec<Scalar<Secp256k1>>> {
        let mut party_shares: Vec<Scalar<Secp256k1>> = Vec::new();

        let receiver_id = (params.share_params.party_index - 1) as usize;
        let msg_vec = collect_messages_p2p::<KeyGenMessage>(
            &receive_share_sub.subscription,
            params.share_params.party_count as usize,
            receiver_id
        )?;

        for (index, phase2_shares) in msg_vec.into_iter().enumerate() {
            let encrypted_data = serde_json::from_str::<EncryptedData>(&phase2_shares.msg).unwrap();
            let key = &enc_key_vec[index];
            let plaintext = aes_decrypt(&encrypted_data, &key)?;
            let out_bn = BigInt::from_bytes(&plaintext[..]);
            let out_fe = Scalar::from(&out_bn);
            party_shares.push(out_fe);
        }

        party_shares.insert(receiver_id, secret_shares[receiver_id].clone());

        Ok(party_shares)
    }

    fn phase2_generate_shares(
        context: &KeyGenContext,
        phase1_part1: &Phase1Part1Data,
        commit_vec: &Vec<KeyGenBroadcastMessage1>,
        decom_vec: &Vec<KeyGenDecommitMessage1>,
        point_vec: &Vec<Point<Secp256k1>>
    ) -> anyhow::Result<(Point<Secp256k1>, VerifiableSS<Secp256k1>, Vec<Scalar<Secp256k1>>)> {
        let (head, tail) = point_vec.split_at(1);
        let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

        let (vss_scheme, secret_shares, _) = phase1_part1.keys
            .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
                &(ThresholdParameters {
                    share_count: context.share_params.party_count as u16,
                    threshold: context.share_params.threshold as u16,
                }),
                decom_vec,
                commit_vec
            )
            .map_err(|_| anyhow!("Phase 2 share generation unsuccessful"))?;

        Ok((y_sum, vss_scheme, secret_shares))
    }

    fn phase2_send_and_receive_vss_commitments(
        context: &KeyGenContext,
        vss_scheme: &VerifiableSS<Secp256k1>,
        round4: RoundSubscription
    ) -> anyhow::Result<Vec<VerifiableSS<Secp256k1>>> {
        let mut vss_scheme_vec = Vec::<VerifiableSS<Secp256k1>>::new();
        let vss_message = KeyGenMessage {
            sender_id: (context.share_params.party_index - 1) as usize,
            msg: serde_json::to_string(vss_scheme).unwrap(),
        };
        context.nc.publish(&round4.subject, serde_json::to_string(&vss_message).unwrap()).unwrap();
        let msg_vec = collect_messages_ordered::<KeyGenMessage>(
            &round4.subscription,
            context.share_params.party_count as usize
        )?;
        for phase2_vss in msg_vec {
            vss_scheme_vec.push(
                serde_json::from_str::<VerifiableSS<Secp256k1>>(&phase2_vss.msg).unwrap()
            );
        }
        Ok(vss_scheme_vec)
    }

    fn phase2_part2(
        params: &KeyGenContext,
        phase1_part1_data: &Phase1Part1Data,
        point_vec: &Vec<Point<Secp256k1>>,
        party_shares: &Vec<Scalar<Secp256k1>>,
        vss_scheme_vec: &Vec<VerifiableSS<Secp256k1>>
    ) -> anyhow::Result<Phase2Part2Data> {
        let (shared_keys, dlog_proof) = Self::phase2_recreate_shared_keys(
            params,
            point_vec,
            phase1_part1_data,
            party_shares,
            vss_scheme_vec
        )?;

        Ok(Phase2Part2Data {
            shared_keys,
            dlog_proof,
        })
    }

    fn phase2_recreate_shared_keys(
        context: &KeyGenContext,
        point_vec: &Vec<Point<Secp256k1>>,
        phase1_part1_data: &Phase1Part1Data,
        party_shares: &Vec<Scalar<Secp256k1>>,
        vss_scheme_vec: &Vec<VerifiableSS<Secp256k1>>
    ) -> anyhow::Result<(SharedKeys, DLogProof<Secp256k1, Sha256>)> {
        let p1p1d = phase1_part1_data.keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &(ThresholdParameters {
                    share_count: context.share_params.party_count as u16,
                    threshold: context.share_params.threshold as u16,
                }),
                &point_vec,
                party_shares,
                vss_scheme_vec,
                context.share_params.party_index as usize
            )
            .map_err(|_| anyhow!("Shared keys were not recreated successfully"))?;
        Ok(p1p1d)
    }

    fn phase3_send_and_receive_dlog_proof(
        params: &KeyGenContext,
        dlog_proof: &DLogProof<Secp256k1, Sha256>,
        round5: RoundSubscription
    ) -> anyhow::Result<Vec<DLogProof<Secp256k1, Sha256>>> {
        let mut dlog_proof_vec = Vec::<DLogProof<Secp256k1, Sha256>>::new();

        let dlog_message = KeyGenMessage {
            sender_id: (params.share_params.party_index - 1) as usize,
            msg: serde_json::to_string(dlog_proof).unwrap(),
        };
        params.nc.publish(&round5.subject, serde_json::to_string(&dlog_message).unwrap()).unwrap();
        let msg_vec = collect_messages_ordered::<KeyGenMessage>(
            &round5.subscription,
            params.share_params.party_count as usize
        )?;
        for phase3 in msg_vec {
            dlog_proof_vec.push(
                serde_json::from_str::<DLogProof<Secp256k1, Sha256>>(&phase3.msg).unwrap()
            );
        }
        Ok(dlog_proof_vec)
    }

    fn phase3(
        context: &KeyGenContext,
        point_vec: &Vec<Point<Secp256k1>>,
        dlog_proof_vec: &Vec<DLogProof<Secp256k1, Sha256>>,
        vss_scheme: &[VerifiableSS<Secp256k1>]
    ) -> anyhow::Result<()> {
        Self::phase3_verify_dlog_proofs(
            &(ThresholdParameters {
                share_count: context.share_params.party_count as u16,
                threshold: context.share_params.threshold as u16,
            }),
            dlog_proof_vec,
            point_vec,
            vss_scheme
        )
    }

    fn phase3_verify_dlog_proofs(
        params: &ThresholdParameters,
        dlog_proof_vec: &Vec<DLogProof<Secp256k1, Sha256>>,
        y_vec: &Vec<Point<Secp256k1>>,
        vss_scheme: &[VerifiableSS<Secp256k1>]
    ) -> anyhow::Result<()> {
        let verified = Keys::verify_dlog_proofs_check_against_vss(
            params,
            dlog_proof_vec,
            y_vec,
            vss_scheme
        ).map_err(|_| anyhow!("{}", "Dlog proofs not verified successfully"))?;
        Ok(verified)
    }

    pub fn save_to_file(&self, keysaver: &KeyshareSaver) -> anyhow::Result<()> {
        let public_key_vec = (0..self.party_count)
            .map(|i| self.dlog_proof_vec[i].pk.clone())
            .collect::<Vec<Point<Secp256k1>>>();

        let paillier_key_vec = (0..self.party_count)
            .map(|i| self.commit_vec[i].e.clone())
            .collect::<Vec<EncryptionKey>>();

        let keyshare = ECDSA {
            x_i: self.shared_keys.x_i.clone().into(),
            y_sum: self.y_sum.clone().into(),
            threshold: THRESHOLD,
            party_index: self.party_id,
            vss_scheme_vec: self.vss_scheme_vec.to_vec(),
            paillier_key_vec,
            h1_h2_N_tilde_vec: self.h1_h2_n_tilde_vec.to_vec(),
            public_key_vec,
            paillier_dk: self.private_keys.dk.clone(),
        };

        keysaver.save_key(&keyshare)
    }
}

impl AllRoundSubscriptions {
    pub fn subscribe_to_all_rounds(
        session: &NewKeyGenSession,
        party_num: u16,
        conn: &nats::Connection
    ) -> anyhow::Result<AllRoundSubscriptions> {
        //TODO refactor this further, make it more generic
        let round1_subject = format_round_subject(&session.key_id, "round1");
        let round1_sub = Self::round_subscribe(round1_subject, conn)?;

        let round2_subject = format_round_subject(&session.key_id, "round2");
        let round2_sub = Self::round_subscribe(round2_subject, conn)?;
        //bit different to the rest as it has party_num
        let round3_subject = format_round_subject(
            &session.key_id,
            &format!("round3.{}", party_num)
        );
        let round3_sub = Self::round_subscribe(round3_subject, conn)?;

        let round4_subject = format_round_subject(&session.key_id, "round4");
        let round4_sub = Self::round_subscribe(round4_subject, conn)?;

        let round5_subject = format_round_subject(&session.key_id, "round5");
        let round5_sub = Self::round_subscribe(round5_subject, conn)?;

        Ok(AllRoundSubscriptions {
            round1: round1_sub,
            round2: round2_sub,
            round3: round3_sub,
            round4: round4_sub,
            round5: round5_sub,
        })
    }

    fn round_subscribe(
        round: String,
        conn: &nats::Connection
    ) -> anyhow::Result<RoundSubscription> {
        let subscription = conn.subscribe(&round)?;
        Ok(RoundSubscription {
            subscription,
            subject: round,
        })
    }
}

fn format_round_subject(key_id: &str, suffix: &str) -> String {
    return format!(
        "network.gridlock.nodes.keyGen.{}{}{}",
        key_id,
        if suffix.is_empty() {
            ""
        } else {
            "."
        },
        suffix
    );
}
