use crate::communication::ecdsa::{ collect_messages_ordered, collect_messages_p2p, JoinMessage };
use crate::signing::ecdsa;
use crate::signing::ecdsa::{
    JoinSignSessionErrorResponse,
    JoinSignSessionResponse,
    NewSignSession,
    NewSignMessage,
    SigningResult,
};
use crate::storage::{ KeyshareAccessor, ECDSA };
use crate::App;
use anyhow::{ anyhow, bail };
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{ Point, Scalar, Secp256k1 };
use curv::BigInt;
use itertools::Itertools;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::blame::{
    GlobalStatePhase5,
    GlobalStatePhase6,
    GlobalStatePhase7,
    LocalStatePhase5,
    LocalStatePhase6,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    Keys,
    LocalSignature,
    SignBroadcastPhase1,
    SignDecommitPhase1,
    SignKeys,
    SignatureRecid,
};
use multi_party_ecdsa::utilities::mta::{ MessageA, MessageB };
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use paillier::EncryptionKey;
use sha2::Sha256;
use std::any::type_name;
use std::thread;
use std::time::Duration;
use tracing::{ error, info, instrument };
use chrono::{ DateTime, Utc };
use hmac::{ Hmac, Mac, NewMac };
use base64;
use crate::node::NodeIdentity;
use crate::storage::fs::WriteOpts;
use crate::storage::key_metadata_store::KeyMetadataStore;
use crate::auth::e2e_decrypt;

const PARTIES: usize = 5;
const THRESHOLD: usize = 3;

const PHASES: usize = 8;
const P2P_PHASE: usize = 2;

fn format_session_subject(sess: &NewSignSession, suffix: &str) -> String {
    return format!(
        "network.gridlock.nodes.keySign.session.{}{}{}",
        sess.session_id,
        if suffix.is_empty() {
            ""
        } else {
            "."
        },
        suffix
    );
}

fn signature_recid_to_signing_result(sig: &SignatureRecid) -> SigningResult {
    let fe_to_string = |x: &Scalar<Secp256k1>| {
        format!("{:0>width$}", x.to_bigint().to_str_radix(16), width = 64usize)
    };

    SigningResult {
        r: fe_to_string(&sig.r),
        s: fe_to_string(&sig.s),
        recid: sig.recid,
    }
}

pub struct SignPhase {
    topic: String,
    sub: nats::Subscription,
}

impl SignPhase {
    pub fn new(
        connection: &nats::Connection,
        session: &NewSignSession,
        name: &str
    ) -> anyhow::Result<Self> {
        let subject = format_session_subject(session, name);
        info!("Subscribing to topic \"{}\"", &subject);

        let subscription = connection.subscribe(&subject)?;

        Ok(Self {
            sub: subscription,
            topic: subject,
        })
    }
}

struct Phase1Data {
    pub decommit: SignDecommitPhase1,
    pub bc1_vec: Vec<SignBroadcastPhase1>,
    pub g_w_vec: Vec<Point<Secp256k1>>,
    pub m_a_k: MessageA,
    pub m_a_vec: Vec<MessageA>,
    pub randomness: BigInt,
    pub sign_keys: SignKeys,
    pub xi_com_vec: Vec<Point<Secp256k1>>,
}

struct Phase2Data {
    pub alpha_vec: Vec<Scalar<Secp256k1>>,
    pub beta_vec: Vec<Scalar<Secp256k1>>,
    pub beta_randomness_vec: Vec<BigInt>,
    pub beta_tag_vec: Vec<BigInt>,
    pub miu_vec: Vec<Scalar<Secp256k1>>,
    pub miu_bigint_vec: Vec<BigInt>,
    pub m_b_gamma_all_mtx: Vec<Vec<MessageB>>,
    pub m_b_gamma_rec_vec: Vec<MessageB>,
    pub m_b_w_rec_vec: Vec<MessageB>,
    pub m_b_w_all_mtx: Vec<Vec<MessageB>>,
    pub ni_vec: Vec<Scalar<Secp256k1>>,
}

struct Phase3Data {
    pub delta_inv: Scalar<Secp256k1>,
    pub delta_vec: Vec<Scalar<Secp256k1>>,
    pub l_i: Scalar<Secp256k1>,
    pub sigma: Scalar<Secp256k1>,
    pub T_i: Point<Secp256k1>,
    pub T_vec: Vec<Point<Secp256k1>>,
}

struct Phase4Data {
    pub decommit_vec: Vec<SignDecommitPhase1>,
    pub R: Point<Secp256k1>,
}

struct Phase5Data {
    pub R_dash_vec: Vec<Point<Secp256k1>>,
}

struct Phase6Data {
    pub S_vec: Vec<Point<Secp256k1>>,
}

struct Phase7Data {
    pub local_sig_vec: Vec<LocalSignature>,
    pub sig: SignatureRecid,
    pub message_bn: BigInt,
}

impl SignSession {
    #[instrument(skip_all)]
    fn session_join(
        conn: &nats::Connection,
        sess: &NewSignSession
    ) -> anyhow::Result<JoinSignSessionResponse> {
        info!("START");
        let join_subject = format_session_subject(&sess, "join");
        let join_message = serde_json::to_string(&JoinMessage::new(sess.session_id.clone(), 0))?;
        info!(
            "Sending Request on Subject {} session_id: {}, key_id: {}",
            join_subject,
            sess.session_id,
            sess.key_id
        );
        let response_json = conn.request_timeout(
            &join_subject,
            join_message,
            Duration::from_secs(25)
        )?;

        match serde_json::from_slice::<JoinSignSessionResponse>(&response_json.data) {
            Ok(ok) => {
                info!("OK RESPONSE");
                if ok.message.len() > 32 {
                    let err_msg = format!(
                        "message has size more than 32 bytes! message: {:?}",
                        ok.message
                    );
                    error!("{}", err_msg);
                    bail!("{}", err_msg);
                } else {
                    Ok(ok)
                }
            }
            Err(_) => {
                match serde_json::from_slice::<JoinSignSessionErrorResponse>(&response_json.data) {
                    Ok(response) => {
                        error!("ERROR RESPONSE");
                        bail!("{}", response.error);
                    }
                    Err(_) => {
                        let err_msg = format!(
                            "Failed to deserialize message to \"{}\" and \"{}\" struct",
                            type_name::<JoinSignSessionResponse>(),
                            type_name::<JoinSignSessionErrorResponse>()
                        );

                        error!("{}", err_msg);
                        bail!("{}", err_msg);
                    }
                }
            }
        }
    }

    #[instrument(skip_all)]
    pub fn new(
        connection: nats::Connection,
        session: NewSignSession,
        email: Option<String>
    ) -> anyhow::Result<Self> {
        // Use email-aware keyshare accessor if email is provided
        let keyshare = (
            if let Some(email_str) = email {
                KeyshareAccessor::<ECDSA>::read_only_with_email(&session.key_id, &email_str)?
            } else {
                KeyshareAccessor::<ECDSA>::read_only(&session.key_id)?
            }
        ).key;

        let start_phase = SignPhase::new(&connection, &session, "start")?;

        let mut phase_vec: Vec<SignPhase> = Vec::with_capacity(PHASES);
        for i in 0..PHASES {
            // phase2 is a p2p phase and receives special treatment
            if i == P2P_PHASE {
                continue;
            }

            let phase = SignPhase::new(&connection, &session, &format!("phase{}", i))?;
            phase_vec.push(phase);
        }

        let mut phase2_p2p_vec: Vec<SignPhase> = Vec::with_capacity(PARTIES);
        for i in 0..PARTIES {
            let phase = SignPhase::new(&connection, &session, &format!("phase2.to{}", i))?;
            phase2_p2p_vec.push(phase);
        }

        let party_info = Self::session_join(&connection, &session)?;
        phase_vec.insert(P2P_PHASE, phase2_p2p_vec.remove(party_info.id_in_session));
        Ok(Self {
            connection,
            start_phase,
            phases: phase_vec,
            keyshare,
            party_info,
            session,
        })
    }

    fn wait_for_start_message(&self) {
        self.start_phase.sub.next_timeout(Duration::from_secs(10)).unwrap();
    }

    #[instrument(skip_all)]
    fn phase0__exchange_party_ids(&self) -> anyhow::Result<Vec<usize>> {
        let mesg = ecdsa::Phase0Identity {
            id_in_session: self.party_info.id_in_session,
            shareholder_id: self.keyshare.party_index,
        };
        let json = serde_json::to_string(&mesg).unwrap();
        info!("publishing on subject {}", &self.phases[0].topic);
        self.connection.publish(&self.phases[0].topic, &json).unwrap();

        // Shareholder IDs generated during keygen are in 1..=PARTIES range,
        // but most of the signing code expects them to be in 0..PARTIES range,
        // hence the -1 in the lambda.
        info!("collecting Phase0Identity");
        Ok(
            collect_messages_ordered::<ecdsa::Phase0Identity>(&self.phases[0].sub, THRESHOLD)?
                .into_iter()
                .map(|p0i| p0i.shareholder_id - 1)
                .collect()
        )
    }

    #[instrument(skip_all)]
    fn phase1_broadcast_commitment(
        &self,
        com: &SignBroadcastPhase1,
        m_a_k: &MessageA
    ) -> anyhow::Result<(Vec<SignBroadcastPhase1>, Vec<MessageA>)> {
        let mesg = ecdsa::Phase1Commitment {
            sender_id: self.party_info.id_in_session,
            commitment: com.clone(),
            message: m_a_k.clone(),
        };
        let json = serde_json::to_string(&mesg).unwrap();
        info!("publishing on subject {}", &self.phases[1].topic);
        self.connection.publish(&self.phases[1].topic, &json).unwrap();

        let mut com_vec: Vec<SignBroadcastPhase1> = vec![];
        let mut m_vec: Vec<MessageA> = vec![];
        info!("collecting phase1_broadcast_commitment");

        for p1c in collect_messages_ordered::<ecdsa::Phase1Commitment>(
            &self.phases[1].sub,
            THRESHOLD
        )? {
            com_vec.push(p1c.commitment);
            m_vec.push(p1c.message);
        }

        Ok((com_vec, m_vec))
    }

    #[instrument(skip_all)]
    fn phase1(&self, signers_vec: &Vec<usize>) -> anyhow::Result<Phase1Data> {
        let g_w_vec = SignKeys::g_w_vec(
            &self.keyshare.public_key_vec.iter().cloned().map_into().collect::<Vec<_>>(),
            &signers_vec[..],
            &self.keyshare.vss_scheme_vec[self.keyshare.party_index - 1].clone().into()
        );
        /* let private = PartyPrivate::set_private(
            self.keyshare.party_keys.clone(),
            self.keyshare.shared_keys.clone(),
        );*/

        let sign_keys = SignKeys::create(
            &self.keyshare.x_i,
            &self.keyshare.vss_scheme_vec[self.keyshare.party_index - 1].clone().into(),
            self.keyshare.party_index - 1,
            &signers_vec
        );

        let xi_com_vec = Keys::get_commitments_to_xi(
            &self.keyshare.vss_scheme_vec.iter().cloned().map_into().collect::<Vec<_>>()
        );

        let (com, decommit) = sign_keys.phase1_broadcast();
        let (m_a_k, randomness) = MessageA::a(
            &sign_keys.k_i,
            &self.keyshare.paillier_key_vec[&self.keyshare.party_index - 1],
            &[]
        );

        let (bc1_vec, m_a_vec) = self.phase1_broadcast_commitment(&com, &m_a_k)?;

        Ok(Phase1Data {
            decommit,
            bc1_vec,
            g_w_vec,
            m_a_k,
            m_a_vec,
            randomness,
            sign_keys,
            xi_com_vec,
        })
    }

    #[instrument(skip_all)]
    fn phase2_exchange_gamma_and_w(
        &self,
        gamma_vec: &Vec<MessageB>,
        m_b_vec: &Vec<MessageB>
    ) -> anyhow::Result<(Vec<MessageB>, Vec<MessageB>)> {
        let mut index: usize = 0;
        for party_id in 0..THRESHOLD {
            if party_id == self.party_info.id_in_session {
                continue;
            }

            let mesg = ecdsa::Phase2Gamma {
                sender_id: self.party_info.id_in_session,
                target_id: party_id,
                gamma: gamma_vec[index].clone(),
                w: m_b_vec[index].clone(),
            };
            let json = serde_json::to_string(&mesg).unwrap();

            let subject = format_session_subject(&self.session, &format!("phase2.to{}", party_id));
            info!("publish on subject {}", &subject);
            self.connection.publish(&subject, &json).unwrap();

            index += 1;
        }

        let mut gamma_vec: Vec<MessageB> = vec![];
        let mut w_vec: Vec<MessageB> = vec![];
        info!("collect_messages_p2p Phase2Gamma");
        for p2g in collect_messages_p2p::<ecdsa::Phase2Gamma>(
            &self.phases[2].sub,
            THRESHOLD,
            self.party_info.id_in_session
        )? {
            gamma_vec.push(p2g.gamma);
            w_vec.push(p2g.w);
        }
        Ok((gamma_vec, w_vec))
    }

    #[instrument(skip_all)]
    fn phase2(&self, signers_vec: &Vec<usize>, p1d: &Phase1Data) -> anyhow::Result<Phase2Data> {
        let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
        let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
        let mut beta_vec = Vec::new();
        let mut beta_randomness_vec = Vec::new();
        let mut beta_tag_vec = Vec::new();
        let mut ni_vec = Vec::new();

        for i in 0..THRESHOLD {
            if i != self.party_info.id_in_session {
                let (m_b_gamma, beta_gamma, beta_randomness, beta_tag) = match
                    MessageB::b(
                        &p1d.sign_keys.gamma_i,
                        &self.keyshare.paillier_key_vec[signers_vec[i]],
                        p1d.m_a_vec[i].clone(),
                        &[]
                    )
                {
                    Ok((a, b, c, d)) => (a, b, c, d),
                    Err(_) => bail!("Message b failure in Phase 2"),
                };
                let (m_b_w, beta_wi, _, _) = match
                    MessageB::b(
                        &p1d.sign_keys.w_i,
                        &self.keyshare.paillier_key_vec[signers_vec[i]],
                        p1d.m_a_vec[i].clone(),
                        &[]
                    )
                {
                    Ok((a, b, c, d)) => (a, b, c, d),
                    Err(_) => bail!("Message b failure in Phase 2"),
                };
                m_b_gamma_send_vec.push(m_b_gamma);
                m_b_w_send_vec.push(m_b_w);
                beta_vec.push(beta_gamma);
                beta_randomness_vec.push(beta_randomness);
                beta_tag_vec.push(beta_tag);
                ni_vec.push(beta_wi);
            }
        }

        let (m_b_gamma_rec_vec, m_b_w_rec_vec) = self.phase2_exchange_gamma_and_w(
            &m_b_gamma_send_vec,
            &m_b_w_send_vec
        )?;

        let mut m_b_gamma_all_mtx = Vec::new();
        let mut m_b_w_all_mtx = Vec::new();

        m_b_gamma_all_mtx.push(m_b_gamma_send_vec);
        m_b_gamma_all_mtx.push(m_b_gamma_rec_vec.clone());
        m_b_w_all_mtx.push(m_b_w_send_vec);
        m_b_w_all_mtx.push(m_b_w_rec_vec.clone());

        //  Alpha
        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();
        let mut miu_bigint_vec = Vec::new();
        let mut j = 0;

        for i in 0..THRESHOLD {
            if i != self.party_info.id_in_session {
                let m_b = m_b_gamma_rec_vec[j].clone();

                let alpha_ij_gamma = m_b
                    .verify_proofs_get_alpha(&self.keyshare.paillier_dk, &p1d.sign_keys.k_i)
                    .map_err(|err| anyhow!("{:?}", err))?;

                let m_b = m_b_w_rec_vec[j].clone();
                let alpha_ij_wi = m_b
                    .verify_proofs_get_alpha(&self.keyshare.paillier_dk, &p1d.sign_keys.k_i)
                    .map_err(|err| anyhow!("{:?}", err))?;

                alpha_vec.push(alpha_ij_gamma.0);
                miu_vec.push(alpha_ij_wi.0);
                miu_bigint_vec.push(alpha_ij_wi.1);

                let g_w_i = Keys::update_commitments_to_xi(
                    &p1d.xi_com_vec[signers_vec[i]],
                    &self.keyshare.vss_scheme_vec[signers_vec[i]].clone().into(),
                    signers_vec[i],
                    &signers_vec
                );
                assert_eq!(m_b.b_proof.pk, g_w_i);
                j += 1;
            }
        }

        Ok(Phase2Data {
            alpha_vec,
            beta_vec,
            beta_randomness_vec,
            beta_tag_vec,
            miu_bigint_vec,
            miu_vec,
            m_b_gamma_all_mtx,
            m_b_gamma_rec_vec,
            m_b_w_all_mtx,
            m_b_w_rec_vec,
            ni_vec,
        })
    }

    #[instrument(skip_all)]
    fn phase3_broadcast(
        &self,
        delta_i: &Scalar<Secp256k1>,
        T_i: &Point<Secp256k1>
    ) -> anyhow::Result<(Vec<Scalar<Secp256k1>>, Vec<Point<Secp256k1>>)> {
        let mesg = ecdsa::Phase3Broadcast {
            sender_id: self.party_info.id_in_session,
            delta: delta_i.clone(),
            t: T_i.clone(),
        };
        let json = serde_json::to_string(&mesg).unwrap();
        info!("publish on {} ", &self.phases[3].topic);

        self.connection.publish(&self.phases[3].topic, &json).unwrap();

        let mut delta_vec: Vec<Scalar<Secp256k1>> = vec![];
        let mut t_vec: Vec<Point<Secp256k1>> = vec![];
        info!("collect Phase3Broadcast");
        for p3b in collect_messages_ordered::<ecdsa::Phase3Broadcast>(
            &self.phases[3].sub,
            THRESHOLD
        )? {
            delta_vec.push(p3b.delta);
            t_vec.push(p3b.t);
        }
        Ok((delta_vec, t_vec))
    }

    #[instrument(skip_all)]
    fn phase3(&self, p1d: &Phase1Data, p2d: &Phase2Data) -> anyhow::Result<Phase3Data> {
        let delta_i = p1d.sign_keys.phase2_delta_i(&p2d.alpha_vec, &p2d.beta_vec);
        let sigma = p1d.sign_keys.phase2_sigma_i(&p2d.miu_vec, &p2d.ni_vec);
        let (T_i, l_i, _) = SignKeys::phase3_compute_t_i(&sigma);

        let (delta_vec, T_vec) = self.phase3_broadcast(&delta_i, &T_i)?;
        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

        Ok(Phase3Data {
            delta_inv,
            delta_vec,
            l_i,
            sigma,
            T_i,
            T_vec,
        })
    }

    #[instrument(skip_all)]
    fn phase4_broadcast_decommit(
        &self,
        p1d: &Phase1Data
    ) -> anyhow::Result<Vec<SignDecommitPhase1>> {
        let mesg = ecdsa::Phase4Decommit {
            sender_id: self.party_info.id_in_session,
            decommit: p1d.decommit.clone(),
        };
        let json = serde_json::to_string(&mesg).unwrap();
        info!("publish {}", &self.phases[4].topic);
        self.connection.publish(&self.phases[4].topic, &json).unwrap();
        info!("collect Phase4Decommit");
        Ok(
            collect_messages_ordered::<ecdsa::Phase4Decommit>(&self.phases[4].sub, THRESHOLD)?
                .into_iter()
                .map(|p4d| p4d.decommit)
                .collect()
        )
    }

    #[instrument(skip_all)]
    fn phase4(
        &self,
        p1d: &Phase1Data,
        p2d: &Phase2Data,
        p3d: &Phase3Data
    ) -> anyhow::Result<Phase4Data> {
        let decommit_vec = self.phase4_broadcast_decommit(&p1d)?;

        let b_proof_vec: Vec<&DLogProof<Secp256k1, Sha256>> = p2d.m_b_gamma_rec_vec
            .iter()
            .map(|m_b_gamma| &m_b_gamma.b_proof)
            .collect();

        let R = SignKeys::phase4(
            &p3d.delta_inv,
            &b_proof_vec,
            decommit_vec.clone(),
            &p1d.bc1_vec,
            self.party_info.id_in_session
        ).map_err(|err| anyhow!("{:?}", err))?;

        Ok(Phase4Data { decommit_vec, R })
    }

    #[instrument(skip_all)]
    fn phase5_broadcast_rdash(
        &self,
        r_dash: &Point<Secp256k1>
    ) -> anyhow::Result<Vec<Point<Secp256k1>>> {
        let mesg = ecdsa::Phase5RDash {
            sender_id: self.party_info.id_in_session,
            r_dash: r_dash.clone(),
        };
        let json = serde_json::to_string(&mesg).unwrap();
        info!("publish {}", &self.phases[5].topic);
        self.connection.publish(&self.phases[5].topic, &json).unwrap();
        info!("collect Phase5RDash");

        Ok(
            collect_messages_ordered::<ecdsa::Phase5RDash>(&self.phases[5].sub, THRESHOLD)?
                .into_iter()
                .map(|p5rd| p5rd.r_dash)
                .collect()
        )
    }

    // TODO: Tidy up local state and vectors. make sure they contain all the necessary information.
    #[instrument(skip_all)]
    fn phase5_blame(&self, p1d: &Phase1Data, p2d: &Phase2Data, p3d: &Phase3Data, p4d: &Phase4Data) {
        let mut local_state_vec = Vec::new();
        // compose beta tag vector:
        let mut beta_tag_vec_to_test = Vec::new();
        let mut beta_randomness_vec_to_test = Vec::new();
        for j in 0..THRESHOLD - 1 {
            // this code is different from the "simplify to continue" case
            let index = if j < self.party_info.id_in_session + 1 {
                self.party_info.id_in_session - 1
            } else {
                self.party_info.id_in_session
            };

            beta_tag_vec_to_test.push(p2d.beta_tag_vec[index].clone());
            beta_randomness_vec_to_test.push(p2d.beta_randomness_vec[index].clone());
        }

        let local_state = LocalStatePhase5 {
            k: p1d.sign_keys.k_i.clone(),
            k_randomness: p1d.randomness.clone(),
            gamma: p1d.sign_keys.gamma_i.clone(),
            beta_randomness: beta_randomness_vec_to_test,
            beta_tag: beta_tag_vec_to_test,
            encryption_key: self.keyshare.paillier_key_vec[self.keyshare.party_index - 1].clone(),
        };
        local_state_vec.push(local_state);

        //g_gamma_vec:
        let g_gamma_vec = (0..p4d.decommit_vec.len())
            .map(|i| p4d.decommit_vec[i].g_gamma_i.clone())
            .collect::<Vec<Point<Secp256k1>>>();
        //m_a_vec
        let m_a_vec = (0..p1d.m_a_vec.len())
            .map(|i| p1d.m_a_vec[i].clone())
            .collect::<Vec<MessageA>>();
        // reduce ek vec to only ek of participants :
        let paillier_key_vector = (0..THRESHOLD)
            .map(|k| self.keyshare.paillier_key_vec[k].clone())
            .collect::<Vec<EncryptionKey>>();

        let global_state = GlobalStatePhase5::local_state_to_global_state(
            &paillier_key_vector[..],
            &p3d.delta_vec,
            &g_gamma_vec[..],
            &m_a_vec[..],
            p2d.m_b_gamma_all_mtx.clone(),
            &local_state_vec[..]
        );
        match global_state.phase5_blame() {
            Ok(_) => error!("Unable to determine blame during phase5"),
            Err(err) => error!("Assigned blame to signer(s): {:?}", err),
        };
    }

    #[instrument(skip_all)]
    fn phase5(
        &self,
        signers_vec: &Vec<usize>,
        p1d: &Phase1Data,
        p2d: &Phase2Data,
        p3d: &Phase3Data,
        p4d: &Phase4Data
    ) -> anyhow::Result<Phase5Data> {
        let R_dash = &p4d.R * &p1d.sign_keys.k_i;
        let R_dash_vec = self.phase5_broadcast_rdash(&R_dash)?;

        // phase 5
        let mut phase5_proofs: Vec<PDLwSlackProof> = Vec::new();
        for i in 0..THRESHOLD {
            if i == self.party_info.id_in_session {
                continue;
            }
            let proof = LocalSignature::phase5_proof_pdl(
                &R_dash,
                &p4d.R,
                &p1d.m_a_k.c,
                &self.keyshare.paillier_key_vec[self.keyshare.party_index - 1],
                &p1d.sign_keys.k_i,
                &p1d.randomness,
                &self.keyshare.h1_h2_N_tilde_vec[signers_vec[i]].clone().into() // changed from dlog_statement_vec
            );

            phase5_proofs.push(proof);
        }

        LocalSignature::phase5_verify_pdl(
            &phase5_proofs,
            &R_dash,
            &p4d.R,
            &p1d.m_a_k.c,
            &self.keyshare.paillier_key_vec[self.keyshare.party_index - 1],
            &self.keyshare.h1_h2_N_tilde_vec.iter().cloned().map_into().collect::<Vec<_>>(),
            &signers_vec,
            self.party_info.id_in_session
        ).map_err(|err| anyhow!("{:?}", err))?;

        match LocalSignature::phase5_check_R_dash_sum(&R_dash_vec) {
            Ok(_) => {}
            Err(_) => {
                error!("Phase5 R_dash sum check failed, initiating blame protocol");
                self.phase5_blame(p1d, p2d, p3d, p4d);
            }
        }

        Ok(Phase5Data { R_dash_vec })
    }

    #[instrument(skip_all)]
    fn phase6_broadcast(
        &self,
        S_i: &Point<Secp256k1>,
        zk_proof: &HomoELGamalProof<Secp256k1, Sha256>,
        R: &Point<Secp256k1>
    ) -> anyhow::Result<
        (Vec<Point<Secp256k1>>, Vec<HomoELGamalProof<Secp256k1, Sha256>>, Vec<Point<Secp256k1>>)
    > {
        let mesg = ecdsa::Phase6Broadcast {
            sender_id: self.party_info.id_in_session,
            s: S_i.clone(),
            r: R.clone(),
            zk_proof: zk_proof.clone(),
        };
        let json = serde_json::to_string(&mesg).unwrap();
        info!("publish on subject {} ", &self.phases[6].topic);
        self.connection.publish(&self.phases[6].topic, &json).unwrap();

        let mut S_vec: Vec<Point<Secp256k1>> = vec![];
        let mut R_vec: Vec<Point<Secp256k1>> = vec![];
        let mut zk_proof_vec: Vec<HomoELGamalProof<Secp256k1, Sha256>> = vec![];
        info!("collect Phase6Broadcast");
        for msg in collect_messages_ordered::<ecdsa::Phase6Broadcast>(
            &self.phases[6].sub,
            THRESHOLD
        )? {
            S_vec.push(msg.s);
            R_vec.push(msg.r);
            zk_proof_vec.push(msg.zk_proof);
        }
        Ok((S_vec, zk_proof_vec, R_vec))
    }

    #[instrument(skip_all)]
    fn phase6_blame(
        &self,
        S_i: &Point<Secp256k1>,
        S_vec: &Vec<Point<Secp256k1>>,
        signers_vec: &Vec<usize>,
        p1d: &Phase1Data,
        p2d: &Phase2Data,
        p3d: &Phase3Data,
        p4d: &Phase4Data
    ) {
        // initiate phase 6 blame protocol to learn which parties acted maliciously.
        // each party generates local state and share with other parties.
        // assuming sync communication - if a message was failed to arrive from a party -
        // this party should automatically be blamed
        let proof = GlobalStatePhase6::ecddh_proof(&p3d.sigma, &p4d.R, S_i);

        let mut miu_randomness_vec = Vec::new();
        for j in 0..THRESHOLD - 1 {
            let rand = GlobalStatePhase6::extract_paillier_randomness(
                &p2d.m_b_w_rec_vec[j].c,
                &self.keyshare.paillier_dk
            );
            miu_randomness_vec.push(rand);
        }

        let mut local_state_vec = Vec::new();
        let local_state = LocalStatePhase6 {
            k: p1d.sign_keys.k_i.clone(),
            k_randomness: p1d.randomness.clone(),
            miu: p2d.miu_bigint_vec.clone(), // TODO: de we need to also somehow include the local Mpz?
            miu_randomness: miu_randomness_vec,
            proof_of_eq_dlog: proof,
        };
        local_state_vec.push(local_state);

        //m_a_vec
        let m_a_vec = (0..p1d.m_a_vec.len())
            .map(|i| p1d.m_a_vec[i].clone())
            .collect::<Vec<MessageA>>();

        // reduce ek vec to only ek of participants :
        let ek_vec = (0..THRESHOLD)
            .map(|k| self.keyshare.paillier_key_vec[signers_vec[k]].clone())
            .collect::<Vec<EncryptionKey>>();

        let global_state = GlobalStatePhase6::local_state_to_global_state(
            &ek_vec[..],
            &S_vec[..],
            &p1d.g_w_vec[..],
            &m_a_vec[..],
            p2d.m_b_w_all_mtx.clone(),
            &local_state_vec[..]
        );
        //changed this to R, as it seems to just use a generic R by calling R_vec[0]
        match global_state.phase6_blame(&p4d.R) {
            Ok(_) => error!("Unable to determine blame during phase6"),
            Err(err) => error!("Assigned blame to signer(s): {:?}", err),
        }
    }

    fn phase6(
        &self,
        signers_vec: &Vec<usize>,
        p1d: &Phase1Data,
        p2d: &Phase2Data,
        p3d: &Phase3Data,
        p4d: &Phase4Data
    ) -> anyhow::Result<Phase6Data> {
        let (S_i, zk_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
            &p4d.R,
            &p3d.T_i,
            &p3d.sigma,
            &p3d.l_i
        );

        let (S_vec, zk_proof_vec, R_vec) = self.phase6_broadcast(&S_i, &zk_proof, &p4d.R)?;
        LocalSignature::phase6_verify_proof(&S_vec, &zk_proof_vec, &R_vec, &p3d.T_vec).map_err(|err|
            anyhow!("{:?}", err)
        )?;

        match LocalSignature::phase6_check_S_i_sum(&self.keyshare.y_sum, &S_vec) {
            Ok(_) => {}
            Err(_) => {
                info!("Phase6 S_i sum check failed, initiating blame protocol");
                self.phase6_blame(&S_i, &S_vec, signers_vec, p1d, p2d, p3d, p4d);
            }
        }

        Ok(Phase6Data { S_vec })
    }

    #[instrument(skip_all)]
    fn phase7_broadcast_signature(
        &self,
        signature: &LocalSignature
    ) -> anyhow::Result<Vec<LocalSignature>> {
        let mesg = ecdsa::Phase7Signature {
            sender_id: self.party_info.id_in_session,
            signature: signature.clone(),
        };
        let json = serde_json::to_string(&mesg).unwrap();
        info!("publish subject {}", &self.phases[7].topic);
        info!("About to publish message: {json}");
        self.connection.publish(&self.phases[7].topic, &json)?;
        info!("collect Phase7Signature");
        Ok(
            collect_messages_ordered::<ecdsa::Phase7Signature>(&self.phases[7].sub, THRESHOLD)?
                .into_iter()
                .map(|p7s| p7s.signature)
                .collect()
        )
    }

    #[instrument(skip_all)]
    fn phase7_blame(
        &self,
        s_vec: Vec<Scalar<Secp256k1>>,
        local_sig_vec: &Vec<LocalSignature>,
        p5d: &Phase5Data,
        p6d: &Phase6Data
    ) {
        let global_state = GlobalStatePhase7 {
            s_vec,
            r: local_sig_vec[0].r.clone(),
            R_dash_vec: p5d.R_dash_vec.clone(),
            m: local_sig_vec[0].m.clone(),
            R: local_sig_vec[0].R.clone(),
            S_vec: p6d.S_vec.clone(),
        };
        match global_state.phase7_blame() {
            Ok(_) => error!("Unable to determine blame during phase7"),
            Err(err) => error!("Assigned blame to signer(s): {:?}", err),
        }
    }

    #[instrument(skip_all)]
    fn phase7(
        &self,
        p1d: &Phase1Data,
        p3d: &Phase3Data,
        p4d: &Phase4Data,
        p5d: &Phase5Data,
        p6d: &Phase6Data
    ) -> anyhow::Result<Phase7Data> {
        let message_bn: BigInt = BigInt::from_bytes(&self.party_info.message[..]);
        let mut s_vec: Vec<Scalar<Secp256k1>> = Vec::new();

        let local_sig = LocalSignature::phase7_local_sig(
            &p1d.sign_keys.k_i,
            &message_bn,
            &p4d.R,
            &p3d.sigma,
            &self.keyshare.y_sum
        );

        // TODO: BROADCAST local_sig.s_i
        let local_sig_vec = self.phase7_broadcast_signature(&local_sig)?;

        // sum the s_i's
        for i in 0..THRESHOLD {
            if i != self.party_info.id_in_session {
                s_vec.push(local_sig_vec[i].s_i.clone());
            } else {
                s_vec.push(local_sig.s_i.clone());
            }
        }

        let sig = match local_sig_vec[0].output_signature(&s_vec[1..]) {
            Ok(val) => val,
            Err(_) => {
                error!("Failed to output signature during phase7, initiating blame protocol");
                self.phase7_blame(s_vec, &local_sig_vec, p5d, p6d);

                // phase7_blame calls panic! already, we need this so the type checker won't complain
                panic!();
            }
        };

        Ok(Phase7Data {
            local_sig_vec,
            sig,
            message_bn,
        })
    }

    fn check_sig(
        r: &Scalar<Secp256k1>,
        s: &Scalar<Secp256k1>,
        msg: &BigInt,
        pk: &Point<Secp256k1>
    ) -> anyhow::Result<()> {
        use secp256k1::{ Message, PublicKey, Secp256k1, Signature };

        let raw_msg = BigInt::to_bytes(&msg);
        if raw_msg.len() > 32 {
            panic!("Message longer then 32 bytes! msg: {:?}", raw_msg);
        }

        let mut msg: Vec<u8> = Vec::new(); // padding
        msg.extend(vec![0u8; 32 - raw_msg.len()]);
        msg.extend(raw_msg.iter());

        let msg = Message::from_slice(msg.as_slice())?;
        let mut raw_pk = pk.to_bytes(false).to_vec();
        if raw_pk.len() == 64 {
            raw_pk.insert(0, 4u8);
        }
        let pk = PublicKey::from_slice(&raw_pk)?;

        let mut compact: Vec<u8> = Vec::new();
        let bytes_r = &r.to_bytes()[..];
        compact.extend(vec![0u8; 32 - bytes_r.len()]);
        compact.extend(bytes_r.iter());

        let bytes_s = &s.to_bytes()[..];
        compact.extend(vec![0u8; 32 - bytes_s.len()]);
        compact.extend(bytes_s.iter());

        let secp_sig = Signature::from_compact(compact.as_slice())?;

        Ok(Secp256k1::new().verify(&msg, &secp_sig, &pk)?)
    }

    #[instrument(skip_all)]
    fn send_result(&mut self, p7d: &Phase7Data) -> anyhow::Result<()> {
        let subject = format_session_subject(&self.session, "result");
        let mesg = signature_recid_to_signing_result(&p7d.sig);

        let json = serde_json::to_string(&mesg)?;
        self.connection.publish(&subject, &json)?;

        info!("Signing session result sent by node #{}!", self.party_info.id_in_session);
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn sign(&mut self) -> anyhow::Result<()> {
        info!("waiting for START message from communication-hub");
        self.wait_for_start_message();
        info!("calling phase 0");
        let signers = self.phase0__exchange_party_ids()?;
        info!("calling phase 1");
        let p1d = self.phase1(&signers)?;
        info!("calling phase 2");
        let p2d = self.phase2(&signers, &p1d)?;
        info!("calling phase 3");
        let p3d = self.phase3(&p1d, &p2d)?;
        info!("calling phase 4");
        let p4d = self.phase4(&p1d, &p2d, &p3d)?;
        info!("calling phase 5");
        let p5d = self.phase5(&signers, &p1d, &p2d, &p3d, &p4d)?;
        info!("calling phase 6");
        let p6d = self.phase6(&signers, &p1d, &p2d, &p3d, &p4d)?;
        info!("calling phase 7");
        let p7d = self.phase7(&p1d, &p3d, &p4d, &p5d, &p6d)?;
        info!("checking signature");
        Self::check_sig(&p7d.sig.r, &p7d.sig.s, &p7d.message_bn, &self.keyshare.y_sum)?;
        info!("send result");
        self.send_result(&p7d)
    }
}

pub fn handle_new_session_message(app: &App, message: nats::Message) {
    let parsed_message = match serde_json::from_slice::<NewSignMessage>(&message.data[..]) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!("Failed to parse message: {}", err);
            return;
        }
    };
    // Validate security fields
    if
        parsed_message.timestamp.is_none() ||
        parsed_message.message_hmac.is_none() ||
        parsed_message.email.is_none()
    {
        error!("Missing required security fields: timestamp, message_hmac, or email");
        return;
    }

    let node = match NodeIdentity::load() {
        Ok(node) => node,
        Err(err) => {
            error!("Failed to load node identity: {}", err);
            return;
        }
    };

    let decrypted_signing_key = match
        e2e_decrypt(
            &parsed_message.encrypted_signing_key,
            &node.e2e_private_key,
            &parsed_message.client_e2e_public_key
        )
    {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to decrypt signing key: {}", err);
            return;
        }
    };

    let node_signing_key = match String::from_utf8(decrypted_signing_key) {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to convert decrypted signing key to string: {}", err);
            return;
        }
    };

    let message_hmac = parsed_message.message_hmac.as_ref().unwrap();
    let timestamp = parsed_message.timestamp.as_ref().unwrap();

    let email = parsed_message.email.unwrap_or_default();

    // Security verification: HMAC then timestamp
    if !verify_hmac(message_hmac, timestamp, &email, &node_signing_key) {
        error!("HMAC verification failed");
        return;
    }

    if !verify_timestamp(&parsed_message.key_id, timestamp, &email) {
        error!("Timestamp verification failed");
        return;
    }
    info!("Timestamp verified");

    // Transfer transaction validation
    if parsed_message.is_transfer_tx.unwrap_or(false) {
        info!("Initiating ownership transfer");

        let message_str = match String::from_utf8(parsed_message.message.clone()) {
            Ok(s) => s,
            Err(err) => {
                error!("Failed to convert message to string: {}", err);
                return;
            }
        };

        if !message_str.starts_with("Authorizing ownership transfer to ") {
            error!("Invalid transfer message format: {}", message_str);
            return;
        }

        let target_client_key = message_str.replace("Authorizing ownership transfer to ", "");

        let stored_identity = match KeyMetadataStore::get_user_level("new_identity_key", &email) {
            Ok(identity) => identity,
            Err(err) => {
                error!("Failed to retrieve identity using KeyMetadataStore: {}", err);
                return;
            }
        };

        if stored_identity.trim() != target_client_key.trim() {
            error!(
                "Transfer target mismatch. Expected: {}, Actual: {}",
                stored_identity.trim(),
                target_client_key.trim()
            );
            return;
        }

        info!("Matched user identity, proceeding with ownership transfer transaction");

        // Delete the new_identity_key file after successful verification
        if let Err(err) = KeyMetadataStore::remove_user_level("new_identity_key", &email) {
            error!("Failed to remove new_identity_key: {}", err);
            return;
        }

        info!("Successfully removed new_identity_key after ownership verification");
    }

    // Validate access key
    let saved_access_key = match KeyMetadataStore::get(&parsed_message.key_id, "access", &email) {
        Ok(key) => key,
        Err(err) => {
            error!("Failed to load saved access key: {}", err);
            return;
        }
    };

    if node_signing_key != saved_access_key {
        error!("Access key mismatch: decrypted key does not match saved access key");
        return;
    }

    // Store the client_e2e_public_key at user level
    if
        let Err(err) = KeyMetadataStore::save_user_level(
            &parsed_message.client_e2e_public_key,
            "e2e_key",
            &email,
            &WriteOpts::Modify
        )
    {
        error!("Failed to store client_e2e_public_key: {}", err);
        // Continue anyway as this is not critical
    }

    let session = NewSignSession {
        key_id: parsed_message.key_id,
        session_id: parsed_message.session_id,
        message: parsed_message.message,
    };

    // Create a new thread for this signing session
    info!("Spawning a thread to handle ECDSA signature generation");
    let app_clone = app.clone();
    let session_clone = session.clone();
    let thread_name = format!("sign_session_{}", session_clone.session_id);
    let session_id = session_clone.session_id.clone();
    match
        thread::Builder
            ::new()
            .name(thread_name)
            .spawn(move || {
                let mut sign_session = match
                    SignSession::new(app_clone.nc, session_clone, Some(email))
                {
                    Ok(ss) => ss,
                    Err(err) => {
                        error!("Error creating signing session: {}", err);
                        return;
                    }
                };
                match sign_session.sign() {
                    Ok(()) => {
                        info!("Signing completed successfully");
                    }
                    Err(err) => {
                        error!("Error in signing: {}", err);
                    }
                }
            })
    {
        Ok(_) => (),
        Err(err) => error!("Failed to spawn thread for signing session {}: {}", session_id, err),
    };
}

struct SignSession {
    connection: nats::Connection,
    start_phase: SignPhase,
    phases: Vec<SignPhase>,
    keyshare: ECDSA,
    party_info: JoinSignSessionResponse,
    session: NewSignSession,
}

// Verify that the timestamp is newer than the last one we've seen
fn verify_timestamp(key_id: &str, new_timestamp: &str, email: &str) -> bool {
    let timestamp_key = "timestamp";
    let new_dt = match DateTime::parse_from_rfc3339(new_timestamp) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(err) => {
            error!("Failed to parse timestamp: {}", err);
            return false;
        }
    };

    // It's fine if this fails - it just means first tx
    let previous_timestamp_result = KeyMetadataStore::get(key_id, timestamp_key, email);

    match previous_timestamp_result {
        Ok(prev_timestamp_str) => {
            let prev_dt = match DateTime::parse_from_rfc3339(&prev_timestamp_str) {
                Ok(dt) => dt.with_timezone(&Utc),
                Err(err) => {
                    error!("Failed to parse stored timestamp: {}", err);
                    return false;
                }
            };

            if new_dt <= prev_dt {
                error!(
                    "Timestamp validation failed: provided timestamp ({}) is not newer than stored timestamp ({})",
                    new_timestamp,
                    prev_timestamp_str
                );
                return false;
            }
        }
        Err(err) => {
            info!("No previous timestamp found, likely first transaction: {}", err);
        }
    }

    match KeyMetadataStore::save(new_timestamp, key_id, timestamp_key, email, &WriteOpts::Modify) {
        Ok(_) => true,
        Err(err) => {
            error!("Failed to save new timestamp: {}", err);
            false
        }
    }
}

// HMAC verification using SHA256(timestamp + email) with signing key
fn verify_hmac(provided_hmac: &str, timestamp: &str, email: &str, signing_key: &str) -> bool {
    type HmacSha256 = Hmac<Sha256>;
    let message_input = format!("{}{}", timestamp, email);

    let mut mac = match HmacSha256::new_from_slice(signing_key.as_bytes()) {
        Ok(m) => m,
        Err(err) => {
            error!("Failed to create HMAC instance: {}", err);
            return false;
        }
    };

    mac.update(message_input.as_bytes());
    let calculated_hmac_bytes = mac.finalize().into_bytes();

    // Use base64 encoding instead of hex to match TypeScript implementation
    let calculated_hmac = base64::encode(&calculated_hmac_bytes);

    if calculated_hmac != provided_hmac {
        error!("HMAC verification failed: expected {}, got {}", provided_hmac, calculated_hmac);
        return false;
    }

    true
}
