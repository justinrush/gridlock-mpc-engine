use crate::communication::nats::PeerMessenger;
use crate::communication::protocol::{ AllRounds, KeySignEdDSAAllRounds };
use crate::keygen::eddsa::client::EphemeralEdDSAKey;
use crate::keygen::ShareParams;
use crate::signing::eddsa::SignatureResult;
use crate::storage::EDDSA;
use anyhow::anyhow;
use curv::elliptic::curves::{ Ed25519, Point, Scalar };
use itertools::Itertools;
use multi_party_eddsa::protocols::thresholdsig::{ EphemeralSharedKeys, LocalSig, SharedKeys };
use multi_party_eddsa::protocols::{ thresholdsig, Signature };
use tracing::info;

pub struct EdDSAKeySignClient<C> {
    pub peer_messenger: C,
    pub share_params: ShareParams,
    pub all_party_indices: Vec<usize>,
}

impl<C> EdDSAKeySignClient<C> where C: PeerMessenger<KeySignEdDSAAllRounds> {
    pub fn create_shared_sig(
        &self,
        message: &[u8],
        ephemeral_keyshare: &EphemeralEdDSAKey,
        keyshare: &EDDSA
    ) -> anyhow::Result<Signature> {
        let party_indices: Vec<usize> = self.all_party_indices
            .iter()
            .map(|x| x - 1)
            .collect();
        let local_sig = self.create_local_sig(
            message,
            &ephemeral_keyshare.shared_key,
            &keyshare.x_i,
            &keyshare.y_sum
        )?;
        info!("Local signature created successfully");
        let local_sigs = self.exchange_local_sigs(local_sig)?;
        info!("Exchanged local signatures");
        let party_indices = &*party_indices
            .iter()
            .map(|&i| i as u16)
            .collect_vec();
        let vss_sum_local_sigs = LocalSig::verify_local_sigs(
            &local_sigs,
            party_indices,
            &keyshare.vss_scheme_vec.iter().cloned().map_into().collect::<Vec<_>>(),
            &ephemeral_keyshare.vss_scheme_vec
        ).map_err(|_| anyhow!("Not able to verify party local signatures"))?;

        info!("Verified all local signatures");
        let signature = thresholdsig::generate(
            &vss_sum_local_sigs,
            &local_sigs,
            party_indices,
            ephemeral_keyshare.shared_key.R.clone()
        );

        signature
            .verify(message, &keyshare.y_sum)
            .map_err(|_| anyhow!("Signature did not pass verification"))?;
        info!("Full signature generated and verified");

        Ok(signature)
    }

    pub fn publish_result(&self, signature: SignatureResult) -> anyhow::Result<()> {
        let _ = self.peer_messenger.broadcast_and_collect_messages(
            &<KeySignEdDSAAllRounds as AllRounds>::BroadcastRound::Result,
            signature
        )?;
        Ok(())
    }

    fn create_local_sig(
        &self,
        message: &[u8],
        ephemeral_shared_key: &EphemeralSharedKeys,
        x_i: &Scalar<Ed25519>,
        y: &Point<Ed25519>
    ) -> anyhow::Result<LocalSig> {
        let shared_key = SharedKeys {
            y: y.clone(),
            x_i: x_i.clone(),
            prefix: Scalar::random(),
        };
        let local_sig = LocalSig::compute(message, ephemeral_shared_key, &shared_key);

        Ok(local_sig)
    }

    pub fn exchange_local_sigs(&self, local_sig: LocalSig) -> anyhow::Result<Vec<LocalSig>> {
        let local_sigs = self.peer_messenger.broadcast_and_collect_messages(
            &<KeySignEdDSAAllRounds as AllRounds>::BroadcastRound::LocalSig,
            local_sig
        )?;

        Ok(local_sigs)
    }
}
