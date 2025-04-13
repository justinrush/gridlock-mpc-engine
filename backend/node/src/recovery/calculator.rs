use anyhow::{ anyhow, bail, Result };
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing,
    VerifiableSS,
};
use curv::elliptic::curves::{ Curve, Point, Scalar };
use curv::BigInt;
use itertools::Itertools;

use crate::recovery::Party;

pub struct LinearShareParts<C> where C: Curve {
    pub retained: Scalar<C>,
    pub for_peer_exchange: Vec<Scalar<C>>,
}

pub struct RecoveryCalculator<C> where C: Curve {
    pub recovery_index: usize,
    pub party: Party,
    pub threshold: usize,
    pub secret_share: Scalar<C>,
}

impl<C> RecoveryCalculator<C> where C: Curve {
    pub fn new(
        recovery_index: usize,
        party_index: usize,
        all_parties: Vec<usize>,
        threshold: usize,
        secret_share: Scalar<C>
    ) -> Self {
        Self {
            recovery_index,
            party: Party {
                party_index,
                all_parties,
            },
            threshold,
            secret_share,
        }
    }

    pub fn create_secret_sharing_of_lost_share(&self) -> LinearShareParts<C> {
        let li = Self::map_share_to_new_params_for_x(
            self.recovery_index.into(),
            self.party.party_index.into(),
            &self.party.all_parties
        );
        let lc = self.secret_share.clone() * li;

        Self::create_linear_shares_of_scalar(lc, self.threshold)
    }

    pub fn create_secret_sharing_of_zero_point(&self) -> LinearShareParts<C> {
        let sss_params = ShamirSecretSharing {
            threshold: self.threshold as u16,
            share_count: 5,
        };
        let all_parties = &*self.party.all_parties
            .iter()
            .map(|&i| i as u16)
            .collect_vec();
        let li = VerifiableSS::<C>::map_share_to_new_params(
            &sss_params,
            self.party.party_index as u16,
            all_parties
        );

        let lc = self.secret_share.clone() * li;

        Self::create_linear_shares_of_scalar(lc, self.threshold)
    }

    fn create_linear_shares_of_scalar(
        scalar: Scalar<C>,
        num_of_shares: usize
    ) -> LinearShareParts<C> {
        let mut rij: Vec<Scalar<C>> = Vec::new();
        for _ in 0..num_of_shares {
            rij.push(Scalar::<C>::random());
        }

        let rij_sum = rij.iter().sum();

        let rii = scalar - &rij_sum;

        LinearShareParts {
            retained: rii,
            for_peer_exchange: rij,
        }
    }

    pub fn sum_secret_shares(&self, rii: Scalar<C>, mixed_shares: Vec<Scalar<C>>) -> Scalar<C> {
        mixed_shares.iter().sum::<Scalar<_>>() + rii
    }

    pub fn validate_recovered_share(
        secret: &Scalar<C>,
        vss: &Vec<VerifiableSS<C>>,
        index: usize
    ) -> Result<()> {
        let mut vss_iter = vss.iter();
        let head = vss_iter
            .next()
            .unwrap()
            .get_point_commitment(index as u16);
        let tail = vss_iter;
        let point_commitment_sum = tail.fold(head.clone(), |acc, x| {
            acc + x.get_point_commitment(index as u16)
        });
        let public_point = Point::generator() * secret.clone();
        match public_point == point_commitment_sum {
            true => Ok(()),
            false => bail!("Recovered key share did not pass validation"),
        }
    }

    pub fn calculate_y_sum_from_vss_vec(vss_vec: &Vec<VerifiableSS<C>>) -> Result<Point<C>> {
        let mut vss_iter = vss_vec.iter();

        let add_to_sum = |sum: Point<C>, x: &VerifiableSS<C>| -> Result<Point<C>> {
            let new_p = x.commitments.iter().nth(0).ok_or(anyhow!("VSS commitments empty"))?;
            Ok(sum + new_p.clone())
        };

        let head = vss_iter
            .next()
            .ok_or(anyhow!("VSS empty"))?
            .commitments.iter()
            .nth(0)
            .ok_or(anyhow!("VSS commitments empty"))?;
        let mut tail = vss_iter;
        let y_sum_from_vss = tail.try_fold(head.clone(), |acc, x| add_to_sum(acc, x))?;

        Ok(y_sum_from_vss)
    }

    pub fn calculate_y_sum_from_single_vss(vss: &VerifiableSS<C>) -> Result<Point<C>> {
        let y_sum_from_vss = vss.commitments.iter().nth(0).ok_or(anyhow!("VSS commitments empty"))?;
        Ok(y_sum_from_vss.clone())
    }

    pub fn map_share_to_new_params_for_x(x_index: usize, index: usize, s: &[usize]) -> Scalar<C> {
        let s_len = s.len();
        let mut all_indices = s.to_vec();
        all_indices.push(index);
        all_indices.push(x_index);

        let max_index = all_indices.iter().max().unwrap();

        let points: Vec<Scalar<C>> = (0..=*max_index)
            .map(|i| {
                let index_bn = BigInt::from((i + 1) as u32);
                Scalar::from(&index_bn)
            })
            .collect::<Vec<Scalar<C>>>();

        let x = &points[x_index];
        let xi = &points[index];
        let num = Scalar::from(&BigInt::from(1u32));
        let denum = Scalar::from(&BigInt::from(1u32));
        let num = (0..s_len).fold(num, |acc, i| {
            if s[i] != index {
                let xj_sub_x = points[s[i]].clone() - x;
                acc * xj_sub_x
            } else {
                acc
            }
        });
        let denum = (0..s_len).fold(denum, |acc, i| {
            if s[i] != index {
                let xj_sub_xi = points[s[i]].clone() - xi;
                acc * xj_sub_xi
            } else {
                acc
            }
        });
        let denum = denum.invert().expect("Denum is not zero");
        num * denum
    }
}

#[derive(Clone, Debug)]
pub struct KeyshareRecoverySession {
    pub session_id: String,
    pub key_ids: Vec<String>,
    pub public_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::elliptic::curves::{ Ed25519, Secp256k1 };

    #[test]
    fn twofa_owner_having_zero_point_is_feasible_eddsa() {
        can_recover_secret_at_zero_index::<Ed25519>();
    }

    fn can_recover_secret_at_zero_index<C>() where C: Curve {
        let secret = Scalar::<C>::random();
        let (_, secret_shares) = VerifiableSS::<C>::share_at_indices(
            2,
            5,
            &secret,
            &[0, 1, 2, 3, 4]
        );

        let recovered_secret = three_of_five_recovery::<C>(0, vec![1, 2, 3], &secret_shares);
        assert_eq!(recovered_secret.to_bigint(), secret_shares[0].to_bigint());

        let recovered_secret = three_of_five_recovery::<C>(0, vec![1, 2, 4], &secret_shares);
        assert_eq!(recovered_secret.to_bigint(), secret_shares[0].to_bigint());

        let recovered_secret = three_of_five_recovery::<C>(0, vec![2, 3, 4], &secret_shares);
        assert_eq!(recovered_secret.to_bigint(), secret_shares[0].to_bigint())
    }

    #[test]
    fn can_recover_secret_eddsa() {
        can_recover_secret_over_multiple_permutations::<Ed25519>();
    }

    #[test]
    fn can_recover_secret_ecdsa() {
        can_recover_secret_over_multiple_permutations::<Secp256k1>();
    }

    fn can_recover_secret_over_multiple_permutations<C>() where C: Curve {
        let secret = Scalar::<C>::random();
        let (_, secret_shares) = VerifiableSS::<C>::share(2, 5, &secret);

        let recovered_secret = three_of_five_recovery::<C>(4, vec![0, 1, 2], &secret_shares);
        assert_eq!(recovered_secret.to_bigint(), secret_shares[4].to_bigint());

        let recovered_secret = three_of_five_recovery::<C>(0, vec![1, 4, 3], &secret_shares);
        assert_eq!(recovered_secret.to_bigint(), secret_shares[0].to_bigint());

        let recovered_secret = three_of_five_recovery::<C>(3, vec![1, 4, 2], &secret_shares);
        assert_eq!(recovered_secret.to_bigint(), secret_shares[3].to_bigint())
    }

    fn three_of_five_recovery<C>(
        recovery_index: usize,
        party_num_vec: Vec<usize>,
        secret_shares: &[Scalar<C>]
    ) -> Scalar<C>
        where C: Curve
    {
        let threshold = 2;

        let recoverer_1 = RecoveryCalculator::<C>::new(
            recovery_index,
            party_num_vec[0],
            party_num_vec.clone(),
            threshold,
            secret_shares[party_num_vec[0]].clone()
        );

        let recoverer_2 = RecoveryCalculator::<C>::new(
            recovery_index,
            party_num_vec[1],
            party_num_vec.clone(),
            threshold,
            secret_shares[party_num_vec[1]].clone()
        );

        let recoverer_3 = RecoveryCalculator::<C>::new(
            recovery_index,
            party_num_vec[2],
            party_num_vec.clone(),
            threshold,
            secret_shares[party_num_vec[2]].clone()
        );

        let contrib1 = recoverer_1.create_secret_sharing_of_lost_share();
        let contrib2 = recoverer_2.create_secret_sharing_of_lost_share();
        let contrib3 = recoverer_3.create_secret_sharing_of_lost_share();

        let shares1 = contrib1.for_peer_exchange.clone();
        let shares2 = contrib2.for_peer_exchange.clone();
        let shares3 = contrib3.for_peer_exchange.clone();

        let recoverer1_shares = vec![shares2[1].clone(), shares3[0].clone()];
        let recoverer2_shares = vec![shares3[1].clone(), shares1[0].clone()];
        let recoverer3_shares = vec![shares1[1].clone(), shares2[0].clone()];

        let summed_shares_1 = recoverer_1.sum_secret_shares(contrib1.retained, recoverer1_shares);
        let summed_shares_2 = recoverer_2.sum_secret_shares(contrib2.retained, recoverer2_shares);
        let summed_shares_3 = recoverer_3.sum_secret_shares(contrib3.retained, recoverer3_shares);

        let all_shares = vec![summed_shares_1, summed_shares_2, summed_shares_3];

        all_shares.iter().sum()
    }
}
