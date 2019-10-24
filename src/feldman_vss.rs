#![allow(non_snake_case)]
/// Copyright 2018 by Kzen Networks
// (https://github.com/KZen-networks/curv)
/// License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>

use mohan::dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint, 
    scalar::Scalar,
};
use bacteria::Transcript;
use serde::{Serialize, Deserialize};
use crate::SchnorrError;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ShamirSecretSharing {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}

/// Feldman VSS, based on  Paul Feldman. 1987. A practical scheme for non-interactive verifiable secret sharing.
/// In Foundations of Computer Science, 1987., 28th Annual Symposium on.IEEE, 427–43
///
/// implementation details: The code is using FE and GE. Each party is given an index from 1,..,n and a secret share of type FE.
/// The index of the party is also the point on the polynomial where we treat this number as u32 but converting it to FE internally.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct VerifiableSS {
    pub parameters: ShamirSecretSharing,
    pub commitments: Vec<RistrettoPoint>,
}

impl VerifiableSS {

    pub fn reconstruct_limit(&self) -> usize {
        self.parameters.threshold + 1
    }

    /// generate VerifiableSS from a secret
    pub fn share(t: usize, n: usize, secret: &Scalar) -> (VerifiableSS, Vec<Scalar>) {
        assert!(t < n);

        let poly = VerifiableSS::sample_polynomial(t, secret);

        let index_vec: Vec<usize> = (1..=n).collect();
        let secret_shares = VerifiableSS::evaluate_polynomial(&poly, &index_vec);

        let G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
        let commitments = (0..poly.len()).map(|i| G * poly[i]).collect::<Vec<RistrettoPoint>>();
        (
            VerifiableSS {
                parameters: ShamirSecretSharing {
                    threshold: t,
                    share_count: n,
                },
                commitments,
            },
            secret_shares,
        )
    }

    // generate VerifiableSS from a secret and user defined x values (in case user wants to distribute point f(1), f(4), f(6) and not f(1),f(2),f(3))
    pub fn share_at_indices(
        t: usize,
        n: usize,
        secret: &Scalar,
        index_vec: &[usize],
    ) -> (VerifiableSS, Vec<Scalar>) {
        assert_eq!(n, index_vec.len());
        let poly = VerifiableSS::sample_polynomial(t, secret);
        let secret_shares = VerifiableSS::evaluate_polynomial(&poly, index_vec);

        let G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
        let commitments = (0..poly.len())
            .map(|i| G.clone() * &poly[i])
            .collect::<Vec<RistrettoPoint>>();
        (
            VerifiableSS {
                parameters: ShamirSecretSharing {
                    threshold: t,
                    share_count: n,
                },
                commitments,
            },
            secret_shares,
        )
    }

    // returns vector of coefficients
    pub fn sample_polynomial(t: usize, coef0: &Scalar) -> Vec<Scalar> {
        let mut transcript = Transcript::new(b"VSS");
        //randomize transcript and commit private key
        let mut rng = transcript
            .build_rng()
            .rekey_with_witness_bytes(b"coef0", &coef0.to_bytes())
            .finalize(&mut mohan::mohan_rand());

        let mut coefficients = vec![*coef0];
        // sample the remaining coefficients randomly using secure randomness
        let random_coefficients: Vec<Scalar> = (0..t).map(|_| Scalar::random(&mut rng)).collect();
        coefficients.extend(random_coefficients);
        // return
        coefficients
    }

    pub fn evaluate_polynomial(coefficients: &[Scalar], index_vec: &[usize]) -> Vec<Scalar> {
        (0..index_vec.len())
            .map(|point| {
                //let point_bn = BigInt::from(index_vec[point] as u32);

                VerifiableSS::mod_evaluate_polynomial(coefficients, Scalar::from(index_vec[point] as u32))
            })
            .collect::<Vec<Scalar>>()
    }

    pub fn mod_evaluate_polynomial(coefficients: &[Scalar], point: Scalar) -> Scalar {
        // evaluate using Horner's rule
        //  - to combine with fold we consider the coefficients in reverse order
        let mut reversed_coefficients = coefficients.iter().rev();
        // manually split due to fold insisting on an initial value
        let head = reversed_coefficients.next().unwrap();
        let tail = reversed_coefficients;
        tail.fold(head.clone(), |partial, coef| {
            let partial_times_point = partial * &point;
            partial_times_point + coef 
        })
    }

    pub fn reconstruct(&self, indices: &[usize], shares: &[Scalar]) -> Scalar {
        assert_eq!(shares.len(), indices.len());
        assert!(shares.len() >= self.reconstruct_limit());
        // add one to indices to get points
        let points = indices
            .iter()
            .map(|i| {
                let index_bn = i + 1;
                Scalar::from(index_bn as u32)
            })
            .collect::<Vec<Scalar>>();
        VerifiableSS::lagrange_interpolation_at_zero(&points, &shares)
    }

    /// Performs a Lagrange interpolation in field Zp at the origin
    /// for a polynomial defined by `points` and `values`.
    /// `points` and `values` are expected to be two arrays of the same size, containing
    /// respectively the evaluation points (x) and the value of the polynomial at those point (p(x)).
    /// The result is the value of the polynomial at x=0. It is also its zero-degree coefficient.
    /// This is obviously less general than `newton_interpolation_general` as we
    /// only get a single value, but it is much faster.
    pub fn lagrange_interpolation_at_zero(points: &[Scalar], values: &[Scalar]) -> Scalar {
        let vec_len = values.len();

        assert_eq!(points.len(), vec_len);
        // Lagrange interpolation for point 0
        // let mut acc = 0i64;
        let lag_coef =
            (0..vec_len)
                .map(|i| {
                    let xi = &points[i];
                    let yi = &values[i];
                    let num: Scalar = Scalar::one();
                    let denum: Scalar = Scalar::one();
                    let num = points.iter().zip(0..vec_len).fold(num, |acc, x| {
                        if i != x.1 {
                            acc * x.0
                        } else {
                            acc
                        }
                    });
                    let denum = points.iter().zip(0..vec_len).fold(denum, |acc, x| {
                        if i != x.1 {
                            let xj_sub_xi = x.0 - xi;
                            acc * xj_sub_xi
                        } else {
                            acc
                        }
                    });
                    let denum = denum.invert();
                    num * denum * yi
                })
                .collect::<Vec<Scalar>>();
        let mut lag_coef_iter = lag_coef.iter();
        let head = lag_coef_iter.next().unwrap();
        let tail = lag_coef_iter;
        tail.fold(head.clone(), |acc, x| acc + x)
    }

    pub fn validate_share(&self, secret_share: &Scalar, index: usize) -> Result<(), SchnorrError> {
        let G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
        let ss_point = G * secret_share;
        self.validate_share_public(&ss_point, index)
    }

    pub fn validate_share_public(&self, ss_point: &RistrettoPoint, index: usize) -> Result<(), SchnorrError> {
        let comm_to_point = self.get_point_commitment(index);
        if *ss_point == comm_to_point {
            Ok(())
        } else {
            Err(SchnorrError::VerifyShareError)
        }
    }

    pub fn get_point_commitment(&self, index: usize) -> RistrettoPoint {
        let index_fe: Scalar = Scalar::from(index as u32);
        let mut comm_iterator = self.commitments.iter().rev();
        let head = comm_iterator.next().unwrap();
        let tail = comm_iterator;
        let comm_to_point = tail.fold(head.clone(), |acc, x: &RistrettoPoint| *x + acc * index_fe);
        comm_to_point
    }

    //compute \lambda_{index,S}, a lagrangian coefficient that change the (t,n) scheme to (|S|,|S|)
    // used in http://stevengoldfeder.com/papers/GG18.pdf
    pub fn map_share_to_new_params(&self, index: usize, s: &[usize]) -> Scalar {
        let s_len = s.len();
        //     assert!(s_len > self.reconstruct_limit());
        // add one to indices to get points
        let points: Vec<Scalar> = (0..self.parameters.share_count)
            .map(|i| {
                let index_bn = i as u32 + 1 as u32;
                Scalar::from(index_bn)
            })
            .collect::<Vec<Scalar>>();

        let xi = &points[index];
        let num: Scalar = Scalar::one();
        let denum: Scalar = Scalar::one();
        let num = (0..s_len).fold(num, |acc, i| {
            if s[i] != index {
                acc * points[s[i]]
            } else {
                acc
            }
        });
        let denum = (0..s_len).fold(denum, |acc, i| {
            if s[i] != index {
                let xj_sub_xi = points[s[i]] - xi;
                acc * xj_sub_xi
            } else {
                acc
            }
        });
        let denum = denum.invert();
        num * denum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_sharing_3_out_of_5_at_indices() {
        let mut transcript = Transcript::new(b"VSS");
        //randomize transcript and commit private key
        let mut rng = transcript
            .build_rng()
            .finalize(&mut mohan::mohan_rand());

        let secret: Scalar = Scalar::random(&mut rng);
        let parties = [1, 2, 4, 5, 6];
        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(3, 5, &secret, &parties);

        let mut shares_vec = Vec::new();
        shares_vec.push(secret_shares[0].clone());
        shares_vec.push(secret_shares[1].clone());
        shares_vec.push(secret_shares[3].clone());
        shares_vec.push(secret_shares[4].clone());
        //test reconstruction

        let secret_reconstructed = vss_scheme.reconstruct(&vec![0, 1, 4, 5], &shares_vec);
        assert_eq!(secret, secret_reconstructed);
    }

    #[test]
    fn test_secret_sharing_3_out_of_5() {
        let mut transcript = Transcript::new(b"VSS");
        //randomize transcript and commit private key
        let mut rng = transcript
            .build_rng()
            .finalize(&mut mohan::mohan_rand());

        let secret: Scalar = Scalar::random(&mut rng);

        let (vss_scheme, secret_shares) = VerifiableSS::share(3, 5, &secret);

        let mut shares_vec = Vec::new();
        shares_vec.push(secret_shares[0].clone());
        shares_vec.push(secret_shares[1].clone());
        shares_vec.push(secret_shares[2].clone());
        shares_vec.push(secret_shares[4].clone());
        //test reconstruction

        let secret_reconstructed = vss_scheme.reconstruct(&vec![0, 1, 2, 4], &shares_vec);

        assert_eq!(secret, secret_reconstructed);
        // test secret shares are verifiable
        let valid3 = vss_scheme.validate_share(&secret_shares[2], 3);
        let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
        assert!(valid3.is_ok());
        assert!(valid1.is_ok());

        let g: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
        let share1_public = g * &secret_shares[0];
        let valid1_public = vss_scheme.validate_share_public(&share1_public, 1);
        assert!(valid1_public.is_ok());

        // test map (t,n) - (t',t')
        let s = &vec![0, 1, 2, 3, 4];
        let l0 = vss_scheme.map_share_to_new_params(0, &s);
        let l1 = vss_scheme.map_share_to_new_params(1, &s);
        let l2 = vss_scheme.map_share_to_new_params(2, &s);
        let l3 = vss_scheme.map_share_to_new_params(3, &s);
        let l4 = vss_scheme.map_share_to_new_params(4, &s);
        let w = l0 * secret_shares[0].clone()
            + l1 * secret_shares[1].clone()
            + l2 * secret_shares[2].clone()
            + l3 * secret_shares[3].clone()
            + l4 * secret_shares[4].clone();
        assert_eq!(w, secret_reconstructed);
    }

    #[test]
    fn test_secret_sharing_3_out_of_7() {
         let mut transcript = Transcript::new(b"VSS");
        //randomize transcript and commit private key
        let mut rng = transcript
            .build_rng()
            .finalize(&mut mohan::mohan_rand());

        let secret: Scalar = Scalar::random(&mut rng);

        let (vss_scheme, secret_shares) = VerifiableSS::share(3, 7, &secret);

        let mut shares_vec = Vec::new();
        shares_vec.push(secret_shares[0].clone());
        shares_vec.push(secret_shares[6].clone());
        shares_vec.push(secret_shares[2].clone());
        shares_vec.push(secret_shares[4].clone());

        //test reconstruction
        let secret_reconstructed = vss_scheme.reconstruct(&vec![0, 6, 2, 4], &shares_vec);
        assert_eq!(secret, secret_reconstructed);

        // test secret shares are verifiable
        let valid3 = vss_scheme.validate_share(&secret_shares[2], 3);
        let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
        assert!(valid3.is_ok());
        assert!(valid1.is_ok());

        // test map (t,n) - (t',t')
        let s = &vec![0, 1, 3, 4, 6];
        let l0 = vss_scheme.map_share_to_new_params(0, &s);
        let l1 = vss_scheme.map_share_to_new_params(1, &s);
        let l3 = vss_scheme.map_share_to_new_params(3, &s);
        let l4 = vss_scheme.map_share_to_new_params(4, &s);
        let l6 = vss_scheme.map_share_to_new_params(6, &s);
        let w = l0 * secret_shares[0].clone()
            + l1 * secret_shares[1].clone()
            + l3 * secret_shares[3].clone()
            + l4 * secret_shares[4].clone()
            + l6 * secret_shares[6].clone();
        assert_eq!(w, secret_reconstructed);
    }

    #[test]
    fn test_secret_sharing_1_out_of_2() {
         let mut transcript = Transcript::new(b"VSS");
        //randomize transcript and commit private key
        let mut rng = transcript
            .build_rng()
            .finalize(&mut mohan::mohan_rand());

        let secret: Scalar = Scalar::random(&mut rng);

        let (vss_scheme, secret_shares) = VerifiableSS::share(1, 2, &secret);

        let mut shares_vec = Vec::new();
        shares_vec.push(secret_shares[0].clone());
        shares_vec.push(secret_shares[1].clone());

        //test reconstruction
        let secret_reconstructed = vss_scheme.reconstruct(&vec![0, 1], &shares_vec);
        assert_eq!(secret, secret_reconstructed);

        // test secret shares are verifiable
        let valid2 = vss_scheme.validate_share(&secret_shares[1], 2);
        let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
        assert!(valid2.is_ok());
        assert!(valid1.is_ok());

        // test map (t,n) - (t',t')
        let s = &vec![0, 1];
        let l0 = vss_scheme.map_share_to_new_params(0, &s);
        let l1 = vss_scheme.map_share_to_new_params(1, &s);

        let w = l0 * secret_shares[0].clone() + l1 * secret_shares[1].clone();
        assert_eq!(w, secret_reconstructed);
    }

    #[test]
    fn test_secret_sharing_1_out_of_3() {
        let mut transcript = Transcript::new(b"VSS");
        //randomize transcript and commit private key
        let mut rng = transcript
            .build_rng()
            .finalize(&mut mohan::mohan_rand());

        let secret: Scalar = Scalar::random(&mut rng);

        let (vss_scheme, secret_shares) = VerifiableSS::share(1, 3, &secret);

        let mut shares_vec = Vec::new();
        shares_vec.push(secret_shares[0].clone());
        shares_vec.push(secret_shares[1].clone());

        // test commitment to point and sum of commitments
        let (vss_scheme2, secret_shares2) = VerifiableSS::share(1, 3, &secret);
        let sum = secret_shares[0].clone() + secret_shares2[0].clone();
        let point_comm1 = vss_scheme.get_point_commitment(1);
        let point_comm2 = vss_scheme.get_point_commitment(2);
        let g: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
        let g_sum = g.clone() * &sum;
        assert_eq!(g.clone() * secret_shares[0].clone(), point_comm1.clone());
        assert_eq!(g.clone() * secret_shares[1].clone(), point_comm2.clone());
        let point1_sum_com =
            vss_scheme.get_point_commitment(1) + vss_scheme2.get_point_commitment(1);
        assert_eq!(point1_sum_com, g_sum);

        //test reconstruction
        let secret_reconstructed = vss_scheme.reconstruct(&vec![0, 1], &shares_vec);
        assert_eq!(secret, secret_reconstructed);

        // test secret shares are verifiable
        let valid2 = vss_scheme.validate_share(&secret_shares[1], 2);
        let valid1 = vss_scheme.validate_share(&secret_shares[0], 1);
        assert!(valid2.is_ok());
        assert!(valid1.is_ok());

        // test map (t,n) - (t',t')
        let s = &vec![0, 2];
        let l0 = vss_scheme.map_share_to_new_params(0, &s);
        let l2 = vss_scheme.map_share_to_new_params(2, &s);

        let w = l0 * secret_shares[0].clone() + l2 * secret_shares[2].clone();
        assert_eq!(w, secret_reconstructed);
    }
}