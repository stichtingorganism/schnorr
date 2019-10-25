#![allow(non_snake_case)]
#[allow(unused_doc_comments)]
// Multisig Schnorr
// Copyright 2018 by Kzen Networks
// This file is part of Multisig Schnorr library
// (https://github.com/KZen-networks/multisig-schnorr)
// Multisig Schnorr is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
// @license GPL-3.0+ <https://github.com/KZen-networks/multisig-schnorr/blob/master/LICENSE>

use mohan::{
    mohan_rand,
    hash::{
        blake256,
        H256
    },
    dalek::{
        constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::{
            IsIdentity, 
            VartimeMultiscalarMul
        },
    }
};
use crate::{
    feldman_vss::{
        VerifiableSS,
        ShamirSecretSharing
    },
    SchnorrError
};
use serde::{ Serialize,Deserialize};



pub struct Keys {
    pub u_i: Scalar,
    pub y_i: RistrettoPoint,
    pub party_index: usize,
}


pub struct KeyGenBroadcastMessage1 {
    commitment: H256,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct SharedKeys {
    pub y: RistrettoPoint,
    pub x_i: Scalar
}


impl Keys {
    
    pub fn phase1_create(index: usize) -> Keys {
        let u: Scalar = Scalar::random(&mut mohan_rand());
        let y = RISTRETTO_BASEPOINT_POINT * u;

        Keys {
            u_i: u,
            y_i: y,
            party_index: index.clone(),
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenBroadcastMessage1, Scalar) {
        let blind_factor = Scalar::random(&mut mohan_rand());
        let mut buf = Vec::new();
        buf.extend_from_slice(self.y_i.compress().as_bytes());
        buf.extend_from_slice(blind_factor.as_bytes());
        let commitment = blake256(&buf);

        let bcm1 = KeyGenBroadcastMessage1 { commitment };
        (bcm1, blind_factor)
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &ShamirSecretSharing,
        blind_vec: &Vec<Scalar>,
        y_vec: &Vec<RistrettoPoint>,
        bc1_vec: &Vec<KeyGenBroadcastMessage1>,
        parties: &[usize],
    ) -> Result<(VerifiableSS, Vec<Scalar>, usize), SchnorrError> {
        // test length:
        assert_eq!(blind_vec.len(), params.share_count);
        assert_eq!(bc1_vec.len(), params.share_count);
        assert_eq!(y_vec.len(), params.share_count);

        // test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                let mut buf = Vec::new();
                buf.extend_from_slice(y_vec[i].compress().as_bytes());
                buf.extend_from_slice(blind_vec[i].as_bytes());
                blake256(&buf) == bc1_vec[i].commitment
            })
            .all(|x| x == true);

        let (vss_scheme, secret_shares) = VerifiableSS::share_at_indices(
            params.threshold,
            params.share_count,
            &self.u_i,
            &parties,
        );

        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(SchnorrError::VerifyError),
        }
    }

    pub fn phase2_verify_vss_construct_keypair(
        &self,
        params: &ShamirSecretSharing,
        y_vec: &Vec<RistrettoPoint>,
        secret_shares_vec: &Vec<Scalar>,
        vss_scheme_vec: &Vec<VerifiableSS>,
        index: &usize,
    ) -> Result<SharedKeys, SchnorrError> {
        assert_eq!(y_vec.len(), params.share_count);
        assert_eq!(secret_shares_vec.len(), params.share_count);
        assert_eq!(vss_scheme_vec.len(), params.share_count);

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], *index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == y_vec[i]
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let mut y_vec_iter = y_vec.iter();
                let y0 = y_vec_iter.next().unwrap();
                let y = y_vec_iter.fold(y0.clone(), |acc, x| acc + x);
                let x_i = secret_shares_vec.iter().fold(Scalar::zero(), |acc, x| acc + x);
                Ok(SharedKeys { y, x_i })
            }

            false => Err(SchnorrError::VerifyShareError),
        }
    }

    // remove secret shares from x_i for parties that are not participating in signing
    pub fn update_shared_key(
        shared_key: &SharedKeys,
        parties_in: &[usize],
        secret_shares_vec: &Vec<Scalar>,
    ) -> SharedKeys {
        let mut new_xi: Scalar = Scalar::zero();
        for i in 0..secret_shares_vec.len() {
            if parties_in.iter().find(|&&x| x == i).is_some() {
                new_xi = new_xi + &secret_shares_vec[i]
            }
        }
        SharedKeys {
            y: shared_key.y.clone(),
            x_i: new_xi,
        }
    }
}

pub struct LocalSig {
    gamma_i: Scalar,
    e: Scalar,
}

impl LocalSig {

    pub fn compute(
        message: &[u8],
        local_ephemaral_key: &SharedKeys,
        local_private_key: &SharedKeys,
    ) -> LocalSig {
        let beta_i = local_ephemaral_key.x_i.clone();
        let alpha_i = local_private_key.x_i.clone();

        let mut buf = Vec::new();
        buf.extend_from_slice(local_ephemaral_key.y.compress().as_bytes());
        buf.extend_from_slice(local_private_key.y.compress().as_bytes());
        buf.extend_from_slice(message);
        let e = blake256(&buf).into_scalar();

        let gamma_i = beta_i + e.clone() * alpha_i;

        LocalSig { gamma_i, e }
    }

    // section 4.2 step 3
    #[allow(unused_doc_comments)]
    pub fn verify_local_sigs(
        gamma_vec: &Vec<LocalSig>,
        parties_index_vec: &[usize],
        vss_private_keys: &Vec<VerifiableSS>,
        vss_ephemeral_keys: &Vec<VerifiableSS>,
    ) -> Result<(VerifiableSS), SchnorrError> {
        //parties_index_vec is a vector with indices of the parties that are participating and provided gamma_i for this step
        // test that enough parties are in this round
        assert!(parties_index_vec.len() > vss_private_keys[0].parameters.threshold);

        // Vec of joint commitments:
        // n' = num of signers, n - num of parties in keygen
        // [com0_eph_0,... ,com0_eph_n', e*com0_kg_0, ..., e*com0_kg_n ;
        // ...  ;
        // comt_eph_0,... ,comt_eph_n', e*comt_kg_0, ..., e*comt_kg_n ]
        let comm_vec = (0..vss_private_keys[0].parameters.threshold + 1)
            .map(|i| {
                let mut key_gen_comm_i_vec = (0..vss_private_keys.len())
                    .map(|j| vss_private_keys[j].commitments[i].clone() * &gamma_vec[i].e)
                    .collect::<Vec<RistrettoPoint>>();

                let mut eph_comm_i_vec = (0..vss_ephemeral_keys.len())
                    .map(|j| vss_ephemeral_keys[j].commitments[i].clone())
                    .collect::<Vec<RistrettoPoint>>();

                key_gen_comm_i_vec.append(&mut eph_comm_i_vec);
                let mut comm_i_vec_iter = key_gen_comm_i_vec.iter();
                let comm_i_0 = comm_i_vec_iter.next().unwrap();
                comm_i_vec_iter.fold(comm_i_0.clone(), |acc, x| acc + x)
            })
            .collect::<Vec<RistrettoPoint>>();

        let vss_sum = VerifiableSS {
            parameters: vss_ephemeral_keys[0].parameters.clone(),
            commitments: comm_vec,
        };

        let g = RISTRETTO_BASEPOINT_POINT;
        let correct_ss_verify = (0..parties_index_vec.len())
            .map(|i| {
                let gamma_i_g = &g * &gamma_vec[i].gamma_i;
                vss_sum
                    .validate_share_public(&gamma_i_g, parties_index_vec[i] + 1)
                    .is_ok()
            })
            .collect::<Vec<bool>>();

        match correct_ss_verify.iter().all(|x| x.clone() == true) {
            true => Ok(vss_sum),
            false => Err(SchnorrError::VerifyShareError),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature {
    pub sigma: Scalar,
    pub v: RistrettoPoint,
}

impl Signature {

    pub fn generate(
        vss_sum_local_sigs: &VerifiableSS,
        local_sig_vec: &Vec<LocalSig>,
        parties_index_vec: &[usize],
        v: RistrettoPoint,
    ) -> Signature {

        let gamma_vec = (0..parties_index_vec.len())
            .map(|i| local_sig_vec[i].gamma_i.clone())
            .collect::<Vec<Scalar>>();

        let reconstruct_limit = vss_sum_local_sigs.parameters.threshold.clone() + 1;

        let sigma = vss_sum_local_sigs.reconstruct(
            &parties_index_vec[0..reconstruct_limit.clone()],
            &gamma_vec[0..reconstruct_limit.clone()],
        );
        Signature { sigma, v }
    }

    pub fn verify(&self, message: &[u8], pubkey_y: &RistrettoPoint) -> Result<(), SchnorrError> {

        let mut buf = Vec::new();
        buf.extend_from_slice(self.v.compress().as_bytes());
        buf.extend_from_slice(pubkey_y.compress().as_bytes());
        buf.extend_from_slice(message);
        let e = blake256(&buf).into_scalar();

        let g = RISTRETTO_BASEPOINT_POINT;
        let sigma_g = g * &self.sigma;
        let e_y = pubkey_y * &e;
        let e_y_plus_v = e_y + &self.v;

        if e_y_plus_v == sigma_g {
            Ok(())
        } else {
            Err(SchnorrError::VerifyShareError)
        }
    }
}