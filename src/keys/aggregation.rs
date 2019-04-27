// Copyright 2019 Stichting Organism
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Implementation of Schnorr signature key aggregation.

//https://github.com/interstellar/slingshot/blob/main/zkvm/src/keys.rs

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use crate::{PublicKey, SecretKey};
use crate::tools::TranscriptProtocol;


/// Creates an aggregated Schnorr private key for signing from
/// a single party's set of private keys.
pub fn aggregated_privkey(privkeys: &[SecretKey]) -> SecretKey {

    let mut transcript = Transcript::new(b"Schnorr_agg_key");

    // Derive public keys from privkeys
    let pubkeys = privkeys
        .iter()
        .map(|p| PublicKey::from_secret(p))
        .collect::<Vec<_>>();

    // Commit pubkeys
    let n = pubkeys.len();
    transcript.commit_u64(b"n", n as u64);

    for p in pubkeys.iter() {
        transcript.commit_point(b"public_key", p.as_bytes());
    }

    // Generate aggregated private key
    SecretKey(
        privkeys
            .iter()
            .map(|p| {
                let x = transcript.challenge_scalar(b"x");
                p * x
            })
            .sum()
    )
}

/// Creates an aggregated Schnorr public key for verifying signatures from a
/// single party's set of private keys.
pub fn aggregated_pubkey(pubkeys: &[PublicKey]) -> Result<PublicKey, VMError> {

    let mut transcript = Transcript::new(b"Schnorr_agg_key");

    transcript.commit_u64(b"n", pubkeys.len() as u64);

    for p in pubkeys.iter() {
        transcript.commit_point(b"public_key", p.as_bytes());
    }

    let pairs = pubkeys
        .iter()
        .map(|p| {
            let x = transcript.challenge_scalar(b"x");
            (x, p.0)
        })
        .collect::<Vec<_>>();

    let pubkey_op = PointOp {
        primary: None,
        secondary: None,
        arbitrary: pairs,
    };

    Ok(VerificationKey(pubkey_op.compute()?.compress()))
}