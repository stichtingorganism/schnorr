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

//! Commitments used in the first stage of musig

use merlin::Transcript;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use crate::tools::TranscriptProtocol;
use std::vec::Vec;

#[derive(Copy, Clone)]
pub struct NoncePrecommitment(pub(crate) [u8; 32]);

#[derive(Copy, Clone, Debug)]
pub struct NonceCommitment(pub(crate) RistrettoPoint);


impl NonceCommitment {

    pub fn new(commitment: RistrettoPoint) -> Self {
        NonceCommitment(commitment)
    }

    pub fn precommit(&self) -> NoncePrecommitment {
        let mut h = Transcript::new(b"Musig.nonce-precommit");
        h.commit_point(b"R", &self.0.compress());
        let mut precommitment = [0u8; 32];
        h.challenge_bytes(b"precommitment", &mut precommitment);
        NoncePrecommitment(precommitment)
    }

    pub fn compress(&self) -> CompressedRistretto {
        self.0.compress()
    }

    pub fn sum(commitments: &Vec<Self>) -> RistrettoPoint {
        commitments.iter().map(|r_i| r_i.0).sum()
    }
    
}
