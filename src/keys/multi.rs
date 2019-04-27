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

//! MuSig aggregated Public Key's

//
// Key Aggregation
//
//
// Input: list of compressed public keys that will be aggregated
//
// Operation:
//      a. Create a new transcript using the tag "Musig.aggregated-key".
//
//      b. Commit all the pubkeys to the transcript. 
//         The transcript state corresponds to the commitment `<L>` in 
//         the Musig paper: `<L> = H(X_1 || X_2 || ... || X_n)`.
//
//      c. Create `aggregated_key = sum_i ( a_i * X_i )`. 
//         Iterate over the pubkeys, compute the factor `a_i = H(<L>, X_i)`, 
//         and add `a_i * X_i` to the aggregated key.
//
// Output: a new Multikey, with the transcript and aggregated key detailed above.
//
//

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use merlin::Transcript;
use crate::errors::{
    SchnorrError, 
    InternalError,
    MuSigError
};
use crate::keys::PublicKey;
use std::vec::Vec;
use crate::tools::TranscriptProtocol;


// pub(crate) trait MusigContext {
//     /// Takes a mutable transcript, and commits the internal context to the transcript.
//     fn commit(&self, transcript: &mut Transcript);

//     /// Takes a public key and mutable transcript, and returns the suitable challenge for that public key.
//     fn challenge(&self, pubkey: &PublicKey, transcript: &mut Transcript) -> Scalar;

//     /// Returns the associated public keys.
//     fn get_pubkeys(&self) -> Vec<PublicKey>;
// }



#[derive(Clone)]
/// MuSig aggregated key.
pub struct MultiKey {
    transcript: Option<Transcript>,
    aggregated_key: PublicKey,
    public_keys: Vec<PublicKey>,
}



impl MultiKey {

    /// Constructs a new MuSig multikey aggregating the pubkeys.
    pub fn new(pub_keys: Vec<PublicKey>) -> Result<Self, SchnorrError> {
        match pub_keys.len() {
            0 => {
                return Err(SchnorrError(InternalError::BadArguments));
            }

            1 => {

                return Ok(MultiKey {
                    transcript: None,
                    aggregated_key: pub_keys[0],
                    public_keys: pub_keys,
                });
            }
            _ => {}
        }

        // Create transcript for Multikey
        let mut transcript = Transcript::new(b"Musig.aggregated-key");
        transcript.commit_u64(b"n", pub_keys.len() as u64);

        // Commit pubkeys into the transcript
        // <L> = H(X_1 || X_2 || ... || X_n)
        for X in &pub_keys {
            transcript.commit_point(b"X", &X.0);
        }

        // aggregated_key = sum_i ( a_i * X_i )
        let mut aggregated_key = RistrettoPoint::default();
        for X in &pub_keys {
            let a = MultiKey::compute_factor(&transcript, X);
            let X = X.0.decompress().ok_or(SchnorrError(InternalError::PointDecompressionError))?;
            aggregated_key = aggregated_key + a * X;
        }

        Ok(MultiKey {
            transcript: Some(transcript),
            aggregated_key: PublicKey(aggregated_key.compress()),
            public_keys: pub_keys,
        })
    }

    /// Amount of public keys in this Multi key
    pub fn len(&self) -> usize {
        self.public_keys.len()
    }

    /// Returns `a_i` factor for component key in aggregated key.
    /// a_i = H(<L>, X_i). The list of pubkeys, <L>, has already been committed to the transcript.
    fn compute_factor(transcript: &Transcript, X_i: &PublicKey) -> Scalar {
        // a_i = H(<L>, X_i). Components of <L> have already been fed to transcript.
        let mut a_i_transcript = transcript.clone();
        a_i_transcript.commit_point(b"X_i", &X_i.0);
        a_i_transcript.challenge_scalar(b"a_i")
    }

    /// Returns `a_i` factor for component key in aggregated key.
    pub fn factor_for_key(&self, X_i: &PublicKey) -> Scalar {
        match &self.transcript {
            Some(t) => MultiKey::compute_factor(&t, X_i),
            None => Scalar::one(),
        }
    }

    /// Returns VerificationKey representation of aggregated key.
    pub fn aggregated_key(&self) -> PublicKey {
        self.aggregated_key
    }

    pub fn get_pubkeys(&self) -> Vec<PublicKey> {
        self.public_keys.clone()
    }
    
    fn commit(&self, transcript: &mut Transcript) {
        transcript.commit_point(b"X", &self.aggregated_key.0);
    }

    fn challenge(&self, pubkey: &PublicKey, transcript: &mut Transcript) -> Scalar {
        // Make c = H(X, R, m)
        // The message `m`, nonce commitment `R`, and aggregated key `X` 
        // have already been fed into the transcript.
        let c = transcript.challenge_scalar(b"c");

        // Make a_i, the per-party factor. a_i = H(<L>, X_i).
        // The list of pubkeys, <L>, has already been committed to self.transcript.
        let a_i = match &self.transcript {
            Some(t) => MultiKey::compute_factor(&t, &pubkey),
            None => Scalar::one(),
        };

        c * a_i
    }

}


// impl MusigContext for Multikey {
    
//     fn commit(&self, transcript: &mut Transcript) {
//         transcript.commit_point(b"X", &self.aggregated_key.0);
//     }

//     fn challenge(&self, pubkey: &PublicKey, transcript: &mut Transcript) -> Scalar {
//         // Make c = H(X, R, m)
//         // The message `m`, nonce commitment `R`, and aggregated key `X` 
//         // have already been fed into the transcript.
//         let c = transcript.challenge_scalar(b"c");

//         // Make a_i, the per-party factor. a_i = H(<L>, X_i).
//         // The list of pubkeys, <L>, has already been committed to self.transcript.
//         let a_i = match &self.transcript {
//             Some(t) => Multikey::compute_factor(&t, &pubkey),
//             None => Scalar::one(),
//         };

//         c * a_i
//     }

//     fn get_pubkeys(&self) -> Vec<PublicKey> {
//         self.public_keys.clone()
//     }

//  }
