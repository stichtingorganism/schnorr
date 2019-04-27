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

//! Protocol People
use subtle::ConstantTimeEq;
use merlin::Transcript;
use crate::keys::{
    SecretKey,
    PublicKey
};

use crate::musig::{
    NonceCommitment,
    NoncePrecommitment
};

use crate::errors::{
    SchnorrError, 
    InternalError,
    MuSigError
};

use crate::signature::Signature;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;


/// Musig State Machine, 3 part interactive protocol
pub enum MuSigStateMachine {
    ///Setup to execute protocol of known pubkey
    Initialization,
    ///Players have to commit to their nonce, Stage 1
    NonceCommitmentCollection,
    ///Players Reveal there nonce, verify that the openings are correct, Stage 2
    NonceCollection,
    ///Players Sign and share there signatures, Stage 3
    SignatureCollection,
    ///Compute the Aggregated Signatire
    Finalized,
    ///If protocol fails at any point of protocol
    Failed,
}



/// A Signer in MuSig, locally tracks the state of a protocol run
/// Entry point to multi-party signing protocol.
pub struct Signer {
    /// the signer's secret key
    pub(crate) key: SecretKey,
    /// the signers pubkey
    pub(crate) pubkey: PublicKey,
    /// the signer's public nonce
    pub(crate) nonce: NonceCommitment,
    /// the signer's public nonce commitment
    pub(crate) commitment: NoncePrecommitment,
    // The position the signer is in the key order
    pub(crate) position: usize,
}


impl Signer {

    /// Create new signing party for a given transcript.
    pub fn new<'t>(
        // The message `m` has already been fed into the transcript
        transcript: &'t mut Transcript,
        //Signing Key used in this session 
        key: SecretKey,
        
    ) -> Parti {
        
        // Use the transcript to generate a random factor (the nonce), by committing to the privkey 
        let mut rng = transcript
            .build_rng()
            .commit_witness_bytes(b"key", &key.to_bytes())
            .finalize(&mut rand::thread_rng());

        // Use the nonce to create a nonce commitment and precommitment

        // Generate ephemeral keypair (r_i, R_i). r_i is a random nonce.
        let r_i = Scalar::random(&mut rng);

        // R_i = generator * r_i
        let R_i = NonceCommitment::new(RISTRETTO_BASEPOINT_POINT * r_i);

        // Make H(R_i)
        let precommitment = R_i.precommit();

        //Create a Parti member from local signer
        Parti {
            position: 0, 
            pubkey: PublicKey::from(key),
            precommitment: Some(precommitment),
            commitment: Some(R_i),
            partial_sig: None,
            state: MuSigStateMachine::NonceCollection
        }
    }
}


/// A member of the a MuSig protocol
pub struct Parti {
    /// The position this member is in the key order
    pub(crate) position: usize,
    /// The pubic key that they are using
    pub(crate) pubkey: PublicKey,
    /// This members stage 1 precommitment
    pub(crate) precommitment: Option<NoncePrecommitment>,
    /// This members stage 2 reveal, must be valid!
    pub(crate) commitment: Option<NonceCommitment>,
    /// This members stage 3 signature
    pub(crate) partial_sig: Option<Signature>,
    /// The state of this members protocol
    pub(crate) state: MuSigStateMachine
}


impl Parti {

    ///Create a new protocol member
    pub fn new(position: usize, pubkey: PublicKey) -> Self {
        Parti { 
            position: position, 
            pubkey: pubkey,
            precommitment: None,
            commitment: None,
            partial_sig: None,
            state: MuSigStateMachine::Initialization
        }
    }

    /// When we receive there stage 1 precommitment
    /// This will override if already set
    pub fn precommit_nonce(
        &mut self,
        precommitment: NoncePrecommitment,
    ) {

        //set precommitment
        self.precommitment = Some(precommitment);
        //change state
        self.state = MuSigStateMachine::NonceCommitmentCollection;
    }

    /// In stage 2 we get the opening, confirm that it is valid with stage 1
    pub(crate) fn verify_nonce(
        &mut self,
        commitment: NonceCommitment,
    ) -> Result<(), SchnorrError> {

        // Check H(commitment) =? precommitment
        let received_precommitment = commitment.precommit();

        match self.precommitment {
            None => {
                return Err(SchnorrError(InternalError::MuSig {
                    kind: MuSigError::MissingNonce,
                }));
            },
            Some(n) => {

                let equal = n.0.ct_eq(&received_precommitment.0);

                if equal.unwrap_u8() == 0 {
                    //we failed
                    self.state = MuSigStateMachine::Failed;

                    return Err(SchnorrError(InternalError::MuSig {
                        kind: MuSigError::MismatchedNonces,
                    }));
                }

            }
        }
    

        //change state
        self.state = MuSigStateMachine::NonceCollection;

        Ok(())
    }

    // /// In stage 3 we get there signature
    // pub(super) fn verify_share(
    //     self,
    //     share: Scalar,
    //     transcript: &Transcript,
    // ) -> Result<Scalar, SchnorrError> {

    //     // Check the partial Schnorr signature:
    //     // s_i * G == R_i + c_i * X_i.
    //     let S_i = share * RISTRETTO_BASEPOINT_POINT;
    //     // Make c = H(X, R, m)
    //     // The message `m`, nonce commitment `R`, and aggregated key `X`
    //     // have already been fed into the transcript.
    //     let c = transcript.challenge_scalar(b"c");

    //     let c_i = context.challenge(self.position, &mut transcript.clone());
    //     let X_i = self.pubkey.into_point();

    //     if S_i != self.commitment.0 + c_i * X_i {
    //         //we failed
    //         self.state = MuSigStateMachine::Failed;

    //         return Err(SchnorrError(InternalError::MuSig {
    //             kind: MuSigError::InvalidPartialSignature(self.position),
    //         }));
    //     }

    //     //change state
    //     self.state = MuSigStateMachine::SignatureCollection;

    //     Ok(share)
    // }
}