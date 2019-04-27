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

//! MuSig Types 


use std::collections::BTreeMap;
use merlin::Transcript;
use crate::keys::{
    PublicKey, 
    MultiKey
};
use crate::signature::Signature;
use crate::errors::{
    SchnorrError, 
    InternalError,
    MuSigError
};

use crate::musig::{
    Parti,
    MuSigStateMachine
};



/// The set of possible input events that can occur during the MuSig signature aggregation protocol.
pub enum MuSigEvent<'a> {
    /// This event is used to add a new public key to the pool of participant keys
    AddKey(PublicKey),
    // /// Provides the message to be signed for the MuSig protocol
    // SetMessage(MessageHash),
    /// This event is used by participants to commit the the public nonce that they will be using the signature
    /// aggregation ceremony
    AddNonceHash(&'a PublicKey),
    /// This event is used to add a public nonce to the pool of nonces for a particular signing ceremony
    AddNonce(&'a PublicKey, PublicKey),
    /// In the 3rd round of MuSig, participants provide their partial signatures, after which any party can
    /// calculate the aggregated signature.
    AddPartialSig(Signature, bool),
}


/// The Cookies n Cream of Multisigs
pub struct MuSig {
    /// Expected Amount protocol signers
    group_size: usize,
    /// Protocol Transcript 
    transcript: Transcript,
   
    /// All people in the protocol, sorted by key including local signer
    parties: BTreeMap<PublicKey, Parti>,

    //combined_nonce

    /// The Combined key from all keys in this session
    multi_key: Option<MultiKey>,

    // The 32-byte hash of the original public keys
    //pk hash
    //
    //combined key 
    //Summed combined public nonce (undefined if `nonce_is_set` is false)
    //combined nonce

    /// Protocol State
    state: MuSigStateMachine
}


impl MuSig {

    /// Create a new Session with a muli key 
    pub fn new(multi: MultiKey) -> MuSig {
        MuSig {
            group_size: multi.len(),
            // transcript ,
            parties: BTreeMap::new(),
            multi_key: Some(multi),
            state: MuSigStateMachine::Initialization,
        }
    }

    //pub fn from_

  
    /// Return the index of the public key in the MuSig ceremony. If were still collecting public keys, the state has
    /// been finalised, or the pub_key isn't in the list, then None is returned.
    pub fn index_of(&self, pk: &PublicKey) -> Result<usize, SchnorrError> {

        match self.parties.get(pk) {
            None => {
                //not found
                return Err(SchnorrError(InternalError::MuSig {
                        kind: MuSigError::ParticipantNotFound,
                }));
            }, 
            Some(c) => {
                return Ok(c.position);
            }
        }
 
    }


    // Implement a finite state machine. Each combination of State and Event is handled here; for each combination, a
    // new state is determined, consuming the old one. If `MuSigState::Failed` is ever returned, the protocol must be
    // abandoned.
    // fn handle_event(self, event: MuSigEvent) -> Self {
        // let state = match self.state {
        //     // On initialization, you can add keys until you reach `num_signers` at which point the state
        //     // automatically flips to `NonceHashCollection`; we're forced to use nested patterns because of error
        //     MuSigState::Initialization(s) => match event {
        //         MuSigEvent::AddKey(p) => s.add_pubkey::<D>(p),
        //         MuSigEvent::SetMessage(m) => s.set_message(m),
        //         _ => RistrettoMuSig::<D>::invalid_transition(),
        //     },

        //     // Nonce Hash collection
        //     MuSigState::NonceHashCollection(s) => match event {
        //         MuSigEvent::AddNonceHash(p, h) => s.add_nonce_hash::<D>(p, h.clone()),
        //         MuSigEvent::SetMessage(m) => s.set_message(m),
        //         _ => RistrettoMuSig::<D>::invalid_transition(),
        //     },

        //     // Nonce Collection
        //     MuSigState::NonceCollection(s) => match event {
        //         MuSigEvent::AddNonce(p, nonce) => s.add_nonce::<D>(p, nonce),
        //         MuSigEvent::SetMessage(m) => s.set_message::<D>(m),
        //         _ => RistrettoMuSig::<D>::invalid_transition(),
        //     },

        //     // Signature collection
        //     MuSigState::SignatureCollection(s) => match event {
        //         MuSigEvent::AddPartialSig(sig, validate) => s.add_partial_signature::<D>(sig, validate),
        //         _ => RistrettoMuSig::<D>::invalid_transition(),
        //     },

        //     // There's no way back from a Failed State.
        //     MuSigState::Failed(_) => RistrettoMuSig::<D>::invalid_transition(),
        //     _ => RistrettoMuSig::<D>::invalid_transition(),
        // };
        
        // MuSig {
        //     state,
        // }
    // }

    // Add a new protocol member
    // pub fn add_counterparty(&mut self, cp: Counterparty)
}













