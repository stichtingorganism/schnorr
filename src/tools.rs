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


//! The Extra Sauce
//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.
//! ristretto point tooling
//! 
//! We provide a `RistrettoBoth` type that contains both an uncompressed
//! `RistrettoPoint` along side its matching `CompressedRistretto`, 
//! which helps several protocols avoid duplicate ristretto compressions
//! and/or decompressions.  

use mohan::dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use mohan::dalek::scalar::Scalar;
use bacteria::Transcript;
use mohan::dalek::digest::{FixedOutput, ExtendableOutput, XofReader};
use mohan::dalek::digest::generic_array::typenum::{U32,U64};


/// A Signing Context Provides an abstraction for signature protocol Merlin Transcript
#[derive(Clone)] // Debug
pub struct SigningContext(Transcript);

impl SigningContext {

    /// Initialize a signing context from a static byte string that
    /// identifies the signature's role in the larger protocol.
    pub fn new(context : &'static [u8]) -> SigningContext {
        SigningContext(Transcript::new(context))
    }

    pub fn to_owned(&mut self) -> Transcript {
        self.0.clone()
    }

    /// Initalize an owned signing transcript on a message provided as a byte array
    pub fn bytes(&self, bytes: &[u8]) -> Transcript {
        let mut t = self.0.clone();
        t.append_message(b"sign-bytes", bytes);
        t
    }

    /// Initalize an owned signing transcript on a message provided as a hash function with extensible output
    pub fn xof<D: ExtendableOutput>(&self, h: D) -> Transcript {

        let mut prehash = [0u8; 32];
        h.xof_result().read(&mut prehash);
        let mut t = self.0.clone();

        t.append_message(b"sign-XoF", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 256 bit output.
    pub fn from_hash256<D: FixedOutput<OutputSize=U32>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 32]; 
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.append_message(b"sign-256", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 512 bit output, usually a gross over kill.
    pub fn from_hash512<D: FixedOutput<OutputSize=U64>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 64]; 
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.append_message(b"sign-256", &prehash);
        t
    }

}
