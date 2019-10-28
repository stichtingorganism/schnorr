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

//
// Schnorr via ristretto
//

// Modified From the hard work off:
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Jeff Burdges <jeff@web3.foundation>
// - The Tari Project Authors
// - Cathie Yun <cathieyun@gmail.com>
// - Tess Rinearson <tess.rinearson@gmail.com>
// - Oleg Andreev <oleganza@gmail.com>

//Modeled from
//https://github.com/dalek-cryptography/ed25519-dalek/blob/master/src/ed25519.rs

//Useful links:
//https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/
//https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
//https://medium.com/cryptoadvance/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744

mod errors;
pub use errors::SchnorrError;
mod tools;
pub use tools::SigningContext;

pub mod keys;
pub mod signature;
/// Export everything public in schnorr.
pub use signature::{Signature, SIGNATURE_LENGTH};

/// Key Swap
mod ecdh;
pub use crate::ecdh::{diffie_hellman, SharedSecret};

/// A Multisignature over many different messages
mod multimessage;
pub use multimessage::Multimessage;
mod multisignature;
pub use multisignature::Multisignature;

pub use crate::keys::*;
mod batch;
pub use batch::{BatchVerification, BatchVerifier, SingleVerifier};

mod context;
pub use context::MuSigContext;

/// A Multisig Participator
pub(crate) mod counterparty;

/// Multisig local signer
mod signer;
pub use signer::{
    Signer, SignerAwaitingCommitments, SignerAwaitingPrecommitments, SignerAwaitingShares,
};

// mod adaptor;

pub mod feldman_vss;

pub mod threshold;
#[cfg(test)]
mod threshold_test;

#[cfg(test)]
mod musig_test;




macro_rules! serde_boilerplate { ($t:ty) => {
    impl ::serde::Serialize for $t {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: ::serde::Serializer {
            serializer.serialize_bytes(&self.to_bytes()[..])
        }
    }

    impl<'d> ::serde::Deserialize<'d> for $t {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: ::serde::Deserializer<'d> {
            struct MyVisitor;

            impl<'d> ::serde::de::Visitor<'d> for MyVisitor {
                type Value = $t;

                fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    formatter.write_str("SERDE ERROR")
                }

                fn visit_bytes<E>(self, bytes: &[u8]) -> Result<$t, E> where E: ::serde::de::Error {
                    Self::Value::from_bytes(bytes).map_err(crate::errors::serde_error_from_signature_error)
                }
            }
            deserializer.deserialize_bytes(MyVisitor)
        }
    }
} } // macro_rules! serde_boilerplate

serde_boilerplate!(Signature);
serde_boilerplate!(PublicKey);