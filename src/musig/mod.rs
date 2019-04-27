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

//! A Rust implementation of Schnorr multi-signatures and key aggregation.

//! Implementation for Ristretto Schnorr signatures of
//! "Simple Schnorr Multi-Signatures with Applications to Bitcoin" by
//! Gregory Maxwell, Andrew Poelstra, Yannick Seurin, and Pieter Wuille
//! https://eprint.iacr.org/2018/068
//!
//! We observe the security arguments from the
//! [original 2-round version](https://eprint.iacr.org/2018/068/20180118:124757)
//! were found lacking in
//! "On the Provable Security of Two-Round Multi-Signatures" by
//! Manu Drijvers, Kasra Edalatnejad, Bryan Ford, and Gregory Neven
//! https://eprint.iacr.org/2018/417
//! ([slides](https://rwc.iacr.org/2019/slides/neven.pdf))
//! so we implement only the
//! [3-round version](https://eprint.iacr.org/2018/068/20180520:191909).
//!
//! Appendix A of the [MuSig paper](https://eprint.iacr.org/2018/068)
//! discusses Interactive Aggregate Signatures (IAS) in which cosigners'
//! messages differ.  Appendix A.3 gives a secure scheme that correctly
//! binds signers to their messages.  See
//! https://github.com/w3f/schnorrkel/issues/5#issuecomment-477912319

mod commitment;
pub use commitment::{ 
    NonceCommitment, 
    NoncePrecommitment 
};

mod parti;

pub use parti::{
    Signer,
    Parti,
    MuSigStateMachine
};

mod core;


