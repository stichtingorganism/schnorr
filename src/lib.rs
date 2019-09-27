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
pub mod tools;
pub use crate::tools::{ SigningContext };
pub mod keys;
pub mod signature;
pub mod ecdh;


// Export everything public in schnorr.
pub use crate::signature::{
    Signature,
    SIGNATURE_LENGTH,
    verify_batch,
    sign_multi,
    verify_multi
};

pub use crate::keys::*;
pub use crate::ecdh::{
    diffie_hellman, 
    SharedSecret
};


// //taken from futures lib:)
// pub mod prelude {
//     //! A "prelude" for crates using the `schnorr` crate.
//     //!
//     //! This prelude is similar to the standard library's prelude in that you'll
//     //! almost always want to import its entire contents, but unlike the
//     //! standard library's prelude you'll have to do so manually:
//     //!
//     //! ```
//     //! use schnorr::prelude::*;
//     //! ```
//     //!
//     //! The prelude may grow over time as additional items see ubiquitous use.
//     // Export everything public in schnorr.
//     pub use crate::signature::{
//         Signature,
//         SIGNATURE_LENGTH,
//         verify_batch,
//         sign_multi,
//         verify_multi
//     };
//     pub use crate::errors::SchnorrError;
//     pub use crate::keys::*;
//     pub use crate::tools::{ SigningContext };
//     pub use crate::ecdh::{
//         diffie_hellman, 
//         SharedSecret
//     };

// }