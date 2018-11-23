// Copyright 2018 Stichting Organism
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

//Modeled from
//https://github.com/dalek-cryptography/ed25519-dalek/blob/master/src/ed25519.rs

//Useful links:
//https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/
//https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
//https://medium.com/cryptoadvance/how-schnorr-signatures-may-improve-bitcoin-91655bcb4744

#![no_std]
#![allow(unused_features)]
//#![deny(missing_docs)] // refuse to compile if documentation is missing

extern crate rand;
extern crate curve25519_dalek;
extern crate serde;
extern crate failure;
extern crate clear_on_drop;
extern crate blake2;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

pub mod errors;
mod schnorr;

// Export everything public in schnorr.
pub use schnorr::*;
pub use errors::*;




// #[cfg(test)]
// mod tests {
//     use super::*;
//     use curve25519_dalek::ristretto::RistrettoPoint;
//     use curve25519_dalek::traits::Identity;

//     #[test]
//     fn test_keys() {
//         //generate sk
//         let sk = SecretKey(Scalar::zero());
//         //generate our pk
//         let pk = PublicKey::from_secret(&sk);
        
//         assert_eq!(pk.0, RistrettoPoint::identity().compress());
//     }

// }