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

//! Keys to the kingdom

//! Schnorr signatures on the 2-tortsion free subgroup of ed25519,
//! as provided by the Ristretto point compression.s

mod public;
pub use public::{PublicKey, PUBLIC_KEY_LENGTH};

mod secret;
pub use secret::{SecretKey, SECRET_KEY_LENGTH};

mod pair;
pub use pair::{Keypair, KEYPAIR_LENGTH};

/// Musig Key
mod multikey;
pub use multikey::MultiKey;

mod extended;
pub use extended::{XPublicKey, XSecretKey};

#[cfg(test)]
mod tests {
    use super::*;
    use mohan::dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};

    #[test]
    fn test_identity_keys() {
        //generate sk
        let sk = SecretKey(Scalar::zero());
        //generate our pk
        let pk = PublicKey::from_secret(&sk);

        assert_eq!(pk.into_point(), RistrettoPoint::identity());
    }
}
