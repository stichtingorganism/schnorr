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

//! A Rust implementation of Schnorr key generation,

use crate::keys::{PublicKey, SecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use crate::SchnorrError;
use mohan::ser;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// The length of an ed25519 Schnorr `Keypair`, in bytes.
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// An Schnorr keypair.
#[derive(Debug, Default, Clone)] // we derive Default in order to use the clear() method in Drop
pub struct Keypair {
    /// The secret half of this keypair.
    pub secret: SecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        let public = PublicKey::from_secret(&secret);
        Keypair { secret, public }
    }
}

impl ::zeroize::Zeroize for Keypair {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Keypair {

    /// Convert this keypair to bytes.
    ///
    /// # Returns
    ///
    /// An array of bytes, `[u8; KEYPAIR_LENGTH]`.  The first
    /// `SECRET_KEY_LENGTH` of bytes is the `SecretKey`, and the next
    /// `PUBLIC_KEY_LENGTH` bytes is the `PublicKey`
    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        bytes[..SECRET_KEY_LENGTH].copy_from_slice(self.secret.as_bytes());
        bytes[SECRET_KEY_LENGTH..].copy_from_slice(self.public.as_bytes());
        bytes
    }

    /// Construct a `Keypair` from the bytes of a `PublicKey` and `SecretKey`.
    ///
    /// # Inputs
    ///
    /// * `bytes`: an `&[u8]` representing the scalar for the secret key, and a
    ///   compressed Edwards-Y coordinate of a point on curve25519, both as bytes.
    ///   (As obtained from `Keypair::to_bytes()`.)
    ///
    /// # Warning
    ///
    /// Absolutely no validation is done on the key.  If you give this function
    /// bytes which do not represent a valid point, or which do not represent
    /// corresponding parts of the key, then your `Keypair` will be broken and
    /// it will be your fault.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an Schnorr `Keypair` or whose error value
    /// is an `SchnorrError` describing the error that occurred.
    pub fn from_bytes<'a>(bytes: &'a [u8]) -> Result<Keypair, SchnorrError> {
        if bytes.len() != KEYPAIR_LENGTH {
            return Err(SchnorrError::SerError);
        }
        let secret = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH])?;
        let public = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..])?;

        Ok(Keypair{ secret: secret, public: public })
    }

    /// Generate an schnorr keypair.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand;
    /// extern crate schnorr;
    ///
    /// # fn main() {
    ///
    /// use rand::Rng;
    /// use rand::rngs::OsRng;
    /// use schnorr::*;
    ///
    /// let mut csprng: OsRng = OsRng;
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    ///
    /// # }
    /// ```
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand::ChaChaRng`.
    ///
    /// The caller must also supply a hash function which implements the
    /// `Digest` and `Default` traits, and which returns 512 bits of output.
    /// The standard hash function used is Blake2b-512,
    pub fn generate<R>(csprng: &mut R) -> Keypair
    where
        R: CryptoRng + RngCore,
    {
        let sk: SecretKey = SecretKey::generate(csprng);
        let pk: PublicKey = PublicKey::from_secret(&sk);

        Keypair {
            public: pk,
            secret: sk,
        }
    }

    /// Derive the `PublicKey` corresponding to this `SecretKey`.
    pub fn from_secret(s: &SecretKey) -> Keypair {
        Keypair {
            secret: s.clone(),
            public: PublicKey::from_secret(s),
        }
    }
}

impl ser::Writeable for Keypair {
    fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
        self.secret.write(writer)?;
        self.public.write(writer)?;

        Ok(())
    }
}

impl ser::Readable for Keypair {
    fn read(reader: &mut dyn ser::Reader) -> Result<Keypair, ser::Error> {
        let s = SecretKey::read(reader)?;
        let p = PublicKey::read(reader)?;

        Ok(Keypair {
            secret: s,
            public: p,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn keypair_clear_on_drop() {
        let mut keypair: Keypair = Keypair::generate(&mut rand::prelude::thread_rng());

        keypair.zeroize();

        fn as_bytes<T>(x: &T) -> &[u8] {
            use core::mem;
            use core::slice;

            unsafe { slice::from_raw_parts(x as *const T as *const u8, mem::size_of_val(x)) }
        }

        assert!(!as_bytes(&keypair).iter().all(|x| *x == 0u8));
    }
}
