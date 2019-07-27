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


//! Schnorr Secret Key & Extended Secret Key generation 


use core::fmt::{Debug};
use subtle::{Choice, ConstantTimeEq};
use rand::{Rng, CryptoRng};
use curve25519_dalek::scalar::Scalar;
use crate::errors::{SchnorrError, InternalError};
use clear_on_drop::clear::Clear;

/// The length of a curve25519 Schnorr `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;



/// An Schnorr secret key.
#[derive(Default, Clone)]
pub struct SecretKey(pub (crate) Scalar);


impl Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "SecretKey: {:?}", &self.0)
    }
}

impl Eq for SecretKey {}
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}
impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}



impl SecretKey {

    const DESCRIPTION : &'static str = "A Schnorr secret key as 32 bytes.";

    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; SECRET_KEY_LENGTH] {
        &self.0.as_bytes()
    }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate schnorr;
    /// #
    /// use schnorr::*;
    ///
    /// # fn doctest() -> Result<SecretKey, SchnorrError> {
    /// let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = [
    ///    157, 097, 177, 157, 239, 253, 090, 096,
    ///    186, 132, 074, 244, 146, 236, 044, 196,
    ///    068, 073, 197, 105, 123, 050, 105, 025,
    ///    112, 059, 172, 003, 028, 174, 127, 096, ];
    ///
    /// let secret_key: SecretKey = SecretKey::from_bytes(&secret_key_bytes)?;
    /// #
    /// # Ok(secret_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     let result = doctest();
    /// #     assert!(result.is_ok());
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an Schnorr `SecretKey` or whose error value
    /// is an `SchnorrError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, SchnorrError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(SchnorrError::from(InternalError::BytesLengthError{
                name: "SecretKey",  
                description: SecretKey::DESCRIPTION, 
                length: SECRET_KEY_LENGTH 
            }));
        }


        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(SecretKey(Scalar::from_bits(bits)))
    }

    /// Generate a `SecretKey` from a `csprng`.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand;
    /// extern crate schnorr;
    ///
    /// # #[cfg(feature = "std")]
    /// # fn main() {
    /// #
    /// use rand::Rng;
    /// use rand::OsRng;
    /// use schnorr::*;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    /// # }
    /// #
    /// # #[cfg(not(feature = "std"))]
    /// # fn main() { }
    /// ```
    ///
    /// Afterwards, you can generate the corresponding public—provided you also
    /// supply a hash function which implements the `Digest` and `Default`
    /// traits, and which returns 512 bits of output—via:
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate schnorr;
    /// #
    /// # fn main() {
    /// #
    /// # use rand::Rng;
    /// # use rand::ChaChaRng;
    /// # use rand::SeedableRng;
    /// # use schnorr::*;
    /// #
    /// # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
    /// # let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    ///
    /// let public_key: PublicKey = PublicKey::from_secret(&secret_key);
    /// # }
    /// ```
    ///
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand::ChaChaRng`
    pub fn generate<T>(csprng: &mut T) -> SecretKey
        where T: CryptoRng + Rng,
    {
        SecretKey(Scalar::random(csprng))
    }

    ///Helper Method to Convert key to scalar
    pub fn to_scalar(&self) -> Scalar { self.0 }

    /// View this scalaras a byte array.
    #[inline]
    pub fn as_scalar<'a>(&'a self) -> &'a Scalar {
        &self.0
    }

    ///Helper Method to Convert Scalar to Key
    pub fn from_scalar(s: Scalar) -> SecretKey { SecretKey(s) }

}


serde_boilerplate!(SecretKey);


