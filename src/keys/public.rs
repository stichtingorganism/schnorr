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

//! Schnorr Public Key generation, 


use core::fmt::{Debug};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use crate::errors::SchnorrError;
use crate::keys::SecretKey;
use crate::tools::RistrettoBoth;


/// The length of an ed25519 Schnorr `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;


/// An Schnorr public key.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct PublicKey(pub (crate) RistrettoBoth);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "PublicKey( CompressedRistretto( {:?} ))", self.0)
    }
}

impl PublicKey {

    const DESCRIPTION : &'static str = "A Ristretto Schnorr public key represented as a 32-byte Ristretto compressed point";

    /// Access the compressed Ristretto form
    pub fn as_compressed(&self) -> &CompressedRistretto { &self.0.as_compressed() }

    /// Extract the compressed Ristretto form
    pub fn into_compressed(self) -> CompressedRistretto { self.0.into_compressed() }

    /// Access the point form
    pub fn as_point(&self) -> &RistrettoPoint { &self.0.as_point() }

    /// Extract the point form
    pub fn into_point(self) -> RistrettoPoint { self.0.into_point() }

    /// Decompress into the `PublicKey` format that also retains the
    /// compressed form.
    pub fn from_compressed(compressed: CompressedRistretto) -> Result<PublicKey, SchnorrError> {
        Ok(PublicKey(RistrettoBoth::from_compressed(compressed) ?))
    }

    /// Compress into the `PublicKey` format that also retains the
    /// uncompressed form.
    pub fn from_point(point: RistrettoPoint) -> PublicKey {
        PublicKey(RistrettoBoth::from_point(point))
    }

    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        &self.0.as_compressed().0
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// The caller is responsible for ensuring that the bytes passed into this
    /// method actually represent a `curve25519_dalek::curve::CompressedRistretto`
    /// and that said compressed point is actually a point on the curve.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate schnorr;
    /// #
    /// use schnorr::prelude::*;
    ///
    /// # fn doctest() -> Result<PublicKey, SchnorrError> {
    /// let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [
    ///    215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
    ///     14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
    ///
    /// let public_key = PublicKey::from_bytes(&public_key_bytes)?;
    /// #
    /// # Ok(public_key)
    /// # }
    /// #
    /// # fn main() {
    /// #     doctest();
    /// # }
    /// ```
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an Schnorr `PublicKey` or whose error value
    /// is an `SchnorrError` describing the error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SchnorrError> {
        Ok(PublicKey(RistrettoBoth::from_bytes_ser("PublicKey", PublicKey::DESCRIPTION, bytes) ?))
    }

    /// Derive this public key from its corresponding `SecretKey`.
    pub fn from_secret(secret_key: &SecretKey) -> PublicKey {
        PublicKey(RistrettoBoth::from_point(Self::from_secret_uncompressed(&Scalar::from_bits(secret_key.to_bytes()))))
    }

    /// Constructs an uncompressed VerificationKey point from a private key.
    pub(crate) fn from_secret_uncompressed(privkey: &Scalar) -> RistrettoPoint {
        privkey * &curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE
    }


}


impl From<SecretKey> for PublicKey {
    fn from(source: SecretKey) -> PublicKey {
        PublicKey::from_secret(&source)
    }
}


serde_boilerplate!(PublicKey);

//Ordering Support, needed to be specific for MuSig 

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        // Although this is slower than `self.compressed == other.compressed`, expanded point comparison is an equal
        // time comparision
        self.as_point() == other.as_point()
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<std::cmp::Ordering> {
        self.to_bytes().partial_cmp(&other.to_bytes())
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}
