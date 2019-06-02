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

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use mohan::merlin::Transcript;
use core::fmt::Debug;
use crate::errors::{SchnorrError, InternalError};
use curve25519_dalek::digest::{FixedOutput, ExtendableOutput, XofReader};
use curve25519_dalek::digest::generic_array::typenum::{U32,U64};


//
// Public Coin Abstraction
//


/// Extension trait to the Merlin transcript API that allows committing scalars and points and
/// generating challenges as scalars.
pub trait TranscriptProtocol {
    /// Extend transcript with some bytes, shadowed by `merlin::Transcript`.
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]);

    /// Commit a `scalar` with the given `label`.
    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    /// Commit a `point` with the given `label`.
    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;

    /// Extend transcript with a protocol name
    fn proto_name(&mut self, label: &'static [u8]) {
        self.commit_bytes(b"proto-name", label);
    }
}



impl TranscriptProtocol for Transcript {

     #[inline(always)]
    fn commit_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {  
       self.commit_bytes(label,bytes)  
    }

    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.commit_bytes(label, scalar.as_bytes());
    }

    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.commit_bytes(label, point.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }
}

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
        t.commit_bytes(b"sign-bytes", bytes);
        t
    }

    /// Initalize an owned signing transcript on a message provided as a hash function with extensible output
    pub fn xof<D: ExtendableOutput>(&self, h: D) -> Transcript {

        let mut prehash = [0u8; 32];
        h.xof_result().read(&mut prehash);
        let mut t = self.0.clone();

        t.commit_bytes(b"sign-XoF", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 256 bit output.
    pub fn from_hash256<D: FixedOutput<OutputSize=U32>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 32]; 
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.commit_bytes(b"sign-256", &prehash);
        t
    }

    /// Initalize an owned signing transcript on a message provided as
    /// a hash function with 512 bit output, usually a gross over kill.
    pub fn from_hash512<D: FixedOutput<OutputSize=U64>>(&self, h: D) -> Transcript {
        let mut prehash = [0u8; 64]; 
        prehash.copy_from_slice(h.fixed_result().as_slice());
        let mut t = self.0.clone();
        t.commit_bytes(b"sign-256", &prehash);
        t
    }

}

//
// Ristretto Helper Abstraction
//

/// Compressed Ristretto point length
pub const RISTRETTO_POINT_LENGTH: usize = 32;

/// A `RistrettoBoth` contains both an uncompressed `RistrettoPoint`
/// as well as the corresponding `CompressedRistretto`.  It provides
/// a convenient middle ground for protocols that both hash compressed
/// points to derive scalars for use with uncompressed points.
#[derive(Copy, Clone, Default, Eq)]  // PartialEq optimnized below
pub struct RistrettoBoth {
    compressed: CompressedRistretto,
    point: RistrettoPoint,
}

impl Debug for RistrettoBoth {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "RistrettoPoint( {:?} )", self.compressed)
    }
}

impl RistrettoBoth {

    const DESCRIPTION : &'static str = "A ristretto point represented as a 32-byte compressed point";

    /// Access the compressed Ristretto form
    pub fn as_compressed(&self) -> &CompressedRistretto { &self.compressed }

    /// Extract the compressed Ristretto form
    pub fn into_compressed(self) -> CompressedRistretto { self.compressed }

    /// Access the point form
    pub fn as_point(&self) -> &RistrettoPoint { &self.point }

    /// Extract the point form
    pub fn into_point(self) -> RistrettoPoint { self.point }

    /// Decompress into the `RistrettoBoth` format that also retains the
    /// compressed form.
    pub fn from_compressed(compressed: CompressedRistretto) -> Result<RistrettoBoth, SchnorrError> {
        Ok(RistrettoBoth {
            point: compressed.decompress().ok_or(SchnorrError(InternalError::PointDecompressionError)) ?,
            compressed,
        })
    }

    /// Compress into the `RistrettoBoth` format that also retains the
    /// uncompressed form.
    pub fn from_point(point: RistrettoPoint) -> RistrettoBoth {
        RistrettoBoth {
            compressed: point.compress(),
            point,
        }
    }

    /// Convert this point to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; RISTRETTO_POINT_LENGTH] {
        self.compressed.to_bytes()
    }

     /// Convert this point to a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; RISTRETTO_POINT_LENGTH] {
        self.compressed.as_bytes()
    }

    /// Construct a `RistrettoBoth` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// The caller is responsible for ensuring that the bytes passed into this
    /// method actually represent a `curve25519_dalek::ristretto::CompressedRistretto`
    /// and that said compressed point is actually a point on the curve.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate schnorr;
    /// #
    /// use schnorr::prelude::*;
    /// use schnorr::tools::RistrettoBoth;
    ///
    /// # fn doctest() -> Result<RistrettoBoth, SchnorrError> {
    /// let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [
    ///    215,  90, 152,   1, 130, 177,  10, 183, 213,  75, 254, 211, 201, 100,   7,  58,
    ///     14, 225, 114, 243, 218, 166,  35,  37, 175,   2,  26, 104, 247,   7,   81, 26];
    ///
    /// let public_key = RistrettoBoth::from_bytes(&public_key_bytes)?;
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
    /// A `Result` whose okay value is an EdDSA `RistrettoBoth` or whose error value
    /// is an `SignatureError` describing the error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<RistrettoBoth, SchnorrError> {
        RistrettoBoth::from_bytes_ser("RistrettoBoth", RistrettoBoth::DESCRIPTION, bytes)
    }

    /// Variant of `RistrettoBoth::from_bytes` that propogates more informative errors.
    #[inline]
    pub fn from_bytes_ser(name: &'static str, description: &'static str, bytes: &[u8]) -> Result<RistrettoBoth, SchnorrError> {
       
        if bytes.len() != RISTRETTO_POINT_LENGTH {
            return Err(SchnorrError(InternalError::BytesLengthError{
                name, description, length: RISTRETTO_POINT_LENGTH }));
        }

        let mut compressed = CompressedRistretto([0u8; RISTRETTO_POINT_LENGTH]);
        compressed.0.copy_from_slice(&bytes[..32]);
        RistrettoBoth::from_compressed(compressed)
    }
}

serde_boilerplate!(RistrettoBoth);

/// We hide fields largely so that only compairing the compressed forms works.
impl PartialEq<Self> for RistrettoBoth {
    fn eq(&self, other: &Self) -> bool {
        let r = self.compressed.eq(&other.compressed);
        debug_assert_eq!(r, self.point.eq(&other.point));
        r
    }

    // fn ne(&self, other: &Rhs) -> bool {
    //   self.compressed.0.ne(&other.compressed.0)
    // }
}


impl PartialOrd<RistrettoBoth> for RistrettoBoth {
    fn partial_cmp(&self, other: &RistrettoBoth) -> Option<::core::cmp::Ordering> {
        self.compressed.0.partial_cmp(&other.compressed.0)
    }

    // fn lt(&self, other: &RistrettoBoth) -> bool {
    //    self.compressed.0.lt(&other.compressed.0)
    // }
    // fn le(&self, other: &RistrettoBoth) -> bool {
    //    self.compressed.0.le(&other.compressed.0)
    // }
    // fn gt(&self, other: &RistrettoBoth) -> bool {
    //    self.compressed.0.gt(&other.compressed.0)
    // }
    // fn ge(&self, other: &RistrettoBoth) -> bool {
    //    self.compressed.0.ge(&other.compressed.0)
    // }
}

impl Ord for RistrettoBoth {
    fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        self.compressed.0.cmp(&other.compressed.0)
    }

    // fn max(self, other: Self) -> Self {
    //    self.compressed.0.max(other.compressed.0)
    // }
    // fn min(self, other: Self) -> Self {
    //    self.compressed.0.min(other.compressed.0)
    // }
}

impl ::core::hash::Hash for RistrettoBoth {
    fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
        self.compressed.0.hash(state);
    }
}