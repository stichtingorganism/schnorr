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


//! A Rust implementation of Schnorr key generation, signing,
//! and verification.


use core::default::Default;
use core::fmt::{Debug};
use serde::{Serialize, Deserialize};
use serde::{Serializer, Deserializer};
use serde::de::Error as SerdeError;
use serde::de::Visitor;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::digest::Digest;
use rand::CryptoRng;
use rand::Rng;
use clear_on_drop::clear::Clear;
use errors::SchnorrError;
use errors::InternalError;


/// The length of a curve25519 Schnorr `Signature`, in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// The length of a curve25519 Schnorr `SecretKey`, in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;

/// The length of an ed25519 Schnorr `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;

/// The length of an ed25519 Schnorr `Keypair`, in bytes.
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// The length of a Blake2b hash used Schnorr `Signature`, in bytes.
pub const HASH_LENGTH: usize = 64;


/// An Schnorr signature.
///
/// # Note
///
/// These signatures are "detached"—that is, they do **not** include a copy 
/// of the message which has been signed.
#[allow(non_snake_case)]
#[derive(Copy, Eq, PartialEq)]
#[repr(C)]
pub struct Signature {
    /// `R` is an `RistrettoPoint`, formed by taking the sampled
    /// random integer `r` in ℤp for each message to be signed.
    ///
    /// This integer is then interpreted as a `Scalar`.
    /// The scalar is then multiplied by the distinguished
    /// basepoint to produce `R`, and `RistrettoPoint`.
    pub (crate) R: CompressedRistretto,

    /// `s` is a `Scalar`, formed by s = r + cx
    /// c = HASH(PublicKey, R, message)
    ///
    /// - the `r` portion of this `Signature`,
    /// - the 'x' is the secret key signing
    /// - the `c` is the Hash of the data
    ///
    /// - the `PublicKey` which should be used to verify this `Signature`, and
    /// - the message to be signed.
    pub (crate) s: Scalar,
}


impl Clone for Signature {
    fn clone(&self) -> Self { *self }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "Signature( R: {:?}, s: {:?} )", &self.R, &self.s)
    }
}


impl Signature {
    /// Convert this `Signature` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut signature_bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];

        signature_bytes[..32].copy_from_slice(&self.R.as_bytes()[..]);
        signature_bytes[32..].copy_from_slice(&self.s.as_bytes()[..]);
        signature_bytes
    }

    /// Construct a `Signature` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, SchnorrError> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(SchnorrError(InternalError::BytesLengthError{
                name: "Signature", length: SIGNATURE_LENGTH }));
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);

        if upper[31] & 224 != 0 {
            return Err(SchnorrError(InternalError::ScalarFormatError));
        }

        Ok(Signature{ R: CompressedRistretto(lower), s: Scalar::from_bits(upper) })
    }
}


impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}


impl<'d> Deserialize<'d> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {
        struct SignatureVisitor;

        impl<'d> Visitor<'d> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An Schnorr signature as 64 bytes.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Signature, E> where E: SerdeError{
                Signature::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SignatureVisitor)
    }
}


/// An Schnorr secret key.
#[repr(C)]
#[derive(Default)] // we derive Default in order to use the clear() method in Drop
pub struct SecretKey(pub (crate) [u8; SECRET_KEY_LENGTH]);

impl Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "SecretKey: {:?}", &self.0[..])
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl SecretKey {

    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate schnorr;
    /// #
    /// use schnorr::SecretKey;
    /// use schnorr::SECRET_KEY_LENGTH;
    /// use schnorr::SchnorrError;
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
            return Err(SchnorrError(InternalError::BytesLengthError{
                name: "SecretKey", length: SECRET_KEY_LENGTH }));
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(SecretKey(bits))
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
    /// use schnorr::PublicKey;
    /// use schnorr::SecretKey;
    /// use schnorr::Signature;
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
    /// # use schnorr::PublicKey;
    /// # use schnorr::SecretKey;
    /// # use schnorr::Signature;
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
        let mut sk: SecretKey = SecretKey([0u8; 32]);

        csprng.fill_bytes(&mut sk.0);

        sk
    }

    // Sign a message with this `SecretKey`.
    #[allow(non_snake_case)]
    pub fn sign<D, T>(&self, csprng: &mut T, message: &[u8], public_key: &PublicKey) -> Signature
        where D:  Digest<OutputSize = U64> + Default, T: CryptoRng + Rng, 
    {

        //c = H(public_key, R, message)
        let mut h: D = D::default();
        //random integer `r`
        let r: Scalar =  Scalar::random(csprng);
        //R = g^r
        let R: CompressedRistretto = (&r * &RISTRETTO_BASEPOINT_TABLE).compress();
        
        //first we hash public key, makes it binding
        h.input(public_key.as_bytes());
        //second we hash in blinded randomness
        h.input(R.as_bytes());
        //lastly we hash the given message
        h.input(&message);

        //convert hash into scalar
        let c: Scalar = Scalar::from_hash(h);

        //decode secret key into scalar
        let mut bits = self.0.clone();
        bits[0]  &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        let sk_as_scalar = Scalar::from_bits(bits);

        //s = r + cx
        let s = &r + &(&c * &sk_as_scalar);

        Signature{ R, s }
    }


}


impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(self.as_bytes())
    }
}


impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {
        struct SecretKeyVisitor;

        impl<'d> Visitor<'d> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An Schnorr secret key as 32 bytes.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey, E> where E: SerdeError {
                SecretKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SecretKeyVisitor)
    }
}


/// An Schnorr public key.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
#[repr(C)]
pub struct PublicKey(pub (crate) CompressedRistretto);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "PublicKey( CompressedRistretto( {:?} ))", self.0)
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes<'a>(&'a self) -> &'a [u8; PUBLIC_KEY_LENGTH] {
        &(self.0).0
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
    /// use schnorr::PublicKey;
    /// use schnorr::PUBLIC_KEY_LENGTH;
    /// use schnorr::SchnorrError;
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
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(SchnorrError(InternalError::BytesLengthError{
                name: "PublicKey", length: PUBLIC_KEY_LENGTH }));
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(PublicKey(CompressedRistretto(bits)))
    }

    /// Derive this public key from its corresponding `SecretKey`.
    #[allow(unused_assignments)]
    pub fn from_secret(secret_key: &SecretKey) -> PublicKey {
        //get sk as byte array
        let mut bits = secret_key.to_bytes();
        //dervive pk from given sk
        PublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut bits)
    }


    /// Internal utility function for mangling the bits of a (formerly
    /// mathematically well-defined) "scalar" and multiplying it to produce a
    /// public key.
    fn mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(bits: &mut [u8; 32]) -> PublicKey {
        //decode scalar
        bits[0]  &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        let pk = (&Scalar::from_bits(*bits) * &RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();

        PublicKey(CompressedRistretto(pk))
    }

    /// Verify a signature on a message with this keypair's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    pub fn verify<D>(&self, message: &[u8], signature: &Signature) -> Result<(), SchnorrError>
            where D: Digest<OutputSize = U64> + Default
    {
        //If g^s == RX^c then we have valid signature.

        //g^s
        let left = &signature.s * &RISTRETTO_BASEPOINT_TABLE;

        //Get our public key as a curve point.
        let X: RistrettoPoint = match self.0.decompress() {
            Some(x) => x,
            None    => return Err(SchnorrError(InternalError::PointDecompressionError)),
        };

        //Get our signature as a curve point.
        let R: RistrettoPoint = match signature.R.decompress() {
            Some(r) => r,
            None    => return Err(SchnorrError(InternalError::PointDecompressionError)),
        };

        //c = H(public_key, R, message)
        let mut h: D = D::default();
        //first we hash public key, makes it binding
        h.input(self.as_bytes());
        //second we hash in blinded randomness
        h.input(signature.R.as_bytes());
        //lastly we hash the given message
        h.input(&message);

        let c = Scalar::from_hash(h);

        //RX^c
        let right = &R + (&X * &c);

        if left == right {
            Ok(())
        } else {
            Err(SchnorrError(InternalError::VerifyError))
        }
    }

    /// Helper Method to Get our public key as a curve point.
    pub fn get_curve_point(&self) -> Result<RistrettoPoint, SchnorrError> { 
        match self.0.decompress() {
            Some(x) => return Ok(x),
            None    => return Err(SchnorrError(InternalError::PointDecompressionError)),
        }
    }

}

    

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(self.as_bytes())
    }
}


impl<'d> Deserialize<'d> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {

        struct PublicKeyVisitor;

        impl<'d> Visitor<'d> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An Schnorr public key as a 32-byte compressed point")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<PublicKey, E> where E: SerdeError {
                PublicKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}


/// An Schnorr keypair.
#[derive(Debug, Default)] // we derive Default in order to use the clear() method in Drop
#[repr(C)]
pub struct Keypair {
    /// The secret half of this keypair.
    pub secret: SecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
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
            return Err(SchnorrError(InternalError::BytesLengthError{
                name: "Keypair", length: KEYPAIR_LENGTH}));
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
    /// use rand::OsRng;
    /// use schnorr::Keypair;
    /// use schnorr::Signature;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
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
        where R: CryptoRng + Rng,
    {
        let sk: SecretKey = SecretKey::generate(csprng);
        let pk: PublicKey = PublicKey::from_secret(&sk);

        Keypair{ public: pk, secret: sk }
    }

    /// Sign a message with this keypair's secret key.
    pub fn sign<D, T>(&self, csprng: &mut T, message: &[u8]) -> Signature
        where D: Digest<OutputSize = U64> + Default, T: CryptoRng + Rng
    {
        self.secret.sign::<D, T>(csprng, &message, &self.public)
    }


    /// Verify a signature on a message with this keypair's public key.
    pub fn verify<D>(&self, message: &[u8], signature: &Signature) -> Result<(), SchnorrError>
            where D: Digest<OutputSize = U64> + Default {
        self.public.verify::<D>(message, signature)
    }
}


impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}


impl<'d> Deserialize<'d> for Keypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'d> {

        struct KeypairVisitor;

        impl<'d> Visitor<'d> for KeypairVisitor {
            type Value = Keypair;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("An Schnorr keypair, 64 bytes in total where the secret key is \
                                     the first 32 bytes and the second \
                                     32 bytes is a compressed point for a public key.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Keypair, E> where E: SerdeError {
                let secret_key = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH]);
                let public_key = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..]);

                if secret_key.is_ok() && public_key.is_ok() {
                    Ok(Keypair{ secret: secret_key.unwrap(), public: public_key.unwrap() })
                } else {
                    Err(SerdeError::invalid_length(bytes.len(), &self))
                }
            }
        }
        deserializer.deserialize_bytes(KeypairVisitor)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use rand::ChaChaRng;
    use rand::SeedableRng;
    use blake2::Blake2b;

    #[test]
    fn sign_verify() {  // TestSignVerify
        let mut csprng: ChaChaRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let good: &[u8] = "test message".as_bytes();
        let bad:  &[u8] = "wrong message".as_bytes();

        csprng  = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign::<Blake2b, _>(&mut csprng, &good);
        bad_sig  = keypair.sign::<Blake2b, _>(&mut csprng, &bad);

        assert!(keypair.verify::<Blake2b>(&good, &good_sig).is_ok(),
                "Verification of a valid signature failed!");
        assert!(keypair.verify::<Blake2b>(&good, &bad_sig).is_err(),
                "Verification of a signature on a different message passed!");
        assert!(keypair.verify::<Blake2b>(&bad,  &good_sig).is_err(),
                "Verification of a signature on a different message passed!");
    }

    //     #[test]
    // fn keypair_clear_on_drop() {
    //     let mut keypair: Keypair = Keypair::from_bytes(&[15u8; KEYPAIR_LENGTH][..]).unwrap();

    //     keypair.clear();

    //     fn as_bytes<T>(x: &T) -> &[u8] {
    //         use core::mem;
    //         use core::slice;

    //         unsafe {
    //             slice::from_raw_parts(x as *const T as *const u8, mem::size_of_val(x))
    //         }
    //     }

    //     assert!(!as_bytes(&keypair).contains(&0x15));
    // }



}