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

//! Implementation of the key tree protocol, a key blinding scheme for deriving hierarchies of public keys.

use core::fmt::Debug;
use curve25519_dalek::scalar::Scalar;
use subtle::{Choice,ConstantTimeEq};
use clear_on_drop::clear::Clear;
use crate::keys::{SecretKey, SECRET_KEY_LENGTH, PublicKey, PUBLIC_KEY_LENGTH };
use rand::{Rng, CryptoRng};
use crate::errors::{SchnorrError, InternalError};
use mohan::merlin::Transcript;
use crate::tools::{TranscriptProtocol};
use curve25519_dalek::ristretto::{CompressedRistretto};
use curve25519_dalek::constants;

/// The length of the "Derivation key" portion of a Extended Schnorr public key, in bytes.
const EXTENDED_PUBLIC_KEY_NONCE_LENGTH: usize = 32;
/// The length of an extended curve25519 Schnorr key, `SecretKey`, in bytes.
pub const EXTENDED_PUBLIC_KEY_LENGTH: usize = PUBLIC_KEY_LENGTH + EXTENDED_PUBLIC_KEY_NONCE_LENGTH;
/// The length of the "nonce" portion of a Extended Schnorr secret key, in bytes.
const EXTENDED_SECRET_KEY_NONCE_LENGTH: usize = 32;
/// The length of an extended curve25519 Schnorr key, `SecretKey`, in bytes.
pub const EXTENDED_SECRET_KEY_LENGTH: usize = SECRET_KEY_LENGTH + EXTENDED_SECRET_KEY_NONCE_LENGTH;


/// An Extended seceret key for use with Ristretto Schnorr signatures.
#[derive(Default)] // we derive Default in order to use the clear() method in Drop
pub struct XSecretKey {
    /// Actual Secret key represented as a scalar.
    pub (crate) key: SecretKey,

    /// Holds the extended public key point of this secret key 
    pub (crate) xpub: XPublicKey
}


impl Debug for XSecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "XSecretKey {{ key: {:?} nonce: {:?} }}", &self.key, &self.xpub.derivation_key)
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for XSecretKey {
    fn drop(&mut self) {
        self.key.clear();
        self.xpub.derivation_key.clear();
        self.xpub.clear();
    }
}

impl Eq for XSecretKey {}
impl PartialEq for XSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1u8
    }
}

impl ConstantTimeEq for XSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

impl From<&SecretKey> for XSecretKey {
    // / Construct an `SecretKey` from a `MiniSecretKey`.
    // /
    // / # Examples
    // /
    // / ```
    // / # extern crate rand;
    // / # extern crate blake2;
    // / # extern crate schnorr;
    // / #
    // / # fn main() {
    // / use rand::{Rng, rngs::OsRng};
    // / use blake2::Blake2b;
    // / use schnorr::prelude::*;
    // /
    // / let mut csprng: OsRng = OsRng::new().unwrap();
    // / let mini_secret_key: SecretKey = SecretKey::generate(&mut csprng);
    // / let secret_key: XSecretKey = XSecretKey::from(&mini_secret_key);
    // / # }
    // / ```
    fn from(msk: &SecretKey) -> XSecretKey {
       XSecretKey::from_secret(msk)
    }
}


impl XSecretKey {

    const DESCRIPTION : &'static str = "An Schnorr expanded secret key as 64 bytes, as specified in Keytree Protocol.";
   
    /// Convert this `SecretKey` into an array of 64 bytes, corresponding to
    /// an Ristrettp expanded secreyt key.
    ///
    /// # Returns
    ///
    /// An array of 64 bytes.  The first 32 bytes represent the "expanded"
    /// secret key, and the last 32 bytes represent the "domain-separation"
    /// "nonce".
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate blake2;
    /// # extern crate schnorr;
    /// #
    /// # fn main() {
    /// use rand::{Rng, rngs::OsRng};
    /// use blake2::Blake2b;
    /// use schnorr::prelude::*;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let mini_secret_key: SecretKey = SecretKey::generate(&mut csprng);
    /// let secret_key: XSecretKey = XSecretKey::from(&mini_secret_key);
    /// let secret_key_bytes: [u8; 64] = secret_key.to_bytes();
    ///
    /// assert!(&secret_key_bytes[..] != &[0u8; 64][..]);
    /// # }
    /// ```
    #[inline]
    pub fn to_bytes(&self) -> [u8; EXTENDED_SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];
        let key = self.key.to_bytes();
        bytes[..32].copy_from_slice(&key[..]);
        bytes[32..].copy_from_slice(&self.xpub.derivation_key[..]);
        bytes
    }

    /// Construct an `SecretKey` from a slice of bytes.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `SecretKey` or whose
    /// error value is an `SignatureError` describing the error that occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rand;
    /// # extern crate blake2;
    /// # extern crate schnorr;
    /// #
    /// use schnorr::prelude::*;
    /// use rand::{Rng, rngs::OsRng};
    /// # fn do_test() -> Result<XSecretKey, SchnorrError> {
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let secret_key: SecretKey = SecretKey::generate(&mut csprng);
    /// let ex_secret_key: XSecretKey = XSecretKey::from(&secret_key);
    /// let bytes: [u8; 64] = ex_secret_key.to_bytes();
    /// let secret_key_again = XSecretKey::from_bytes(&bytes) ?;
    /// #
    /// # Ok(secret_key_again)
    /// # }
    /// #
    /// # fn main() {
    /// #     let result = do_test();
    /// #     assert!(result.is_ok());
    /// # }
    /// ```
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<XSecretKey, SchnorrError> {

        if bytes.len() != EXTENDED_SECRET_KEY_LENGTH {
             return Err(SchnorrError(InternalError::BytesLengthError{
                name: "XSecretKey",  
                description: XSecretKey::DESCRIPTION, 
                length: EXTENDED_SECRET_KEY_LENGTH 
            }));
        }

        let mut key: [u8; 32] = [0u8; 32];
        key.copy_from_slice(&bytes[00..32]);

        let scalar =  Scalar::from_bits(key);
        //return Err(SchnorrError(InternalError::ScalarFormatError)),
     
        let mut nonce: [u8; 32] = [0u8; 32];
        nonce.copy_from_slice(&bytes[32..64]);


        Ok(XSecretKey{
            key: SecretKey(scalar),
            xpub: XPublicKey {
                key: PublicKey::from_point(scalar * &constants::RISTRETTO_BASEPOINT_POINT),
                derivation_key: nonce,
            }
        })
    }

    /// Generate an `Extended SecretKey` directly, 
    pub fn generate<R>(mut csprng: R) -> XSecretKey
        where R: CryptoRng + Rng,
    {
        let scalar = Scalar::random(&mut csprng);
        let mut nonce: [u8; 32] = [0u8; 32];
        csprng.fill_bytes(&mut nonce);

        XSecretKey { 
            key: SecretKey(scalar), 
            xpub: XPublicKey {
                key: PublicKey::from_point(scalar * &constants::RISTRETTO_BASEPOINT_POINT),
                derivation_key: nonce,
            }
        }
    }

    /// Derive the `XPublicKey` corresponding to this `SecretKey`.
    pub fn to_public(&self) -> XPublicKey {
        self.xpub.clone() 
    }

    /// Return Reference the `XPublicKey` corresponding to this `SecretKey`.
    pub fn as_xpub(&self) -> &XPublicKey {
        &self.xpub
    }

    /// Derive the `XSecretKey` from given SecretKey.
    pub fn from_secret(secret: &SecretKey) -> XSecretKey {
        //1. Create a Merlin transcript
        let mut t = Transcript::new(b"Schnorr.derivation");

        //We derive the nonce has the second half of the 512bit hash of secret
        t.commit_bytes(b"secret_key", secret.as_bytes());
   
        let key = t.challenge_scalar(b"Schnorr.derivation.key");

        // squeeze a new derivation key
        let mut nonce = [0u8; 32];
        //Squeeze a new nonce (32 bytes):
        t.challenge_bytes(b"Schnorr.derivation.nonce", &mut nonce);

        XSecretKey {
            key: SecretKey(key),
            xpub: XPublicKey {
                key: PublicKey::from_point(&key * &constants::RISTRETTO_BASEPOINT_POINT),
                derivation_key: nonce,
            }
        }

    }


    /// Returns a intermediate child xprv. Users must provide customize, in order to separate
    /// sibling keys from one another through unique derivation paths.
    pub fn derive_intermediate_key(&self, customize: impl FnOnce(&mut Transcript)) -> XSecretKey {
        let (child_xpub, f) = self.xpub
            .derive_intermediate_helper(self.xpub.prepare_prf(), customize);

        XSecretKey {
            //If you are deriving a child Xprv from a parent Xprv:: parent.point + f
            key:  SecretKey::from_scalar(self.key.as_scalar() + f),
            xpub: child_xpub,
        }
    }

    /// Returns a leaf private key. Users must provide customize, in order to
    /// separate sibling keys from one another through unique derivation paths.
    pub fn derive_key(&self, customize: impl FnOnce(&mut Transcript)) -> SecretKey {
        //5. Squeeze a blinding factor f: a challenge scalar
        let f = self.xpub.derive_leaf_helper(self.xpub.prepare_prf(), customize);
        //6. If you are deriving a child Xprv from a parent Xprv: child = parent.scalar + f
        SecretKey::from_scalar(self.key.as_scalar() + f)
    }


}


/// Xpub represents an extended public key.
#[derive(Default, Clone)]
pub struct XPublicKey {
    //public key 
    pub key: PublicKey,
 
    /// Seed for deriving the nonces used in signing.
    ///
    /// We require this be random and secret or else key compromise attacks will ensue.
    /// Any modificaiton here may dirupt some non-public key derivation techniques.
    pub (crate) derivation_key: [u8; 32],

}


impl XPublicKey {

    /// Returns a intermediate child pubkey. Users must provide customize, in order to separate
    /// sibling keys from one another through unique derivation paths.
    pub fn derive_intermediate_key(&self, customize: impl FnOnce(&mut Transcript)) -> XPublicKey {
        let (xpub, _f) = self.derive_intermediate_helper(self.prepare_prf(), customize);
        xpub
    }

    /// Returns a leaf Xpub, which can safely be shared.
    /// Users must provide customize, in order to separate sibling keys from one another
    /// through unique derivation paths.
    pub fn derive_key(&self, customize: impl FnOnce(&mut Transcript)) -> PublicKey {
        let f = self.derive_leaf_helper(self.prepare_prf(), customize);

        //6. If you are deriving a child Xpub from a parent Xpub: child = parent.point + f·B
        PublicKey::from_point(self.key.as_point() + (&f * &constants::RISTRETTO_BASEPOINT_POINT))
    }

    /// Serializes this Xpub to a sequence of bytes.
    pub fn to_bytes(&self) -> [u8; EXTENDED_PUBLIC_KEY_LENGTH] {
        let mut buf = [0u8; EXTENDED_PUBLIC_KEY_LENGTH];
        buf[..32].copy_from_slice(self.key.as_bytes());
        buf[32..].copy_from_slice(&self.derivation_key);
        buf
    }

    /// Decodes an Xpub from a 64-byte array, and fails if the provided array is not
    /// exactly 64 bytes, or if the compressed point fails to decompress.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != EXTENDED_PUBLIC_KEY_LENGTH {
            return None;
        }

        let precompressed_pubkey = CompressedRistretto::from_slice(&bytes[..32]);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&bytes[32..]);

        let key = match  PublicKey::from_compressed(precompressed_pubkey) {
            Ok(p) => p,
            Err(_) => return None,
        };

        Some(XPublicKey {
            key: key,
            derivation_key: dk,
        })
    }

    ///Helper Method To Prepare our transcipt
    fn prepare_prf(&self) -> Transcript {
        //1. Create a Merlin transcript
        let mut t = Transcript::new(b"Keytree.derivation");
        //3. Commit xpub to the transcript:
        t.commit_point(b"pt", self.key.as_compressed());
        t.commit_bytes(b"dk", &self.derivation_key);
       
        t
    }


    fn derive_intermediate_helper(
        &self,
        mut prf: Transcript,
        customize: impl FnOnce(&mut Transcript),
    ) -> (XPublicKey, Scalar) {

        //4. Provide the transcript to the user to commit an arbitrary derivation path or index:
        // change the derivation path for this key
        customize(&mut prf);

        //5. Squeeze a blinding factor f: a challenge scalar
        let f = prf.challenge_scalar(b"f.intermediate");
        
        //6. Squeeze a new derivation key
        let mut child_dk = [0u8; 32];
        prf.challenge_bytes(b"dk", &mut child_dk);

        //point: parent.point + f·B
        let child_point = self.key.as_point() + (&f * &constants::RISTRETTO_BASEPOINT_POINT);


        //7. If you are deriving a child Xpub from a parent Xpub:
       let xpub = XPublicKey {
            key: PublicKey::from_point(child_point),
            derivation_key: child_dk,
        };

        (xpub, f)
    }

    fn derive_leaf_helper(
        &self,
        mut prf: Transcript,
        customize: impl FnOnce(&mut Transcript),
    ) -> Scalar {
        //4. Provide the transcript to the user to commit an arbitrary derivation path or index:
        // change the derivation path for this key
        customize(&mut prf);
        //5. Squeeze a blinding factor f: a challenge scalar
        prf.challenge_scalar(b"f.leaf")
    }
}






#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_vectors() {

        let root_prv = XSecretKey::default();
        let root_pub = root_prv.to_public();

        assert_eq!(
            to_hex_64(root_prv.to_bytes()),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            to_hex_64(root_pub.to_bytes()),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );

        let child_prv = root_prv.derive_intermediate_key(|prf| prf.commit_u64(b"index", 1));
        let child_pub = root_pub.derive_intermediate_key(|prf| prf.commit_u64(b"index", 1));
        assert_eq!(
            to_hex_64(child_prv.to_bytes()),
            "ba9bead5df738767ca184900a4a09ce8afe9f7696e8d3ac1fd99f607a785bf005237586d5b496618a49a876e9a7e077b1715f8635b41b48edcaf2934ebe62683"
        );
        assert_eq!(
            to_hex_64(child_pub.to_bytes()),
            "2ec9d53d9d43b86c73694f4acd4be1c274a3cf8d7512e91acebafc0ed884dd475237586d5b496618a49a876e9a7e077b1715f8635b41b48edcaf2934ebe62683"
        );
        assert_eq!(
            to_hex_64(child_prv.to_public().to_bytes()),
            "2ec9d53d9d43b86c73694f4acd4be1c274a3cf8d7512e91acebafc0ed884dd475237586d5b496618a49a876e9a7e077b1715f8635b41b48edcaf2934ebe62683"
        );

        // Note: the leaf keys must be domain-separated from the intermediate keys, even if using the same PRF customization
        let child2_prv = child_prv.derive_intermediate_key(|prf| prf.commit_u64(b"index", 1));
        let child2_pub = child_pub.derive_intermediate_key(|prf| prf.commit_u64(b"index", 1));
        assert_eq!(
            to_hex_64(child2_prv.to_bytes()),
            "d4719a691dc4e97b27abfc50764d0369a197b3d03b049f0654d4872dd5f01f02f334cb814294776de8551a4e6382c14d05ad2eb6d6391e87069a3fbe2e6ecf77"
        );
        assert_eq!(
            to_hex_64(child2_pub.to_bytes()),
            "1210a34624dfddb312da90ad5e2d3d4649d7eb50d44dad00972d1e1f422a4f29f334cb814294776de8551a4e6382c14d05ad2eb6d6391e87069a3fbe2e6ecf77"
        );
        assert_eq!(
            to_hex_64(child2_prv.to_public().to_bytes()),
            "1210a34624dfddb312da90ad5e2d3d4649d7eb50d44dad00972d1e1f422a4f29f334cb814294776de8551a4e6382c14d05ad2eb6d6391e87069a3fbe2e6ecf77"
        );

        let leaf_prv = child_prv.derive_key(|prf| prf.commit_u64(b"index", 1));
        let leaf_pub = child_pub.derive_key(|prf| prf.commit_u64(b"index", 1));
        assert_eq!(
            hex::encode(leaf_prv.to_bytes()),
            "a7a8928dfeae1479a7bf908bfa929b714a62fe334b68e4557105414113ffca04"
        );
        assert_eq!(
            hex::encode(leaf_pub.to_bytes()),
            "52ea0c9ce1540e65041565a1057aa6965bbb5b42709c1109da16609248a9d679"
        );
        assert_eq!(
            hex::encode(PublicKey::from(leaf_prv).to_bytes()),
            "52ea0c9ce1540e65041565a1057aa6965bbb5b42709c1109da16609248a9d679"
        );
    }

    #[test]
    fn test_defaults() {
        let default_xprv = XSecretKey::default();
        let default_xpub = XPublicKey::default();
        assert_eq!(
            to_hex_64(default_xprv.to_bytes()),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            to_hex_64(default_xpub.to_bytes()),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            to_hex_64(default_xpub.to_bytes()),
            to_hex_64(default_xprv.to_public().to_bytes())
        );

        let default_xprv = XSecretKey::from_bytes(&hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
        assert_eq!(
            to_hex_64(default_xprv.to_bytes()),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        let default_xpub = XPublicKey::from_bytes(&hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
        assert_eq!(
            to_hex_64(default_xpub.to_bytes()),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn random_xprv_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = XSecretKey::generate(&mut rng);

        // the following are hard-coded based on the previous seed
        assert_eq!(
            to_hex_32(xprv.xpub.derivation_key),
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
        assert_eq!(
            hex::encode(xprv.key.as_bytes()),
            "4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c901"
        );
    }

    #[test]
    fn random_xprv_derivation_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = XSecretKey::generate(&mut rng).derive_intermediate_key(|t| {
            t.commit_u64(b"account_id", 34);
        });

        assert_eq!(
            hex::encode(xprv.key.as_bytes()),
            "55d65740c47cff19c35c2787dbc0e207e901fbb311caa4d583da8efdc7088b03"
        );
        assert_eq!(
            to_hex_32(xprv.xpub.derivation_key),
            "36e435eabc2a562ef228b82b399fbd004b2cc64103313fa673bd1fca0971f59d"
        );
        assert_eq!(
            to_hex_32(xprv.xpub.key.to_bytes()),
            "7414c0c5238c2277318ba3e51fc6fb8e836a2d9b4c04508f93cd5a455422221b"
        );
    }

    #[test]
    fn random_xprv_leaf_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = XSecretKey::generate(&mut rng).derive_key(|t| {
            t.commit_u64(b"invoice_id", 10034);
        });

        assert_eq!(
            hex::encode(xprv.as_bytes()),
            "a71e5435c3374eef60928c3bac1378dcbc91bc1d554e09242247a0861fd12c0c"
        );
    }

    #[test]
    fn serialize_xprv_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = XSecretKey::generate(&mut rng);
        let xprv_bytes = xprv.to_bytes();

        assert_eq!(
            to_hex_64(xprv_bytes),
            "4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c9019f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
    }

    #[test]
    fn deserialize_xprv_test() {
        let xprv_bytes = hex::decode("4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c9019f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed").unwrap();
        let xprv = XSecretKey::from_bytes(&xprv_bytes).unwrap();

        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let expected_xprv = XSecretKey::generate(&mut rng);

        assert_eq!(xprv.xpub.derivation_key, expected_xprv.xpub.derivation_key);
        assert_eq!(xprv.key, expected_xprv.key);
    }

    #[test]
    fn random_xpub_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = XSecretKey::generate(&mut rng);
        let xpub = xprv.to_public();

        // hex strings are hard-coded based on the previous seed
        assert_eq!(
            to_hex_32(xpub.derivation_key),
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
        //assert_eq!(xpub.key.compress(), xpub.precompressed_pubkey); // checks internal consistency
        assert_eq!(
            to_hex_32(xpub.key.to_bytes()),
            "9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b808"
        );
    }

    #[test]
    fn serialize_xpub_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = XSecretKey::generate(&mut rng);
        let xpub = xprv.to_public();

        assert_eq!(
            to_hex_64(xpub.to_bytes()),
            "9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b8089f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
    }

    #[test]
    fn deserialize_xpub_test() {
        let xpub_bytes = hex::decode("9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b8089f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed").unwrap();
        let xpub = XPublicKey::from_bytes(&xpub_bytes).unwrap();

        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let expected_xprv = XSecretKey::generate(&mut rng);
        let expected_xpub = expected_xprv.to_public();

        assert_eq!(xpub.derivation_key, expected_xpub.derivation_key);
        assert_eq!(xpub.key, expected_xpub.key);
        assert_eq!(
            xpub.key.as_compressed(),
            expected_xpub.key.as_compressed()
        );
    }

    #[test]
    fn random_xpub_derivation_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = XSecretKey::generate(&mut rng);
        let xpub = xprv.to_public().derive_intermediate_key(|t| {
            t.commit_u64(b"account_id", 34);
        });

        assert_eq!(
            to_hex_32(xpub.derivation_key),
            "36e435eabc2a562ef228b82b399fbd004b2cc64103313fa673bd1fca0971f59d"
        );
        
        //assert_eq!(xpub.key.compress(), xpub.precompressed_pubkey); // checks internal consistency
        assert_eq!(
            to_hex_32(xpub.key.to_bytes()),
            "7414c0c5238c2277318ba3e51fc6fb8e836a2d9b4c04508f93cd5a455422221b"
        );
    }

    #[test]
    fn random_xpub_leaf_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = XSecretKey::generate(&mut rng);
        let xpub = xprv.to_public().derive_key(|t| {
            t.commit_u64(b"invoice_id", 10034);
        });

        assert_eq!(
            hex::encode(xpub.as_bytes()),
            "a202e8a0b6fb7123bf1e2aaaf90ed9c3c55f7d1975ed4b63b4417e5d7397c048"
        );
    }

    
    fn to_hex_32(input: [u8; 32]) -> std::string::String {
       hex::encode(&input[..])
    }

    fn to_hex_64(input: [u8; 64]) -> std::string::String {
       hex::encode(&input[..])
    }

}