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

//! Serde Support


macro_rules! serde_boilerplate { ($t:ty) => {
    impl ::serde::Serialize for $t {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: ::serde::Serializer {
            serializer.serialize_bytes(&self.to_bytes()[..])
        }
    }

    impl<'d> ::serde::Deserialize<'d> for $t {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: ::serde::Deserializer<'d> {
            struct MyVisitor;

            impl<'d> ::serde::de::Visitor<'d> for MyVisitor {
                type Value = $t;

                fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    formatter.write_str(Self::Value::DESCRIPTION)
                }

                fn visit_bytes<E>(self, bytes: &[u8]) -> Result<$t, E> where E: ::serde::de::Error {
                    Self::Value::from_bytes(bytes).map_err(crate::errors::serde_error_from_signature_error)
                }
            }
            deserializer.deserialize_bytes(MyVisitor)
        }
    }
} } // macro_rules! serde_boilerplate


#[cfg(test)]
mod test {
    use std::vec::Vec;

    use bincode::{serialize, serialized_size, deserialize, Infinite};

    use curve25519_dalek::ristretto::{CompressedRistretto};

    use crate::prelude::*;

    static COMPRESSED_PUBLIC_KEY : CompressedRistretto = CompressedRistretto([
        208, 120, 140, 129, 177, 179, 237, 159,
        252, 160, 028, 013, 206, 005, 211, 241,
        192, 218, 001, 097, 130, 241, 020, 169,
        119, 046, 246, 029, 079, 080, 077, 084]);

    /*
    static ED25519_PUBLIC_KEY: CompressedEdwardsY = CompressedEdwardsY([
        130, 039, 155, 015, 062, 076, 188, 063,
        124, 122, 026, 251, 233, 253, 225, 220,
        014, 041, 166, 120, 108, 035, 254, 077,
        160, 083, 172, 058, 219, 042, 086, 120, ]);
    */

  

    fn ed25519_secret_key() -> SecretKey {
        SecretKey(curve25519_dalek::scalar::Scalar::from_bits([
            062u8, 070u8, 027u8, 163u8, 092u8, 182u8, 011u8, 003u8,
            077u8, 234u8, 098u8, 004u8, 011u8, 127u8, 079u8, 228u8,
            243u8, 187u8, 150u8, 073u8, 201u8, 137u8, 076u8, 022u8,
            085u8, 251u8, 152u8, 002u8, 241u8, 042u8, 072u8, 054u8, ]
        ))
    }

    /// Ed25519 signature with the above keypair of a blank message.
    static SIGNATURE_BYTES: [u8; SIGNATURE_LENGTH] = [
        010, 126, 151, 143, 157, 064, 047, 001,
        196, 140, 179, 058, 226, 152, 018, 102,
        160, 123, 080, 016, 210, 086, 196, 028,
        053, 231, 012, 157, 169, 019, 158, 063,
        045, 154, 238, 007, 053, 185, 227, 229,
        079, 108, 213, 080, 124, 252, 084, 167,
        216, 085, 134, 144, 129, 149, 041, 081,
        063, 120, 126, 100, 092, 059, 050, 011, ];


    #[test]
    fn serialize_deserialize_signature() {
        let signature: Signature = Signature::from_bytes(&SIGNATURE_BYTES).unwrap();
        let encoded_signature: Vec<u8> = serialize(&signature, Infinite).unwrap();
        let decoded_signature: Signature = deserialize(&encoded_signature).unwrap();

        assert_eq!(signature, decoded_signature);
    }

    #[test]
    fn serialize_deserialize_public_key() {
        let public_key = PublicKey::from_compressed(COMPRESSED_PUBLIC_KEY).unwrap();
        let encoded_public_key: Vec<u8> = serialize(&public_key, Infinite).unwrap();
        let decoded_public_key: PublicKey = deserialize(&encoded_public_key).unwrap();

        assert_eq!(public_key, decoded_public_key);
    }

    /*
    TODO: Actually test serde on real secret key, not just mini one.
    fn serialize_deserialize_secret_key() {
        let encoded_secret_key: Vec<u8> = serialize(&SECRET_KEY, Infinite).unwrap();
        let decoded_secret_key: MiniSecretKey = deserialize(&encoded_secret_key).unwrap();
        for i in 0..64 {
            assert_eq!(ed25519_secret_key.0[i], decoded_secret_key.0[i]);
        }
    }
    */

    #[test]
    fn serialize_deserialize_mini_secret_key() {
        let encoded_secret_key: Vec<u8> = serialize(&ed25519_secret_key(), Infinite).unwrap();
        let decoded_secret_key: SecretKey = deserialize(&encoded_secret_key).unwrap();

        for i in 0..32 {
            assert_eq!(ed25519_secret_key().0[i], decoded_secret_key.0[i]);
        }
    }

    #[test]
    fn serialize_public_key_size() {
        let public_key = PublicKey::from_compressed(COMPRESSED_PUBLIC_KEY).unwrap();
        assert_eq!(serialized_size(&public_key) as usize, 32+8);  // Size specific to bincode==1.0.1
    }

    #[test]
    fn serialize_signature_size() {
        let signature: Signature = Signature::from_bytes(&SIGNATURE_BYTES).unwrap();
        assert_eq!(serialized_size(&signature) as usize, 64+8);  // Size specific to bincode==1.0.1
    }

    // #[test]
    // fn serialize_secret_key_size() {
    //     assert_eq!(serialized_size(&ed25519_secret_key) as usize, 32+8);
    //     let secret_key = ed25519_secret_key.expand();
    //     assert_eq!(serialized_size(&secret_key) as usize, 64+8);  // Sizes specific to bincode==1.0.1
    // }
}