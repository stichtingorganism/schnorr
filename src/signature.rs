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


//! A Rust implementation of Schnorr signing

use std::fmt::Debug;
use mohan::dalek::{
    traits::{
        IsIdentity,
        VartimeMultiscalarMul,
    },
    scalar::Scalar,
    ristretto::{
        RistrettoPoint, 
        CompressedRistretto
    },
    constants::{
        RISTRETTO_BASEPOINT_POINT, 
        RISTRETTO_BASEPOINT_TABLE
    }
};

use crate::errors::SchnorrError;
use crate::keys::{PublicKey, SecretKey};
use crate::batch::{
    SingleVerifier,
    BatchVerification
};

use bacteria::Transcript;
use std::vec::Vec;
use std::iter;


/// The length of a curve25519 Schnorr `Signature`, in bytes.
pub const SIGNATURE_LENGTH: usize = 64;


/// An Schnorr signature.
///
/// # Note
///
/// These signatures are "detached"—that is, they do **not** include a copy 
/// of the message which has been signed.
#[allow(non_snake_case)]
#[derive(Copy, Eq, PartialEq)]
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
    
    /// Sign a transcript with this keypair's secret key.
    ///
    /// Requires a `SigningTranscript`, normally created from a
    /// `SigningContext` and a message.  Returns a Schnorr signature.
    ///
    /// # Examples
    ///
    /// Internally, we manage signature transcripts using a 128 bit secure
    /// STROBE construction based on Keccak, which itself is extremly fast
    /// and secure.  You might however influence performance or security
    /// by prehashing your message, like
    ///
    /// ```
    /// extern crate schnorr;
    /// extern crate rand;
    /// extern crate blake2;
    ///
    /// use schnorr::*;
    /// use rand::prelude::*; // ThreadRng,thread_rng
    /// use blake2::Blake2b;
    /// use blake2::digest::{Input};
    ///
    /// # #[cfg(all(feature = "std"))]
    /// # fn main() {
    /// let mut csprng: ThreadRng = thread_rng();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    /// let message: &[u8] = b"All I want is to pet all of the dogs.";
    ///
    /// // Create a hash digest object and feed it the message:
    /// let prehashed = Blake2b::default().chain(message);
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "std")))]
    /// # fn main() { }
    /// ```
    ///
    /// We require a "context" string for all signatures, which should
    /// be chosen judiciously for your project.  It should represent the 
    /// role the signature plays in your application.  If you use the
    /// context in two purposes, and the same key, then a signature for
    /// one purpose can be substituted for the other.
    ///
    /// ```
    /// # extern crate schnorr;
    /// # extern crate rand;
    /// # extern crate blake2;
    /// #
    /// # use schnorr::*;
    /// # use rand::prelude::*; // ThreadRng,thread_rng
    /// # use blake2::digest::Input;
    /// #
    /// # #[cfg(all(feature = "std"))]
    /// # fn main() {
    /// # let mut csprng: ThreadRng = thread_rng();
    /// # let keypair: Keypair = Keypair::generate(&mut csprng);
    /// # let message: &[u8] = b"All I want is to pet all of the dogs.";
    /// # let prehashed = ::blake2::Blake2b::default().chain(message);
    /// #
    /// let mut ctx = SigningContext::new(b"My Signing Context");
    ///
    /// let sig: Signature = Signature::sign(&mut ctx.from_hash512(prehashed), &keypair.secret, &keypair.public);
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "std")))]
    /// # fn main() { }
    /// ```
    ///
    /// Sign a transcript with this `SecretKey`.
    ///
    /// Requires a `SigningTranscript`, normally created from a
    /// `SigningContext` and a message, as well as the public key
    /// correspodning to `self`.  Returns a Schnorr signature.
    ///
    /// We employ a randomized nonce here, but also incorporate the
    /// transcript like in a derandomized scheme, but only after first
    /// extending the transcript by the public key.  As a result, there
    /// should be no attacks even if both the random number generator
    /// fails and the function gets called with the wrong public key.
    // Sign a message with this `SecretKey`.
    pub fn sign(transcript: &mut Transcript, secret_key: &SecretKey) -> Signature {
        //The message `m` has already been fed into the transcript
        let public_key = PublicKey::from_secret(secret_key);
        
        //randomize transcrip and commit private key
        let mut rng = transcript
            .build_rng()
            .rekey_with_witness_bytes(b"secret_key", &secret_key.to_bytes()) 
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r, R). r is a random nonce.
        let mut r: Scalar = Scalar::random(&mut rng);

        // R = generator * r, commiment to nonce
        let _r: CompressedRistretto = (&r * &RISTRETTO_BASEPOINT_TABLE).compress();

       
        //Acts as the hash commitment for message, nonce commitment & pubkey
        let c = {
            //domain seperration
            transcript.proto_name(b"schnorr_sig");
            //commit corresponding public key
            transcript.commit_point(b"public_key", public_key.as_compressed());
            //commit to our nonce
            transcript.commit_point(b"R", &_r);
            //sample challenge
            transcript.challenge_scalar(b"c")
        };


        //compute the signature, s = r + cx
        let s = &r + &(&c * secret_key.as_scalar());  

        //zero out secret r
        mohan::zeroize_hack(&mut r);

        Signature { R: _r, s: s }
    }
    
    /// Verify a signature by keypair's public key on a transcript.
    ///
    /// Requires a `SigningTranscript`, normally created from a
    /// `SigningContext` and a message, as well as the signature
    /// to be verified.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate schnorr;
    /// extern crate rand;
    ///
    /// use schnorr::*;
    /// use rand::prelude::*; // ThreadRng,thread_rng
    ///
    /// # fn main() {
    /// let mut csprng: ThreadRng = thread_rng();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    /// let message: &[u8] = b"All I want is to pet all of the dogs.";
    ///
    /// let mut ctx = SigningContext::new(b"Some context string");
    ///
    /// let sig: Signature = Signature::sign(&mut ctx.bytes(message), &keypair.secret);
    ///
    /// assert!( sig.verify(&mut ctx.bytes(message), &keypair.public).is_ok() );
    /// # }
    /// ```
    /// Verify a signature on a message with this keypair's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    pub fn verify(&self, transcript: &mut Transcript, public_key: &PublicKey) -> Result<(), SchnorrError> {
        SingleVerifier::verify(
            |verifier| 
                self.verify_batched(
                    transcript, 
                    public_key, 
                    verifier
                )
        )
        // //set the domain
        // transcript.proto_name(b"schnorr_sig");

        // // Make c = H(X, R, m)
        // // The message `m` has already been fed into the transcript
        // transcript.commit_point(b"public_key", public_key.as_compressed());
        // transcript.commit_point(b"R", &signature.R);
       
        // let c: Scalar = transcript.challenge_scalar(b"c");
        // let A: &RistrettoPoint = public_key.as_point();
        // let R: RistrettoPoint = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c, &(-A), &signature.s);
        
        // // Validate the final linear combination:
        // // `s * G = R + c * X`
        // //      ->
        // // `0 == (-s * G) + (1 * R) + (c * X)`
        // //If g^s == RX^c then we have valid signature.
        // R.compress() == signature.R  
    }


    /// Verify a batch of `signatures` on `messages` with their respective `public_keys`.
    ///
    /// # Inputs
    ///
    /// * `messages` is a slice of byte slices, one per signed message.
    /// * `transcript` is a slice of `Signature`s. They need messages fed in before and discarded after
    /// * `signatures` is a slice of `Signature`s.
    /// * `public_keys` is a slice of `PublicKey`s.
    /// * `csprng` is an implementation of `Rng + CryptoRng`, such as `rand::ThreadRng`.
    /// 
    /// # Panics
    ///
    /// This function will panic if the `messages, `signatures`, and `public_keys`
    /// slices are not equal length.
    ///
    /// # Returns
    ///
    /// * A `Result` whose `Ok` value is an emtpy tuple and whose `Err` value is a
    ///   `SignatureError` containing a description of the internal error which
    ///   occured.
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate schnorr;
    /// extern crate rand;
    /// extern crate bacteria;
    ///
    /// use schnorr::*;
    /// use rand::thread_rng;
    /// use rand::rngs::ThreadRng;
    /// use bacteria::Transcript;
    ///
    /// # fn main() {
    ///
    /// let ctx = SigningContext::new(b"some batch");
    /// let mut csprng: ThreadRng = thread_rng();
    /// let keypairs: Vec<Keypair> = (0..64).map(|_| Keypair::generate(&mut csprng)).collect();
    /// let msg: &[u8] = b"They're good dogs Brant"; 
    /// let signatures:  Vec<Signature> = keypairs.iter().map(|key| Signature::sign(&mut ctx.bytes(&msg), &key.secret)).collect();
    /// let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
    /// let mut batch = BatchVerifier::new(rand::thread_rng());
    ///
    /// let mut transcripts: Vec<Transcript> = ::std::iter::once(ctx.bytes(msg)).cycle().take(64).collect();;
    /// for i in 0..signatures.len() {
    ///      signatures[i].verify_batched(&mut transcripts[i], &public_keys[i], &mut batch);
    /// }
    /// 
    /// assert!(batch.verify().is_ok());
    /// # }
    /// ```
    #[allow(non_snake_case)]
    pub fn verify_batched(
        &self,
        transcript: &mut Transcript,  
        public_key: &PublicKey,
        batch: &mut impl BatchVerification,
    ) {

        // // The message `m` has already been fed into the transcripts        
        // // Check transcripts length below
        // if !signatures.len() == public_keys.len() && !transcripts.len() == public_keys.len() {
        //         return Err(SchnorrError::BadArguments);
        // }

        // // Get the total number of points in batch
        // let dyn_length: usize = signatures.len();
        // let length = 2 + dyn_length; // include the (B, B_blinding) pair

        // let mut weights: Vec<Scalar> = Vec::with_capacity(length);
        // let mut points: Vec<Option<RistrettoPoint>> = Vec::with_capacity(length);

        // // Add base points
        // points.push(Some(RISTRETTO_BASEPOINT_POINT));
        // weights.push(Scalar::zero());

        // // Use a random number generator keyed by both the public keys,
        // // and the system random number generator 
        // let mut csprng = {
        //     let mut t = Transcript::new(b"V-RNG");
        //     for pk in public_keys {
        //         t.commit_point(b"",pk.as_compressed());
        //     }
        //     t.build_rng().finalize(&mut rand::prelude::thread_rng())
        // };

        // Iterate over every point, adding both weights and points to
        // our arrays
        // for i in 0..transcripts.len() {
        //     // Select a random Scalar for each signature.
        //     // We may represent these as scalars because we use
        //     // variable time 256 bit multiplication below. 
        //     let e = Scalar::random(&mut csprng);
            
        //     // Compute the basepoint coefficient, running summation
        //     weights[0] = weights[0] + e * -signatures[i].s;

        //     //derive challenge scalar, c = H(X, R, m)
        //     let c = {
        //         transcripts[i].proto_name(b"schnorr_sig");
        //         transcripts[i].commit_point(b"public_key", public_keys[i].as_compressed());
        //         transcripts[i].commit_point(b"R", &signatures[i].R);
        //         transcripts[i].challenge_scalar(b"c") 
        //     };

        //     // Add weights and points for arbitrary points
        //     weights.push(Scalar::one() * e);
        //     weights.push(c * e);

        //     points.push(signatures[i].R.decompress());
        //     //Decompress verification key P. If this fails, return Err(VMError::InvalidPoint).
        //     points.push(Some(public_keys[i].into_point()));
        // }

        // Derive challenge scalar, c = H(X, R, m)
        // The message has already been fed into the transcript
        let c = {
            transcript.proto_name(b"schnorr_sig");
            transcript.commit_point(b"public_key", public_key.as_compressed());
            transcript.commit_point(b"R", &self.R);
            transcript.challenge_scalar(b"c") 
        };

        // // Form the final linear combination:
        // // `s * G = R + c * X`
        // //      ->
        // // `0 == (-s * G) + (1 * R) + (c * X)`
        // // G is the base point.
        // let check = RistrettoPoint::optional_multiscalar_mul(weights, points)
        //         .ok_or(SchnorrError::VerifyError)?;

        // // We need not return SigenatureError::PointDecompressionError because
        // // the decompression failures occur for R represent invalid signatures.
        // if !check.is_identity() {
        //     return Err(SchnorrError::VerifyError);
        // }
        
        // Ok(())
        // Form the final linear combination:
        // `s * G = R + c * X`
        //      ->
        // `0 == (-s * G) + (1 * R) + (c * X)`
        batch.append(
            -self.s,
            iter::once(Scalar::one()).chain(iter::once(c)),
            iter::once(self.R.decompress()).chain(iter::once(Some(public_key.into_point()))),
        );
    }

}


#[cfg(test)]
mod test {
    use bacteria::Transcript;
    use rand::prelude::*; // ThreadRng,thread_rng
    use rand_chacha::ChaChaRng;
    use blake2::digest::Input;
    // use std::vec::Vec;

    use crate::{
        Keypair,
        PublicKey,
        SecretKey,
        Signature,
        tools::SigningContext,
        BatchVerification,
        BatchVerifier
    };

    #[test]
    fn sign_verify_single() {

        let mut csprng: ChaChaRng;
        let keypair: Keypair;

        csprng  = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);

        let sig = Signature::sign(&mut Transcript::new(b"example transcript"), &keypair.secret);

        assert!(sig.verify(&mut Transcript::new(b"example transcript"), &keypair.public).is_ok());

        assert!(sig.verify(&mut Transcript::new(b"invalid transcript"), &keypair.public).is_err());

    }

    #[test]
    fn sign_verify_bytes() {
        let mut csprng: ChaChaRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;
        
        let good = Transcript::new(b"test message");
        let bad = Transcript::new(b"wrong message");

        csprng  = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);
        good_sig = Signature::sign(&mut good.clone(), &keypair.secret);
        bad_sig  = Signature::sign(&mut bad.clone(), &keypair.secret);

        assert!(good_sig.verify(&mut good.clone(), &keypair.public).is_ok(), 
                "Verification of a valid signature failed!");
        assert!(bad_sig.verify(&mut good.clone(), &keypair.public).is_err(),
                "Verification of a signature on a different message passed!");
        assert!(good_sig.verify(&mut bad.clone(), &keypair.public).is_err(),
                "Verification of a signature on a different message passed!");
        assert!(bad_sig.verify(&mut bad.clone(), &keypair.public).is_ok(),
                "Verification of a signature on a different message passed!");
    }

    #[test]
    fn sign_verify_hash() {
        let mut csprng: ChaChaRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let ctx = SigningContext::new(b"testing testing 1 2 3");

        let good: &[u8] = b"test message";
        let bad:  &[u8] = b"wrong message";

        let prehashed_good = blake2::Blake2b::default().chain(good);
        let prehashed_bad = blake2::Blake2b::default().chain(bad);
        // You may verify that `Blake2b: Copy` is possible, making these clones below correct.

        csprng   = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);
        good_sig = Signature::sign(&mut ctx.from_hash512(prehashed_good.clone()), &keypair.secret);
        bad_sig  = Signature::sign(&mut ctx.from_hash512(prehashed_bad.clone()), &keypair.secret);

        assert!(good_sig.verify(&mut ctx.from_hash512(prehashed_good.clone()), &keypair.public).is_ok(), 
                "Verification of a valid signature failed!");
        assert!(bad_sig.verify(&mut ctx.from_hash512(prehashed_good.clone()), &keypair.public).is_err(), 
                "Verification of a valid signature failed!");
        assert!(good_sig.verify(&mut ctx.from_hash512(prehashed_bad.clone()), &keypair.public).is_err(), 
                "Verification of a valid signature failed!");
        assert!(good_sig.verify(&mut SigningContext::new(b"oops").from_hash512(prehashed_good), &keypair.public).is_err(), 
                "Verification of a valid signature failed!");
    }

    #[test]
    fn verify_batch_seven_signatures() {
        
        let ctx = SigningContext::new(b"my batch context");

        let messages: [&[u8]; 7] = [
            b"Watch closely everyone, I'm going to show you how to kill a god.",
            b"I'm not a cryptographer I just encrypt a lot.",
            b"Still not a cryptographer.",
            b"This is a test of the tsunami alert system. This is only a test.",
            b"Fuck dumbin' it down, spit ice, skip jewellery: Molotov cocktails on me like accessories.",
            b"Hey, I never cared about your bucks, so if I run up with a mask on, probably got a gas can too.",
            b"And I'm not here to fill 'er up. Nope, we came to riot, here to incite, we don't want any of your stuff.", ];

        let mut csprng: ThreadRng = thread_rng();
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            signatures.push(
                Signature::sign(&mut ctx.bytes(messages[i]), &keypair.secret)
            );
            keypairs.push(keypair);
        }

        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
        let mut transcripts: Vec<Transcript> = messages.iter().map(|m| ctx.bytes(m)).collect();

        let mut batch = BatchVerifier::new(rand::thread_rng());

        for i in 0..signatures.len() {
            signatures[i].verify_batched(&mut transcripts[i], &public_keys[i], &mut batch);
        }

        assert!(batch.verify().is_ok());
    }

    #[test]
    fn verify_batch_seven_signatures_bad() {
        
        let ctx = SigningContext::new(b"my batch context");

        let messages: [&[u8]; 7] = [
            b"Watch closely everyone, I'm going to show you how to kill a god.",
            b"I'm not a cryptographer I just encrypt a lot.",
            b"Still not a cryptographer.",
            b"This is a test of the tsunami alert system. This is only a test.",
            b"Fuck dumbin' it down, spit ice, skip jewellery: Molotov cocktails on me like accessories.",
            b"Hey, I never cared about your bucks, so if I run up with a mask on, probably got a gas can too.",
            b"And I'm not here to fill 'er up. Nope, we came to riot, here to incite, we don't want any of your stuff.", ];

        let mut csprng: ThreadRng = thread_rng();
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();

        for i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            signatures.push(
                Signature::sign(&mut ctx.bytes(messages[i]), &keypair.secret)
            );
            keypairs.push(keypair);
        }

        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
        let mut transcripts: Vec<Transcript> = messages.iter().map(|m| ctx.bytes(m)).collect();

        let mut batch = BatchVerifier::new(rand::thread_rng());

        for i in 0..signatures.len() {
            signatures[i].verify_batched(&mut &mut Transcript::new(b"bad transcript"), &public_keys[i], &mut batch);
        }

        assert!(batch.verify().is_err());
    }
}