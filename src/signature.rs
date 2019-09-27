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
use std::borrow::Borrow;
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
use crate::errors::{SchnorrError, MuSigError};
use crate::keys::{PublicKey, SecretKey, Keypair};

use bacteria::Transcript;
use std::vec::Vec;

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

    const DESCRIPTION : &'static str = "A 64 byte Ristretto Schnorr signature";

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
            return Err(SchnorrError::BytesLengthError{
                name: "Signature", 
                description: Signature::DESCRIPTION,
                length: SIGNATURE_LENGTH 
            });
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[..32]);
        upper.copy_from_slice(&bytes[32..]);

        if upper[31] & 224 != 0 {
            return Err(SchnorrError::ScalarFormatError);
        }

        Ok(Signature{ R: CompressedRistretto(lower), s: Scalar::from_bits(upper) })

        //let s = Scalar::from_canonical_bytes(upper).ok_or(SignatureError::ScalarFormatError) ?;
        //Ok(Signature{ R: CompressedRistretto(lower), s: s })
 
    }
}



// === Implement signing and verification operations on key types === //

impl SecretKey {

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
    pub fn sign(&self, mut transcript: Transcript, public_key: &PublicKey) -> Signature {
        //The message `m` has already been fed into the transcript
        //set the domain
        transcript.proto_name(b"Schnorr_sig");

        //commit corresponding public key
        transcript.commit_point(b"public_key", public_key.as_compressed());

        //randomize transcrip and commit private key
        let mut rng = transcript
            .build_rng()
            .rekey_with_witness_bytes(b"secret_key", self.as_bytes()) 
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r, R). r is a random nonce.
        let r: Scalar = Scalar::random(&mut rng);

        // R = generator * r, commiment to nonce
        let _r: CompressedRistretto = (&r * &RISTRETTO_BASEPOINT_TABLE).compress();

        //commit to our nonce
        transcript.commit_point(b"R", &_r);

        //Acts as the hash commitment for message, nonce commitment & pubkey
        let c =  transcript.challenge_scalar(b"c");

        //compute the signature, s = r + cx
        let s = &r + &(&c * self.as_scalar());  

        Signature { R: _r, s: s }
    }

    /// Sign a message with this `SecretKey`.
    pub fn sign_simple(&self, ctx: &'static [u8], msg: &[u8], public_key: &PublicKey) -> Signature {
        let mut t = Transcript::new(ctx);
        t.append_message(b"sign-bytes", msg);
        self.sign(t, public_key)
    }

}


impl PublicKey {

    /// Verify a signature on a message with this keypair's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    #[allow(non_snake_case)]
    pub fn verify(&self, mut transcript: Transcript, signature: &Signature) -> bool {
        //set the domain
        transcript.proto_name(b"Schnorr_sig");

        // Make c = H(X, R, m)
        // The message `m` has already been fed into the transcript
        transcript.commit_point(b"public_key", self.as_compressed());
        transcript.commit_point(b"R", &signature.R);
       
        let c: Scalar = transcript.challenge_scalar(b"c");
        let A: &RistrettoPoint = self.as_point();
        let R: RistrettoPoint = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c, &(-A), &signature.s);
        
        // Validate the final linear combination:
        // `s * G = R + c * X`
        //      ->
        // `0 == (-s * G) + (1 * R) + (c * X)`
        //If g^s == RX^c then we have valid signature.

        R.compress() == signature.R
       
    }

    /// Verify a signature by this public key on a message.
    pub fn verify_simple(&self, ctx: &'static [u8], msg: &[u8], signature: &Signature) -> bool {
        let mut t = Transcript::new(ctx);
        t.append_message(b"sign-bytes", msg);
        self.verify(t, signature)
    }
}

impl Keypair {
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
    /// let ctx = SigningContext::new(b"My Signing Context");
    ///
    /// let sig: Signature = keypair.sign(ctx.from_hash512(prehashed));
    /// # }
    /// #
    /// # #[cfg(any(not(feature = "std")))]
    /// # fn main() { }
    /// ```
    ///
    // lol  [terrible_idea]: https://github.com/isislovecruft/scripts/blob/master/gpgkey2bc.py
    pub fn sign(&self, t: Transcript) -> Signature {
        self.secret.sign(t, &self.public)
    }

    /// Sign a message with this keypair's secret key.
    pub fn sign_simple(&self, ctx: &'static [u8], msg: &[u8]) -> Signature
    {
        self.secret.sign_simple(ctx, msg, &self.public)
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
    /// let ctx = SigningContext::new(b"Some context string");
    ///
    /// let sig: Signature = keypair.sign(ctx.bytes(message));
    ///
    /// assert!( keypair.public.verify(ctx.bytes(message), &sig) );
    /// # }
    /// ```
    pub fn verify(&self, t: Transcript, signature: &Signature) -> bool {
        self.public.verify(t, signature)
    }

    /// Verify a signature by keypair's public key on a message.
    pub fn verify_simple(&self, ctx: &'static [u8], msg: &[u8], signature: &Signature) -> bool {
        self.public.verify_simple(ctx, msg, signature)
    }
}


/// Verify a batch of `signatures` on `messages` with their respective `public_keys`.
///
/// # Inputs
///
/// * `messages` is a slice of byte slices, one per signed message.
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
/// let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign(ctx.bytes(&msg))).collect();
/// let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
///
/// let transcripts: Vec<Transcript> = ::std::iter::once(ctx.bytes(msg)).cycle().take(64).collect();;
///
/// assert!( verify_batch(&transcripts[..], &signatures[..], &public_keys[..]).is_ok() );
/// # }
/// ```
#[allow(non_snake_case)]
pub fn verify_batch(
    transcripts: &[Transcript], 
    signatures: &[Signature], 
    public_keys: &[PublicKey]
) -> Result<(), SchnorrError>{

    // The message `m` has already been fed into the transcripts

    const ASSERT_MESSAGE: &'static str = "The number of messages/transcripts, signatures, and public keys must be equal.";
     
    // Check transcripts length below
    if !signatures.len() == public_keys.len() && !transcripts.len() == public_keys.len() {
            return Err(SchnorrError::BytesLengthError{
                name: "Verify Batch",  
                description: ASSERT_MESSAGE, 
                length: 0 
            });
    }

    // Get the total number of points in batch
    let dyn_length: usize = signatures.len();
    let length = 2 + dyn_length; // include the (B, B_blinding) pair

    let mut weights: Vec<Scalar> = Vec::with_capacity(length);
    let mut points: Vec<Option<RistrettoPoint>> = Vec::with_capacity(length);

    // Add base points
    points.push(Some(RISTRETTO_BASEPOINT_POINT));
    weights.push(Scalar::zero());

    let mut rng = rand::prelude::thread_rng();

    // Iterate over every point, adding both weights and points to
    // our arrays
    for i in 0..transcripts.len() {
        // Select a random Scalar for each signature.
        // We may represent these as scalars because we use
        // variable time 256 bit multiplication below. 
        let e = Scalar::random(&mut rng);
        
        // Compute the basepoint coefficient, running summation
        weights[0] = weights[0] + e * -signatures[i].s;

        //derive challenge scalar, c = H(X, R, m)
        let c = {
            let mut t = transcripts[i].borrow().clone(); //TODO is this clone cheap?
            t.proto_name(b"Schnorr_sig");
            t.commit_point(b"public_key", public_keys[i].as_compressed());
            t.commit_point(b"R", &signatures[i].R);
            t.challenge_scalar(b"c") 
        };

        // Add weights and points for arbitrary points
        weights.push(Scalar::one() * e);
        weights.push(c * e);

        points.push(signatures[i].R.decompress());
        //Decompress verification key P. If this fails, return Err(VMError::InvalidPoint).
        points.push(Some(public_keys[i].into_point()));
    }

    // Form the final linear combination:
    // `s * G = R + c * X`
    //      ->
    // `0 == (-s * G) + (1 * R) + (c * X)`
    // G is the base point.
    let check = RistrettoPoint::optional_multiscalar_mul(weights, points)
            .ok_or(SchnorrError::VerifyError)?;

    // We need not return SigenatureError::PointDecompressionError because
    // the decompression failures occur for R represent invalid signatures.
    if !check.is_identity() {
        return Err(SchnorrError::VerifyError);
    }
    
    Ok(())
}


/// Creates a signature for multiple private keys and multiple messages
pub fn sign_multi(
    transcript: &mut Transcript, 
    keys: &[&SecretKey], 
    messages: &[(&PublicKey, &[u8])]
) -> Result<Signature, SchnorrError> {

    if messages.len() != keys.len() {
            return Err(
                SchnorrError::MuSig { 
                    kind: MuSigError::TooManyParticipants 
                }

            );
    }
    
    if keys.len() == 0 {
        return Err(SchnorrError::BadArguments);
    }

    //set the domain
    transcript.proto_name(b"Schnorr_musig");

    //randomize transcrip and commit private key
    let mut rng = transcript
        .build_rng()
        // Use one key that has enough entropy to seed the RNG.
        // We can call unwrap because we know that the privkeys length is > 0
        .rekey_with_witness_bytes(b"secret_key", keys[0].as_bytes())
        .finalize(&mut rand::thread_rng());

    
    // Generate ephemeral keypair (r, R). r is a random nonce.
    let r: Scalar = Scalar::random(&mut rng);

    // R = generator * r, commiment to nonce
    let _r: CompressedRistretto = (&r * &RISTRETTO_BASEPOINT_TABLE).compress();


    // Commit the context, and commit the nonce sum with label "R"
    transcript.append_u64(b"Multimessage_len", messages.len() as u64);

    for (key, msg) in messages {
            transcript.commit_point(b"public_key", key.as_compressed());
            transcript.append_message(b"message", msg.as_ref());
    }

    //commit to our nonce
    transcript.commit_point(b"R", &_r);
    
    //compute the signature, s = r + sum{c_i * x_i}
    let mut s = r;
    for i in 0..keys.len() {
        let mut transcript_i = transcript.clone();
        //This prevents later steps from being able to get the same challenges that come from the forked transcript.
        transcript_i.append_message(b"dom-sep", b"multi_message_boundary");
        //The index i is the index of pair of the key it matches to.
        transcript_i.append_u64(b"i", i as u64);
        //Acts as the hash commitment for message, nonce commitment & pubkey
        let c: Scalar = transcript_i.challenge_scalar(b"c");

        s = s + c * keys[i].as_scalar();
    }

    Ok(Signature { R: _r, s: s })
}

pub fn verify_multi(
    transcript: &mut Transcript, 
    signature: &Signature, 
    messages: &[(&PublicKey, &[u8])]
) -> Result<(), SchnorrError> {

    //set the domain
    transcript.proto_name(b"Schnorr_musig");

    // Commit the context, and commit the nonce sum with label "R"
    transcript.append_u64(b"Multimessage_len", messages.len() as u64);

    for (key, msg) in messages {
            transcript.commit_point(b"public_key", key.as_compressed());
            transcript.append_message(b"message", msg.as_ref());
    }

    transcript.commit_point(b"R", &signature.R);

    // Form the final linear combination:
    // `s * G = R + sum{c_i * X_i}`
    //      ->
    // `0 == (-s * G) + (1 * R) + sum{c_i * X_i}`

    // Get the total number of points in batch
    let dyn_length: usize = messages.len();
    let length = 1 + dyn_length; // include the (B, B_blinding) pair

    let mut weights: Vec<Scalar> = Vec::with_capacity(length);
    let mut points: Vec<Option<RistrettoPoint>> = Vec::with_capacity(length);

    // (1 * R)
    points.push(signature.R.decompress());
    weights.push(Scalar::one());

    //(-s * G)
    weights.push(-signature.s);
    points.push(Some(RISTRETTO_BASEPOINT_POINT));


    for i in 0..messages.len() {
        
        let c = {
            let mut t = transcript.clone(); //TODO is this clone cheap?
          
            //This prevents later steps from being able to get the same challenges that come from the forked transcript.
            t.append_message(b"dom-sep", b"multi_message_boundary");
            //The index i is the index of pair of the key it matches to.
            t.append_u64(b"i", i as u64);
            //get the per-pubkey challenge c_i.
            //Acts as the hash commitment for message, nonce commitment & pubkey
            t.challenge_scalar(b"c")
        };

        //sum_i(X_i * c_i) into cX.
        weights.push(c);

        //Decompress verification key P. If this fails, return Err(VMError::InvalidPoint).
        points.push(Some(messages[i].0.into_point()));

    }

    //Check if s * G == cX + R. G is the base point.
    let check = RistrettoPoint::optional_multiscalar_mul(weights, points)
            .ok_or(SchnorrError::VerifyError)?;

    // We need not return SigenatureError::PointDecompressionError because
    // the decompression failures occur for R represent invalid signatures.
    if !check.is_identity() {
        return Err(SchnorrError::VerifyError);
    }

    Ok(())
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
        SigningContext,
        sign_multi,
        verify_multi,
        verify_batch
    };

    #[test]
    fn sign_verify_single() {

        let mut csprng: ChaChaRng;
        let keypair: Keypair;

        csprng  = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);

        let sig = keypair.sign(Transcript::new(b"example transcript"));

        assert!(keypair.verify(Transcript::new(b"example transcript"), &sig));

        assert!(!keypair.verify(Transcript::new(b"invalid transcript"), &sig));

    }

    #[test]
    fn sign_verify_bytes() {
        let mut csprng: ChaChaRng;
        let keypair: Keypair;
        let good_sig: Signature;
        let bad_sig:  Signature;

        let ctx = SigningContext::new(b"good");
        
        let good: &[u8] = "test message".as_bytes();
        let bad:  &[u8] = "wrong message".as_bytes();

        csprng  = ChaChaRng::from_seed([0u8; 32]);
        keypair  = Keypair::generate(&mut csprng);
        good_sig = keypair.sign(ctx.bytes(&good));
        bad_sig  = keypair.sign(ctx.bytes(&bad));

        assert!(keypair.verify(ctx.bytes(&good), &good_sig),
                "Verification of a valid signature failed!");
        assert!(!keypair.verify(ctx.bytes(&good), &bad_sig),
                "Verification of a signature on a different message passed!");
        assert!(!keypair.verify(ctx.bytes(&bad),  &good_sig),
                "Verification of a signature on a different message passed!");
        assert!(!keypair.verify(SigningContext::new(b"bad").bytes(&good),  &good_sig),
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
        good_sig = keypair.sign(ctx.from_hash512(prehashed_good.clone()));
        bad_sig  = keypair.sign(ctx.from_hash512(prehashed_bad.clone()));

        assert!(keypair.verify(ctx.from_hash512(prehashed_good.clone()), &good_sig),
                "Verification of a valid signature failed!");
        assert!(! keypair.verify(ctx.from_hash512(prehashed_good.clone()), &bad_sig),
                "Verification of a signature on a different message passed!");
        assert!(! keypair.verify(ctx.from_hash512(prehashed_bad.clone()), &good_sig),
                "Verification of a signature on a different message passed!");
        assert!(! keypair.verify(SigningContext::new(b"oops").from_hash512(prehashed_good), &good_sig),
                "Verification of a signature on a different message passed!");
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
            signatures.push(keypair.sign(ctx.bytes(messages[i])));
            keypairs.push(keypair);
        }

        let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();
        let transcripts: Vec<Transcript> = messages.iter().map(|m| ctx.bytes(m)).collect();
        
        assert!(verify_batch(&transcripts[..], &signatures[..], &public_keys[..]).is_ok());
    }

    #[test]
    fn verify_multimessage_singleplayer() {
        let messages = vec![b"message1", b"message2", b"message3", b"message4"];
        let ctx = Transcript::new(b"my multi message context");
        let mut csprng: ThreadRng = thread_rng();
        let mut keypairs: Vec<Keypair> = Vec::new();
        let mut pairs: Vec<(&PublicKey, &[u8])> = Vec::new();
        let mut priv_keys: Vec<&SecretKey> = Vec::new();

        for _i in 0..messages.len() {
            let keypair: Keypair = Keypair::generate(&mut csprng);
            keypairs.push(keypair);
        }

        for i in 0..keypairs.len() {
            pairs.push((&keypairs[i].public, messages[i]));
            priv_keys.push(&keypairs[i].secret);
        }


        let signature = sign_multi(
            &mut ctx.to_owned(),
            priv_keys.as_slice(),
            pairs.as_slice(),
        ).unwrap();


        assert!(verify_multi(
                &mut ctx.to_owned(),
                &signature, 
                pairs.as_slice()
            ).is_ok());
    }

  
}