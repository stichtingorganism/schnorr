//! Multiple message signatures
//! When a signer has all the private keys and wants to produce a single
//! signature over various data. For example when signing a transaction
//! in the UTXO model where a single signature is produced over all the
//! inputs for efficient veriffication

use crate::{
    MuSigContext, 
    PublicKey
};
use bacteria::Transcript;
use mohan::dalek::{
    scalar::Scalar,
};

/// MuSig multimessage context
#[derive(Clone)]
pub struct Multimessage<M: AsRef<[u8]>> {
    pairs: Vec<(PublicKey, M)>,
}

impl<M: AsRef<[u8]>> Multimessage<M> {
    /// Constructs a new multimessage context
    pub fn new(pairs: Vec<(PublicKey, M)>) -> Self {
        Self { pairs }
    }
}

impl<M: AsRef<[u8]>> MuSigContext for Multimessage<M> {
    fn commit(&self, transcript: &mut Transcript) {
        transcript.append_message(b"dom-sep", b"schnorr-multi-signature v1");
        transcript.append_u64(b"n", self.pairs.len() as u64);
        for (key, msg) in &self.pairs {
            transcript.commit_point(b"X", key.as_compressed());
            transcript.append_message(b"m", msg.as_ref());
        }
    }

    fn challenge(&self, i: usize, transcript: &mut Transcript) -> Scalar {
        let mut transcript_i = transcript.clone();
        transcript_i.append_u64(b"i", i as u64);
        transcript_i.challenge_scalar(b"c")

        // TBD: Do we want to add a domain separator to the transcript?
    }

    fn len(&self) -> usize {
        self.pairs.len()
    }

    fn key(&self, index: usize) -> PublicKey {
        self.pairs[index].0
    }
}

// /// Creates a signature for multiple private keys and multiple messages
// pub fn sign_multimessage(
//     transcript: &mut Transcript,
//     keys: &[&SecretKey],
//     messages: &[(&PublicKey, &[u8])]
// ) -> Result<Signature, SchnorrError> {

//     if messages.len() != keys.len() {
//             return Err(
//                 errors::from_musig(
//                     MuSigError::TooManyParticipants
//                 )
//             );
//     }

//     if keys.len() == 0 {
//         return Err(SchnorrError::BadArguments);
//     }

//     //set the domain
//     transcript.proto_name(b"Schnorr_musig");

//     //randomize transcript and commit private key
//     let mut rng = transcript
//         .build_rng()
//         // Use one key that has enough entropy to seed the RNG.
//         // We can call unwrap because we know that the privkeys length is > 0
//         .rekey_with_witness_bytes(b"secret_key", keys[0].as_bytes())
//         .finalize(&mut rand::thread_rng());

//     // Generate ephemeral keypair (r, R). r is a random nonce.
//     let r: Scalar = Scalar::random(&mut rng);

//     // R = generator * r, commiment to nonce
//     let _r: CompressedRistretto = (&r * &RISTRETTO_BASEPOINT_TABLE).compress();

//     // Commit the context, and commit the nonce sum with label "R"
//     transcript.append_u64(b"Multimessage_len", messages.len() as u64);

//     for (key, msg) in messages {
//             transcript.commit_point(b"public_key", key.as_compressed());
//             transcript.append_message(b"message", msg.as_ref());
//     }

//     //commit to our nonce
//     transcript.commit_point(b"R", &_r);

//     //compute the signature, s = r + sum{c_i * x_i}
//     let mut s = r;
//     for i in 0..keys.len() {
//         let mut transcript_i = transcript.clone();
//         //This prevents later steps from being able to get the same challenges that come from the forked transcript.
//         transcript_i.append_message(b"dom-sep", b"multi_message_boundary");
//         //The index i is the index of pair of the key it matches to.
//         transcript_i.append_u64(b"i", i as u64);
//         //Acts as the hash commitment for message, nonce commitment & pubkey
//         let c: Scalar = transcript_i.challenge_scalar(b"c");

//         s = s + c * keys[i].as_scalar();
//     }

//     Ok(Signature { R: _r, s: s })
// }

// pub fn verify_multimessage(
//     transcript: &mut Transcript,
//     signature: &Signature,
//     messages: &[(&PublicKey, &[u8])]
// ) -> Result<(), SchnorrError> {

//     //set the domain
//     transcript.proto_name(b"Schnorr_musig");

//     // Commit the context, and commit the nonce sum with label "R"
//     transcript.append_u64(b"Multimessage_len", messages.len() as u64);

//     for (key, msg) in messages {
//             transcript.commit_point(b"public_key", key.as_compressed());
//             transcript.append_message(b"message", msg.as_ref());
//     }

//     transcript.commit_point(b"R", &signature.R);

//     // Form the final linear combination:
//     // `s * G = R + sum{c_i * X_i}`
//     //      ->
//     // `0 == (-s * G) + (1 * R) + sum{c_i * X_i}`

//     // Get the total number of points in batch
//     let dyn_length: usize = messages.len();
//     let length = 1 + dyn_length; // include the (B, B_blinding) pair

//     let mut weights: Vec<Scalar> = Vec::with_capacity(length);
//     let mut points: Vec<Option<RistrettoPoint>> = Vec::with_capacity(length);

//     // (1 * R)
//     points.push(signature.R.decompress());
//     weights.push(Scalar::one());

//     //(-s * G)
//     weights.push(-signature.s);
//     points.push(Some(RISTRETTO_BASEPOINT_POINT));

//     for i in 0..messages.len() {

//         let c = {
//             let mut t = transcript.clone(); //TODO is this clone cheap?

//             //This prevents later steps from being able to get the same challenges that come from the forked transcript.
//             t.append_message(b"dom-sep", b"multi_message_boundary");
//             //The index i is the index of pair of the key it matches to.
//             t.append_u64(b"i", i as u64);
//             //get the per-pubkey challenge c_i.
//             //Acts as the hash commitment for message, nonce commitment & pubkey
//             t.challenge_scalar(b"c")
//         };

//         //sum_i(X_i * c_i) into cX.
//         weights.push(c);

//         //Decompress verification key P. If this fails, return Err(VMError::InvalidPoint).
//         points.push(Some(messages[i].0.into_point()));

//     }

//     //Check if s * G == cX + R. G is the base point.
//     let check = RistrettoPoint::optional_multiscalar_mul(weights, points)
//             .ok_or(SchnorrError::VerifyError)?;

//     // We need not return SigenatureError::PointDecompressionError because
//     // the decompression failures occur for R represent invalid signatures.
//     if !check.is_identity() {
//         return Err(SchnorrError::VerifyError);
//     }

//     Ok(())
// }

// #[test]
// fn verify_multimessage_singleplayer() {
//     use crate::Keypair;
//     use rand::prelude::*;

//     let messages = vec![b"message1", b"message2", b"message3", b"message4"];
//     let ctx = Transcript::new(b"my multi message context");
//     let mut csprng: ThreadRng = thread_rng();
//     let mut keypairs: Vec<Keypair> = Vec::new();
//     let mut pairs: Vec<(&PublicKey, &[u8])> = Vec::new();
//     let mut priv_keys: Vec<&SecretKey> = Vec::new();

//     for _i in 0..messages.len() {
//         let keypair: Keypair = Keypair::generate(&mut csprng);
//         keypairs.push(keypair);
//     }

//     for i in 0..keypairs.len() {
//         pairs.push((&keypairs[i].public, messages[i]));
//         priv_keys.push(&keypairs[i].secret);
//     }

//     let signature = sign_multimessage(
//         &mut ctx.to_owned(),
//         priv_keys.as_slice(),
//         pairs.as_slice(),
//     ).unwrap();

//     assert!(verify_multimessage(
//         &mut ctx.to_owned(),
//         &signature,
//         pairs.as_slice()
//     ).is_ok());
// }
