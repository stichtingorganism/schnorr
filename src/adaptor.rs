// //! Adaptor Signatures

// use crate::{PublicKey, SecretKey, Signature};
// use bacteria::Transcript;
// use mohan::dalek::{
//     constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
//     ristretto::{CompressedRistretto, RistrettoPoint},
//     scalar::Scalar,
//     traits::{IsIdentity, VartimeMultiscalarMul},
// };

// /// https://joinmarket.me/blog/blog/flipping-the-scriptless-script-on-schnorr/
// ///
// /// Alice (P = xG), constructs for Bob:
// /// Calculate T = tG, R = rG
// /// Calculate s = r + t + H(P || R+T || m) * x
// /// Publish (to Bob, others): (s', R, T) with s' = s - t
// /// (so s' should be "adaptor signature"; this notation is retained for the rest of the document).
// /// so you simply share an elliptic curve point (in this case it will be T), and the secret will
// /// be its corresponding private key.
// pub fn adaptor(
//     transcript: &mut Transcript,
//     secret_key: &SecretKey,
//     excess: &SecretKey,
// ) -> (Signature, PublicKey) {
//     // The message `m` has already been fed into the transcript
//     let public_key = PublicKey::from_secret(secret_key);

//     // The message `m` has already been fed into the transcript
//     let t_public_key = PublicKey::from_secret(excess);

//     //randomize transcript and commit private key
//     let mut rng = transcript
//         .build_rng()
//         .rekey_with_witness_bytes(b"secret_key", &secret_key.to_bytes())
//         .finalize(&mut mohan::mohan_rand());

//     // Generate ephemeral keypair (r, R). r is a random nonce.
//     let mut r: Scalar = Scalar::random(&mut rng);

//     // R = generator * r, commiment to nonce
//     let _r = (&r * &RISTRETTO_BASEPOINT_TABLE);

//     let r_plus_t = _r + t_public_key.as_point();

//     //Acts as the hash commitment for message, nonce commitment & pubkey
//     let c = {
//         // Domain seperation
//         transcript.proto_name(b"organism_schnorr_adaptor");
//         //commit corresponding public key
//         transcript.commit_point(b"public_key", public_key.as_compressed());
//         //commit to our nonce
//         transcript.commit_point(b"R+T", &r_plus_t.compress());
//         //sample challenge
//         transcript.challenge_scalar(b"c")
//     };

//     //compute the signature, s = r + t + cx
//     let s = &r + excess.as_scalar() + &(&c * secret_key.as_scalar());
//     // s' = s - t (s' is the adaptor signature)
//     let s_prime = s - excess.as_scalar();

//     //zero out secret r
//     mohan::zeroize_hack(&mut r);

//     (
//         Signature {
//             R: _r.compress(),
//             s: s_prime,
//         },
//         t_public_key,
//     )
// }

// /// Can verify the adaptor sig s' for T,m:
// /// s' * G ?= R + H(P || R+T || m) * P
// /// This is not a valid sig: hashed nonce point is R+T not R;
// /// Cannot retrieve a valid sig : to recover s'+t requires ECDLP solving.
// /// After validation of adaptor sig we know: t <=> receipt of valid sig s = s' + t
// pub fn verify_adaptor(
//     transcript: &mut Transcript,
//     public_key: &PublicKey,
//     big_t: &PublicKey,
//     signature: &Signature,
// ) -> bool {
//     //set the domain
//     transcript.proto_name(b"organism_schnorr_adaptor");

//     // Make c = H(X, R+T, m)
//     // The message `m` has already been fed into the transcript
//     transcript.commit_point(b"public_key", public_key.as_compressed());
//     transcript.commit_point(b"R+T", &signature.R);
//     let c: Scalar = transcript.challenge_scalar(b"c");

//     let A: &RistrettoPoint = public_key.as_point();
//     let R: RistrettoPoint =
//         RistrettoPoint::vartime_double_scalar_mul_basepoint(&c, &(-A), &signature.s);

//     // Validate the final linear combination:
//     // `s' * G = R + c * X`
//     //      ->
//     // `0 == (-s' * G) + (1 * R) + (c * X)`
//     //If g^s' == RX^c then we have valid adaptor signature.
//     R.compress() == signature.R
// }

// /// Knowing the final signature and the original partial signatures can compute `t`. The excess.
// pub fn extract_adaptor(
//     partial_sig: &Signature,
//     final_sig: &Signature
// ) -> Scalar {
//     //s' = s - t, t = s - s'
//     let s = final_sig.s + partial_sig.s;
//     /// R' = R - T
//     let r_prime = final_sig.R.decompress();

//     // //zero out secret r
//     // mohan::zeroize_hack(&mut excess);
// }
