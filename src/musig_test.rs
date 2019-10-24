//! Musig Tests

use bacteria::Transcript;
use mohan::dalek::{ristretto::CompressedRistretto, scalar::Scalar};

use crate::{
    errors::MuSigError, MuSigContext, MultiKey, Multimessage, Multisignature, PublicKey, SecretKey,
    Signature, Signer,
};

#[test]
fn sign_verify_single_multikey() {
    let privkey = SecretKey::from_scalar(Scalar::from(1u64));
    let privkeys = vec![privkey];
    let multikey = multikey_helper(&privkeys);
    let (sig, _) = sign_with_mpc(
        &privkeys,
        multikey.clone(),
        Transcript::new(b"example transcript"),
    )
    .unwrap();

    assert!(sig
        .verify(
            &mut Transcript::new(b"example transcript"),
            &multikey.aggregated_key()
        )
        .is_ok());
}

fn multikey_helper(priv_keys: &Vec<SecretKey>) -> MultiKey {
    MultiKey::new(
        priv_keys
            .iter()
            .map(|priv_key| PublicKey::from_secret(priv_key))
            .collect(),
    )
    .unwrap()
}

#[test]
fn sign_multikey() {
    // super secret, sshhh!
    let priv_keys = vec![
        SecretKey::from_scalar(Scalar::from(1u64)),
        SecretKey::from_scalar(Scalar::from(2u64)),
        SecretKey::from_scalar(Scalar::from(3u64)),
        SecretKey::from_scalar(Scalar::from(4u64)),
    ];

    let multikey = multikey_helper(&priv_keys);

    assert!(sign_with_mpc(&priv_keys, multikey, Transcript::new(b"example transcript")).is_ok());
}

fn sign_with_mpc<C: MuSigContext + Clone>(
    privkeys: &Vec<SecretKey>,
    context: C,
    transcript: Transcript,
) -> Result<(Signature, Scalar), MuSigError> {
    let pubkeys: Vec<_> = privkeys
        .iter()
        .map(|privkey| PublicKey::from_secret(privkey))
        .collect();

    let mut transcripts: Vec<_> = pubkeys.iter().map(|_| transcript.clone()).collect();

    let (parties, precomms): (Vec<_>, Vec<_>) = privkeys
        .clone()
        .into_iter()
        .zip(transcripts.iter_mut())
        .enumerate()
        .map(|(i, (x_i, transcript))| Signer::new(transcript, i, x_i.to_scalar(), context.clone()))
        .unzip();

    let (parties, comms): (Vec<_>, Vec<_>) = parties
        .into_iter()
        .map(|p| p.receive_precommitments(precomms.clone()))
        .unzip();

    let (parties, shares): (Vec<_>, Vec<_>) = parties
        .into_iter()
        .map(|p| p.receive_commitments(comms.clone()).unwrap())
        .unzip();

    let signatures: Vec<Signature> = parties
        .into_iter()
        .map(|p| p.receive_shares(shares.clone()).unwrap())
        .collect();

    // Check that signatures from all parties are the same
    let cmp = &signatures[0];
    for sig in &signatures {
        assert_eq!(cmp.s, sig.s);
        assert_eq!(cmp.R, sig.R)
    }

    // Check that all party transcripts are in sync at end of the protocol
    let cmp_challenge = transcripts[0].clone().challenge_scalar(b"test");
    for mut transcript in transcripts {
        let challenge = transcript.challenge_scalar(b"test");
        assert_eq!(cmp_challenge, challenge);
    }

    Ok((signatures[0].clone(), cmp_challenge))
}

#[test]
fn verify_multikey() {
    // super secret, sshhh!
    let priv_keys = vec![
        SecretKey::from_scalar(Scalar::from(1u64)),
        SecretKey::from_scalar(Scalar::from(2u64)),
        SecretKey::from_scalar(Scalar::from(3u64)),
        SecretKey::from_scalar(Scalar::from(4u64)),
    ];

    let multikey = multikey_helper(&priv_keys);

    let (signature, _) = sign_with_mpc(
        &priv_keys,
        multikey.clone(),
        Transcript::new(b"example transcript"),
    )
    .unwrap();

    assert!(signature
        .verify(
            &mut Transcript::new(b"example transcript"),
            &multikey.aggregated_key()
        )
        .is_ok());
}

#[test]
fn check_transcripts_multikey() {
    // super secret, sshhh!
    let priv_keys = vec![
        SecretKey::from_scalar(Scalar::from(1u64)),
        SecretKey::from_scalar(Scalar::from(2u64)),
        SecretKey::from_scalar(Scalar::from(3u64)),
        SecretKey::from_scalar(Scalar::from(4u64)),
    ];
    let multikey = multikey_helper(&priv_keys);

    let (signature, prover_challenge) = sign_with_mpc(
        &priv_keys,
        multikey.clone(),
        Transcript::new(b"example transcript"),
    )
    .unwrap();

    let verifier_transcript = &mut Transcript::new(b"example transcript");
    assert!(signature
        .verify(verifier_transcript, &multikey.aggregated_key())
        .is_ok());

    let verifier_challenge = verifier_transcript.challenge_scalar(b"test");

    // Test that prover and verifier transcript states are the same after running protocol
    assert_eq!(prover_challenge, verifier_challenge);
}

#[test]
fn sign_multimessage() {
    // super secret, sshhh!
    let priv_keys = vec![
        SecretKey::from_scalar(Scalar::from(1u64)),
        SecretKey::from_scalar(Scalar::from(2u64)),
        SecretKey::from_scalar(Scalar::from(3u64)),
        SecretKey::from_scalar(Scalar::from(4u64)),
    ];
    let messages = vec![b"message1", b"message2", b"message3", b"message4"];
    let multimessage = Multimessage::new(multimessage_helper(&priv_keys, messages));

    assert!(sign_with_mpc(
        &priv_keys,
        multimessage,
        Transcript::new(b"example transcript")
    )
    .is_ok());
}

fn multimessage_helper<M: AsRef<[u8]>>(
    priv_keys: &Vec<SecretKey>,
    messages: Vec<M>,
) -> Vec<(PublicKey, M)> {
    priv_keys
        .iter()
        .zip(messages.into_iter())
        .map(|(priv_key, msg)| (PublicKey::from_secret(priv_key), msg))
        .collect()
}

#[test]
fn verify_multimessage_mpc() {
    // super secret, sshhh!
    let priv_keys = vec![
        SecretKey::from_scalar(Scalar::from(1u64)),
        SecretKey::from_scalar(Scalar::from(2u64)),
        SecretKey::from_scalar(Scalar::from(3u64)),
        SecretKey::from_scalar(Scalar::from(4u64)),
    ];
    let messages = vec![b"message1", b"message2", b"message3", b"message4"];
    let multimessage = Multimessage::new(multimessage_helper(&priv_keys, messages.clone()));

    let (signature, _) = sign_with_mpc(
        &priv_keys,
        multimessage.clone(),
        Transcript::new(b"example transcript"),
    )
    .unwrap();

    assert!(signature
        .verify_multi(
            &mut Transcript::new(b"example transcript"),
            multimessage_helper(&priv_keys, messages)
        )
        .is_ok());
}

#[test]
fn verify_multimessage_singleplayer() {
    // super secret, sshhh!
    let priv_keys = vec![
        SecretKey::from_scalar(Scalar::from(1u64)),
        SecretKey::from_scalar(Scalar::from(2u64)),
        SecretKey::from_scalar(Scalar::from(3u64)),
        SecretKey::from_scalar(Scalar::from(4u64)),
    ];
    let messages = vec![b"message1", b"message2", b"message3", b"message4"];
    let pairs = multimessage_helper(&priv_keys, messages.clone());

    let signature = Signature::sign_multi(
        priv_keys.clone(),
        pairs,
        &mut Transcript::new(b"example transcript"),
    )
    .unwrap();

    assert!(signature
        .verify_multi(
            &mut Transcript::new(b"example transcript"),
            multimessage_helper(&priv_keys, messages)
        )
        .is_ok());
}

#[test]
fn check_transcripts_multimessage() {
    // super secret, sshhh!
    let priv_keys = vec![
        SecretKey::from_scalar(Scalar::from(1u64)),
        SecretKey::from_scalar(Scalar::from(2u64)),
        SecretKey::from_scalar(Scalar::from(3u64)),
        SecretKey::from_scalar(Scalar::from(4u64)),
    ];
    let messages = vec![b"message1", b"message2", b"message3", b"message4"];
    let multimessage = Multimessage::new(multimessage_helper(&priv_keys, messages.clone()));

    let (signature, prover_challenge) = sign_with_mpc(
        &priv_keys,
        multimessage.clone(),
        Transcript::new(b"example transcript"),
    )
    .unwrap();

    let verifier_transcript = &mut Transcript::new(b"example transcript");
    assert!(signature
        .verify_multi(
            verifier_transcript,
            multimessage_helper(&priv_keys, messages)
        )
        .is_ok());

    let verifier_challenge = verifier_transcript.challenge_scalar(b"test");

    // Test that prover and verifier transcript states are the same after running protocol
    assert_eq!(prover_challenge, verifier_challenge);
}
