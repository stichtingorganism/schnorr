//! Other signers in the MuSig Protocol

use crate::{
    errors::{self, MuSigError},
    MuSigContext, PublicKey, SchnorrError,
};
use bacteria::Transcript;
use mohan::dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use subtle::ConstantTimeEq;

#[derive(Copy, Clone)]
pub struct NoncePrecommitment([u8; 32]);

#[derive(Copy, Clone, Debug)]
pub struct NonceCommitment(RistrettoPoint);

impl NonceCommitment {
    pub(crate) fn new(commitment: RistrettoPoint) -> Self {
        NonceCommitment(commitment)
    }

    pub(crate) fn precommit(&self) -> NoncePrecommitment {
        let mut h = Transcript::new(b"Musig.nonce-precommit");
        h.commit_point(b"R", &self.0.compress());
        let mut precommitment = [0u8; 32];
        h.challenge_bytes(b"precommitment", &mut precommitment);
        NoncePrecommitment(precommitment)
    }

    pub(crate) fn sum(commitments: &Vec<Self>) -> RistrettoPoint {
        commitments.iter().map(|R_i| R_i.0).sum()
    }
}

pub struct Counterparty {
    position: usize,
    pubkey: PublicKey,
}

pub struct CounterpartyPrecommitted {
    precommitment: NoncePrecommitment,
    position: usize,
    pubkey: PublicKey,
}

pub struct CounterpartyCommitted {
    commitment: NonceCommitment,
    position: usize,
    pubkey: PublicKey,
}

impl Counterparty {
    pub(crate) fn new(position: usize, pubkey: PublicKey) -> Self {
        Counterparty { position, pubkey }
    }

    pub(crate) fn precommit_nonce(
        self,
        precommitment: NoncePrecommitment,
    ) -> CounterpartyPrecommitted {
        CounterpartyPrecommitted {
            precommitment,
            position: self.position,
            pubkey: self.pubkey,
        }
    }
}

impl CounterpartyPrecommitted {
    pub(crate) fn verify_nonce(
        self,
        commitment: NonceCommitment,
    ) -> Result<CounterpartyCommitted, SchnorrError> {
        // Check H(commitment) =? precommitment
        let received_precommitment = commitment.precommit();
        let equal = self.precommitment.0.ct_eq(&received_precommitment.0);

        if equal.unwrap_u8() == 0 {
            return Err(errors::from_musig(MuSigError::ShareError {
                pubkey: self.pubkey.into_compressed().to_bytes(),
            }));
        }

        Ok(CounterpartyCommitted {
            commitment: commitment,
            position: self.position,
            pubkey: self.pubkey,
        })
    }
}

impl CounterpartyCommitted {
    pub(crate) fn verify_share<C: MuSigContext>(
        self,
        share: Scalar,
        context: &C,
        transcript: &Transcript,
    ) -> Result<Scalar, SchnorrError> {
        // Check the partial Schnorr signature:
        // s_i * G == R_i + c_i * X_i.
        let S_i = share * RISTRETTO_BASEPOINT_POINT;
        let c_i = context.challenge(self.position, &mut transcript.clone());
        let X_i = self.pubkey.into_point();

        if S_i != self.commitment.0 + c_i * X_i {
            return Err(errors::from_musig(MuSigError::ShareError {
                pubkey: X_i.compress().to_bytes(),
            }));
        }

        Ok(share)
    }
}
