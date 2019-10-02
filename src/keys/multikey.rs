//! MuSig Key

use mohan::dalek::{
    scalar::Scalar, 
    ristretto::RistrettoPoint
}; 
use bacteria::Transcript;
use crate::{
    PublicKey,
    SchnorrError, 
    MuSigContext,
    errors::{self, MuSigError}
};


/// MuSig aggregated key context
#[derive(Clone)]
pub struct MultiKey {
    prf: Option<Transcript>,
    aggregated_key: PublicKey,
    public_keys: Vec<PublicKey>,
}

impl MultiKey {

    /// Constructs a new MuSig multikey aggregating the pubkeys.
    pub fn new(pubkeys: Vec<PublicKey>) -> Result<Self, SchnorrError> {
        match pubkeys.len() {
            0 => {
                return Err(
                    errors::from_musig(MuSigError::BadArguments)
                );
            }
            1 => {
                // Special case: single key can be wrapped in a Multikey type
                // without a delinearization factor applied.
                return Ok(MultiKey {
                    prf: None,
                    aggregated_key: pubkeys[0],
                    public_keys: pubkeys,
                });
            }
            _ => {}
        }

        // Create transcript for Multikey
        let mut prf = Transcript::new(b"Musig.aggregated-key");
        prf.append_u64(b"n", pubkeys.len() as u64);

        // Commit pubkeys into the transcript
        // <L> = H(X_1 || X_2 || ... || X_n)
        for X in &pubkeys {
            prf.commit_point(b"X", X.as_compressed());
        }

        // aggregated_key = sum_i ( a_i * X_i )
        let mut aggregated_key = RistrettoPoint::default();

        for (i, X) in pubkeys.iter().enumerate() {
            let a = MultiKey::compute_factor(&prf, i);
            let X = X.into_point();
            aggregated_key = aggregated_key + a * X;
        }

        Ok(MultiKey {
            prf: Some(prf),
            aggregated_key: PublicKey::from_point(aggregated_key),
            public_keys: pubkeys,
        })
    }

    /// Returns `a_i` factor for component key in aggregated key.
    /// a_i = H(<L>, X_i). The list of pubkeys, <L>, has already been committed to the transcript.
    fn compute_factor(prf: &Transcript, i: usize) -> Scalar {
        let mut a_i_prf = prf.clone();
        a_i_prf.append_u64(b"i", i as u64);
        a_i_prf.challenge_scalar(b"a_i")
    }

    /// Returns VerificationKey representation of aggregated key.
    pub fn aggregated_key(&self) -> PublicKey {
        self.aggregated_key
    }
}




impl MuSigContext for MultiKey {

    fn commit(&self, transcript: &mut Transcript) {
        //domain seperration
        transcript.proto_name(b"schnorr_sig");
        //commit corresponding public key
        transcript.commit_point(b"public_key", self.aggregated_key.as_compressed());
    }

    fn challenge(&self, i: usize, transcript: &mut Transcript) -> Scalar {
        // Make c = H(X, R, m)
        // The message `m`, nonce commitment `R`, and aggregated key `X`
        // have already been fed into the transcript.
        let c = transcript.challenge_scalar(b"c");

        // Make a_i, the per-party factor. a_i = H(<L>, X_i).
        // The list of pubkeys, <L>, has already been committed to self.transcript.
        let a_i = match &self.prf {
            Some(t) => MultiKey::compute_factor(&t, i),
            None => Scalar::one(),
        };

        c * a_i
    }

    fn len(&self) -> usize {
        self.public_keys.len()
    }

    fn key(&self, index: usize) -> PublicKey {
        self.public_keys[index]
    }
}