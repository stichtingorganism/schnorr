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

