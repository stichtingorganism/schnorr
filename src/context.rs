//! MuSug Process Context

use bacteria::Transcript;
use mohan::dalek::scalar::Scalar;
use crate::PublicKey;

/// The context for signing - can either be a Multikey or Multimessage context.
pub trait MuSigContext {
    /// Takes a mutable transcript, and commits the internal context to the transcript.
    fn commit(&self, transcript: &mut Transcript);

    /// Takes an index of a public key and mutable transcript,
    /// and returns the suitable challenge for that public key.
    fn challenge(&self, index: usize, transcript: &mut Transcript) -> Scalar;

    /// Length of the number of pubkeys in the context
    fn len(&self) -> usize;

    /// Returns the pubkey for the index i
    fn key(&self, index: usize) -> PublicKey;
}


