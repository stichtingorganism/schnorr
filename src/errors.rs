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

//! Errors which may occur when parsing keys and/or signatures to or from wire formats.

use thiserror::Error;

/// Represents an error in key aggregation, signing, or verification.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum MuSigError {
    /// This error occurs when a point is not a valid compressed Ristretto point
    #[error("Point decoding failed")]
    InvalidPoint,

    /// This error occurs when a signature share fails to verify
    #[error("Share {pubkey:?} failed to verify correctly")]
    ShareError {
        /// The pubkey corresponding to the share that failed fo verify correctly
        pubkey: [u8; 32],
    },

    /// This error occurs when an individual point operation failed.
    #[error("Point operation failed")]
    PointOperationFailed,

    /// This error occurs when a function is called with bad arguments.
    #[error("Bad arguments")]
    BadArguments,

    /// There are too many parties in the MuSig signature
    #[error("There are too many parties in the MuSig signature")]
    TooManyParticipants,
}

/// Internal errors.  Most application-level developers will likely not
/// need to pay any attention to these.
#[derive(Eq, PartialEq, Debug, Error, Clone)]
pub enum SchnorrError {
    /// Invalid point provided.
    #[error("Cannot decompress Edwards point")]
    PointDecompressionError,

    /// Invalid scalar provided.
    #[error("Cannot use scalar with high-bit set")]
    ScalarFormatError,

    /// Invalid ser provided.
    #[error("Issue When Serilizing Data")]
    SerError,

    /// The verification equation wasn't satisfied
    #[error("Verification equation was not satisfied")]
    VerifyError,

    /// This error occurs when a function is called with bad arguments.
    #[error("Function is called with bad arguments")]
    BadArguments,

    /// Musig  
    #[error("Absent {kind:?} violated multi-signature protocol")]
    MuSig { kind: MuSigError },

    /// This error occurs when a point is not a valid compressed Ristretto point
    #[error("Signature verification failed")]
    InvalidSignature,

    /// This error occurs when a set of signatures failed to verify as a batch
    #[error("Batch signature verification failed")]
    InvalidBatch,

    /// VSS Error 
    #[error("VSS share error")]
    VerifyShareError
}




/// Helper function to foncert a musig error into schnorr error
pub fn from_musig(err: MuSigError) -> SchnorrError {
    SchnorrError::MuSig { kind: err }
}

/// Convert `SchnorrError` into `::serde::de::Error` aka `SerdeError`
///
/// We should do this with `From` but right now the orphan rules prohibit
/// `impl From<SchnorrError> for E where E: ::serde::de::Error`.
pub(crate) fn serde_error_from_signature_error<E>(err: SchnorrError) -> E
where E: ::serde::de::Error
{
    match err {
        SchnorrError::PointDecompressionError
            => E::custom("Ristretto point decompression failed"),
        SchnorrError::ScalarFormatError
            => E::custom("improper scalar has high-bit set"), 
        SchnorrError::SerError
            =>  E::custom("improper serde usage"), 
        _ => panic!("Non-serialisation error encountered by serde!"),
    }
}
