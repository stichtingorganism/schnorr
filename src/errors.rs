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

use failure::Fail;

/// Represents an error in key aggregation, signing, or verification.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum MuSigError {
    /// This error occurs when a point is not a valid compressed Ristretto point
    #[fail(display = "Point decoding failed")]
    InvalidPoint,

    /// This error occurs when a signature share fails to verify
    #[fail(display = "Share #{:?} failed to verify correctly", pubkey)]
    ShareError {
        /// The pubkey corresponding to the share that failed fo verify correctly
        pubkey: [u8; 32],
    },

    /// This error occurs when an individual point operation failed.
    #[fail(display = "Point operation failed")]
    PointOperationFailed,

    /// This error occurs when a function is called with bad arguments.
    #[fail(display = "Bad arguments")]
    BadArguments,

    /// There are too many parties in the MuSig signature
    #[fail(display = "There are too many parties in the MuSig signature")]
    TooManyParticipants,
}

/// Internal errors.  Most application-level developers will likely not
/// need to pay any attention to these.
#[derive(Eq, PartialEq, Debug, Fail, Clone)]
pub enum SchnorrError {
    /// Invalid point provided.
    #[fail(display = "Cannot decompress Edwards point")]
    PointDecompressionError,

    /// Invalid scalar provided.
    #[fail(display = "Cannot use scalar with high-bit set")]
    ScalarFormatError,

    /// Invalid ser provided.
    #[fail(display = "Issue When Serilizing Data")]
    SerError,

    /// The verification equation wasn't satisfied
    #[fail(display = "Verification equation was not satisfied")]
    VerifyError,

    /// This error occurs when a function is called with bad arguments.
    #[fail(display = "Function is called with bad arguments")]
    BadArguments,

    /// Musig  
    #[fail(display = "Absent {} violated multi-signature protocol", _0)]
    MuSig { kind: MuSigError },

    /// This error occurs when a point is not a valid compressed Ristretto point
    #[fail(display = "Signature verification failed")]
    InvalidSignature,

    /// This error occurs when a set of signatures failed to verify as a batch
    #[fail(display = "Batch signature verification failed")]
    InvalidBatch,

    /// VSS Error 
    #[fail(display = "VSS share error")]
    VerifyShareError
}


/// Helper function to foncert a musig error into schnorr error
pub fn from_musig(err: MuSigError) -> SchnorrError {
    SchnorrError::MuSig { kind: err }
}



// #[derive(Eq, PartialEq, Debug, Fail, Clone)]
// pub enum MuSigError {
//     /// The number of public nonces must match the number of public keys in the joint key
//     #[fail(display = "The number of public nonces must match the number of public keys in the joint key")]
//     MismatchedNonces,
//     /// The number of partial signatures must match the number of public keys in the joint key
//     #[fail(display = "The number of partial signatures must match the number of public keys in the joint key")]
//     MismatchedSignatures,
//     /// The aggregate signature did not verify
//     #[fail(display = "The aggregate signature did not verify")]
//     InvalidAggregateSignature,
//     /// A partial signature did not validate
//     #[fail(display = "A partial signature did not validate at index: {}", _0)]
//     InvalidPartialSignature(usize),
//     /// The participant list must be sorted before making this call
//     #[fail(display = "The participant list must be sorted before making this call")]
//     NotSorted,
//     /// The participant key is not in the list
//     #[fail(display = "The participant key is not in the list")]
//     ParticipantNotFound,
//     /// An attempt was made to perform an invalid MuSig state transition
//     #[fail(display = "An attempt was made to perform an invalid MuSig state transition")]
//     InvalidStateTransition,
//     /// An attempt was made to add a duplicate public key to a MuSig signature
//     #[fail(display = "An attempt was made to add a duplicate public key to a MuSig signature")]
//     DuplicatePubKey,
//     /// There are too many parties in the MuSig signature
//     #[fail(display = "There are too many parties in the MuSig signature")]
//     TooManyParticipants,
//     /// There are too few parties in the MuSig signature
//     #[fail(display = "There are too few parties in the MuSig signature")]
//     NotEnoughParticipants,
//     /// A nonce hash is missing
//     #[fail(display = "A nonce hash is missing")]
//     MissingNonce,
//     /// The message to be signed can only be set once
//     #[fail(display = "The message to be signed can only be set once")]
//     MessageAlreadySet,
//     /// The message to be signed MUST be set before the final nonce is added to the MuSig ceremony
//     #[fail(display = "The message to be signed MUST be set before the final nonce is added to the MuSig ceremony")]
//     MissingMessage,
//     /// The message to sign is invalid. have you hashed it?
//     #[fail(display = "The message to sign is invalid. have you hashed it?")]
//     InvalidMessage,
//     /// MuSig requires a hash function with a 32 byte digest
//     #[fail(display = "MuSig requires a hash function with a 32 byte digest")]
//     IncompatibleHashFunction,
// }
