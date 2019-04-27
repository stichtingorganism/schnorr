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

// rustc seems to think the typenames in match statements (e.g. in
// Display) should be snake cased, for some reason.
#![allow(non_snake_case)]

use core::fmt;
use core::fmt::Display;

#[derive(Clone, Debug, PartialEq, Eq, Copy, Hash)]
pub enum MuSigError {
    /// The number of public nonces must match the number of public keys in the joint key
    MismatchedNonces,
    /// The number of partial signatures must match the number of public keys in the joint key
    MismatchedSignatures,
    /// The aggregate signature did not verify
    InvalidAggregateSignature,
    /// A partial signature did not validate
    InvalidPartialSignature(usize),
    /// The participant list must be sorted before making this call
    NotSorted,
    /// The participant key is not in the list
    ParticipantNotFound,
    /// An attempt was made to perform an invalid MuSig state transition
    InvalidStateTransition,
    /// An attempt was made to add a duplicate public key to a MuSig signature
    DuplicatePubKey,
    /// There are too many parties in the MuSig signature
    TooManyParticipants,
    /// There are too few parties in the MuSig signature
    NotEnoughParticipants,
    /// A nonce hash is missing
    MissingNonce,
    /// The message to be signed can only be set once
    MessageAlreadySet,
    /// The message to be signed MUST be set before the final nonce is added to the MuSig ceremony
    MissingMessage,
    /// The message to sign is invalid. have you hashed it?
    InvalidMessage,
    /// MuSig requires a hash function with a 32 byte digest
    IncompatibleHashFunction,
}


impl Display for MuSigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MuSigError::MismatchedNonces
                => write!(f, "The number of public nonces must match the number of public keys in the joint key"),

            MuSigError::MismatchedSignatures
                => write!(f, "The number of partial signatures must match the number of public keys in the joint key"),

            MuSigError::InvalidAggregateSignature
                => write!(f, "The aggregate signature did not verify"),

            MuSigError::InvalidPartialSignature(_)
                => write!(f, " A partial signature did not validate"),
            
            MuSigError::NotSorted
                => write!(f, "The participant list must be sorted before making this call"),

            MuSigError::ParticipantNotFound
                => write!(f, "The participant key is not in the list"),

             MuSigError::InvalidStateTransition
                => write!(f, "An attempt was made to perform an invalid MuSig state transition"),

             MuSigError::DuplicatePubKey
                => write!(f, "An attempt was made to add a duplicate public key to a MuSig signature"),

             MuSigError::TooManyParticipants
                => write!(f, "There are too many parties in the MuSig signature"),

             MuSigError::NotEnoughParticipants
                => write!(f, "There are too few parties in the MuSig signature"),

             MuSigError::MissingNonce
                => write!(f, "A nonce hash is missing"),
            
             MuSigError::MessageAlreadySet
                => write!(f, "The message to be signed can only be set once"),

             MuSigError::MissingMessage
                => write!(f, "The message to be signed MUST be set before the final nonce is added to the MuSig ceremony"),

             MuSigError::InvalidMessage
                => write!(f, " The message to sign is invalid. have you hashed it?"),

            MuSigError::IncompatibleHashFunction
                => write!(f, " MuSig requires a hash function with a 32 byte digest"),
        }
    }
}

/// Internal errors.  Most application-level developers will likely not
/// need to pay any attention to these.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) enum InternalError {
    /// Invalid point provided.
    PointDecompressionError,

    /// Invalid scalar provided.
    ScalarFormatError,

    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass a string specifying the `name` of the type which is
    /// returning the error, and the `length` in bytes which its constructor
    /// expects.
    BytesLengthError { 
        /// Identifies the type returning the error
        name: &'static str,  
        /// Describes the type returning the error
        description: &'static str,
        /// Length expected by the constructor in bytes
        length: usize 
    },

    /// The verification equation wasn't satisfied
    VerifyError,

    /// This error occurs when a function is called with bad arguments.
    BadArguments,

    /// Musig
    MuSig {
        kind: MuSigError 
    }


}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InternalError::PointDecompressionError
                => write!(f, "Cannot decompress Edwards point"),

            InternalError::ScalarFormatError
                => write!(f, "Cannot use scalar with high-bit set"),

            InternalError::BytesLengthError{ name, length, ..}
                => write!(f, "{} must be {} bytes in length", name, length),

            InternalError::VerifyError
                => write!(f, "Verification equation was not satisfied"),
            
            InternalError::BadArguments
                => write!(f, "Function is called with bad arguments"),

            InternalError::MuSig{ kind }
                => write!(f, "Absent {} violated multi-signature protocol", kind),

        }
    }
}

impl ::failure::Fail for InternalError {}

/// Errors which may occur while processing signatures and keypairs.
///
/// This error may arise due to:
///
/// * Being given bytes with a length different to what was expected.
///
/// * A problem decompressing `r`, a curve point, in the `Signature`, or the
///   curve point for a `PublicKey`.
///
/// * A problem with the format of `s`, a scalar, in the `Signature`.  This
///   is only raised if the high-bit of the scalar was set.  (Scalars must
///   only be constructed from 255-bit integers.)
///
/// * Failure of a signature to satisfy the verification equation.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
pub struct SchnorrError(pub(crate) InternalError);

impl Display for SchnorrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ::failure::Fail for SchnorrError {
    fn cause(&self) -> Option<&::failure::Fail> {
        Some(&self.0)
    }
}


/// Convert `SchnorrError` into `::serde::de::Error` aka `SerdeError`
///
/// We should do this with `From` but right now the orphan rules prohibit
/// `impl From<SchnorrError> for E where E: ::serde::de::Error`.
pub(crate) fn serde_error_from_signature_error<E>(err: SchnorrError) -> E
where E: ::serde::de::Error
{
    match err {
        SchnorrError(InternalError::PointDecompressionError)
            => E::custom("Ristretto point decompression failed"),
        SchnorrError(InternalError::ScalarFormatError)
            => E::custom("improper scalar has high-bit set"), 
        SchnorrError(InternalError::BytesLengthError{ description, length, .. })
            => E::invalid_length(length, &description),
        _ => panic!("Non-serialisation error encountered by serde!"),
    }
}