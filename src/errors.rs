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



use std::fmt;
use failure::{Backtrace, Context, Fail};

/// An alias for results returned by functions of this crate
pub type SchnorrResult<T> = ::std::result::Result<T, SchnorrError>;

#[derive(Eq, PartialEq, Debug, Fail, Clone)]
pub enum MuSigError {
    /// The number of public nonces must match the number of public keys in the joint key
    #[fail(display = "The number of public nonces must match the number of public keys in the joint key")]
    MismatchedNonces,
    /// The number of partial signatures must match the number of public keys in the joint key
    #[fail(display = "The number of partial signatures must match the number of public keys in the joint key")]
    MismatchedSignatures,
    /// The aggregate signature did not verify
    #[fail(display = "The aggregate signature did not verify")]
    InvalidAggregateSignature,
    /// A partial signature did not validate
    #[fail(display = "A partial signature did not validate at index: {}", _0)]
    InvalidPartialSignature(usize),
    /// The participant list must be sorted before making this call
    #[fail(display = "The participant list must be sorted before making this call")]
    NotSorted,
    /// The participant key is not in the list
    #[fail(display = "The participant key is not in the list")]
    ParticipantNotFound,
    /// An attempt was made to perform an invalid MuSig state transition
    #[fail(display = "An attempt was made to perform an invalid MuSig state transition")]
    InvalidStateTransition,
    /// An attempt was made to add a duplicate public key to a MuSig signature
    #[fail(display = "An attempt was made to add a duplicate public key to a MuSig signature")]
    DuplicatePubKey,
    /// There are too many parties in the MuSig signature
    #[fail(display = "There are too many parties in the MuSig signature")]
    TooManyParticipants,
    /// There are too few parties in the MuSig signature
    #[fail(display = "There are too few parties in the MuSig signature")]
    NotEnoughParticipants,
    /// A nonce hash is missing
    #[fail(display = "A nonce hash is missing")]
    MissingNonce,
    /// The message to be signed can only be set once
    #[fail(display = "The message to be signed can only be set once")]
    MessageAlreadySet,
    /// The message to be signed MUST be set before the final nonce is added to the MuSig ceremony
    #[fail(display = "The message to be signed MUST be set before the final nonce is added to the MuSig ceremony")]
    MissingMessage,
    /// The message to sign is invalid. have you hashed it?
    #[fail(display = "The message to sign is invalid. have you hashed it?")]
    InvalidMessage,
    /// MuSig requires a hash function with a 32 byte digest
    #[fail(display = "MuSig requires a hash function with a 32 byte digest")]
    IncompatibleHashFunction,
}


/// Internal errors.  Most application-level developers will likely not
/// need to pay any attention to these.
#[derive(Eq, PartialEq, Debug, Fail, Clone)]
pub enum InternalError {
    /// Invalid point provided.
    #[fail(display = "Cannot decompress Edwards point")]
    PointDecompressionError,

    /// Invalid scalar provided.
    #[fail(display = "Cannot use scalar with high-bit set")]
    ScalarFormatError,

    /// An error in the length of bytes handed to a constructor.
    ///
    /// To use this, pass a string specifying the `name` of the type which is
    /// returning the error, and the `length` in bytes which its constructor
    /// expects.
    #[fail(
        display = "{} must be {} bytes in length",
        name, length
    )]
    BytesLengthError { 
        /// Identifies the type returning the error
        name: &'static str,  
        /// Describes the type returning the error
        description: &'static str,
        /// Length expected by the constructor in bytes
        length: usize 
    },

    /// The verification equation wasn't satisfied
    #[fail(display = "Verification equation was not satisfied")]
    VerifyError,

    /// This error occurs when a function is called with bad arguments.
    #[fail(display = "Function is called with bad arguments")]
    BadArguments,

    /// Musig  
    #[fail(
        display = "Absent {} violated multi-signature protocol",
        _0
    )]
    MuSig {
        kind: MuSigError 
    }


}



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
#[derive(Debug)]
pub struct SchnorrError {
    inner: Context<InternalError>,
}

impl SchnorrError {
    /// Get the kind of the error
    pub fn kind(&self) -> &InternalError {
        self.inner.get_context()
    }
}


impl Clone for SchnorrError {
    fn clone(&self) -> Self {
        SchnorrError {
            inner: Context::new(self.inner.get_context().clone()),
        }
    }
}


impl fmt::Display for SchnorrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl Fail for SchnorrError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl From<InternalError> for SchnorrError {
    fn from(kind: InternalError) -> SchnorrError {
        SchnorrError {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<InternalError>> for SchnorrError {
    fn from(inner: Context<InternalError>) -> SchnorrError {
        SchnorrError { inner }
    }
}


/// Convert `SchnorrError` into `::serde::de::Error` aka `SerdeError`
///
/// We should do this with `From` but right now the orphan rules prohibit
/// `impl From<SchnorrError> for E where E: ::serde::de::Error`.
pub(crate) fn serde_error_from_signature_error<E>(err: SchnorrError) -> E
where E: ::serde::de::Error
{
    match *err.kind() {
        InternalError::PointDecompressionError
            => E::custom("Ristretto point decompression failed"),
        InternalError::ScalarFormatError
            => E::custom("improper scalar has high-bit set"), 
        InternalError::BytesLengthError{ description, length, .. }
            => E::invalid_length(length, &description),
        _ => panic!("Non-serialisation error encountered by serde!"),
    }
}