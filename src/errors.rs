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
pub enum SchnorrError {
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

