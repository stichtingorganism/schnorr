use std::borrow::Borrow;
use std::iter;
use mohan::dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul}
};
use rand::{CryptoRng, RngCore};
use crate::SchnorrError;

/// Trait for a batch verification of signatures.
/// If you are only verifying signatures, without other proofs, you can use
/// concrete implementation `BatchVerifier` without rolling out your own.
pub trait BatchVerification {
    /// Adds scalar for multiplying by a base point and pairs of dynamic scalars/points.
    /// The API admits variable-length iterators of scalars/points
    /// for compatibility with multi-key signatures (see Musig).
    /// It is responsibility of the caller to provide iterators of scalars and points with matching lengths.
    fn append<I, J>(&mut self, basepoint_scalar: I::Item, dynamic_scalars: I, dynamic_points: J)
    where
        I: IntoIterator<Item = Scalar>,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>;
}

/// Single signature verifier that implements batching interface.
pub struct SingleVerifier {
    result: Result<(), SchnorrError>,
}

impl SingleVerifier {
    /// Creates a new verifier
    pub fn verify<F>(closure: F) -> Result<(), SchnorrError>
    where
        F: FnOnce(&mut Self),
    {
        let mut verifier = Self {
            result: Err(SchnorrError::InvalidSignature),
        };
        closure(&mut verifier);
        verifier.result
    }
}

impl BatchVerification for SingleVerifier {
    fn append<I, J>(&mut self, basepoint_scalar: I::Item, dynamic_scalars: I, dynamic_points: J)
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>,
    {
        self.result = RistrettoPoint::optional_multiscalar_mul(
            iter::once(basepoint_scalar).chain(dynamic_scalars),
            iter::once(Some(RISTRETTO_BASEPOINT_POINT)).chain(dynamic_points),
        )
        .ok_or(SchnorrError::InvalidSignature)
        .and_then(|result| {
            if result.is_identity() {
                Ok(())
            } else {
                Err(SchnorrError::InvalidSignature)
            }
        })
    }
}

/// Batch signature verifier for use with `Signature::verify_batched`.
pub struct BatchVerifier<R: RngCore + CryptoRng> {
    rng: R,
    basepoint_scalar: Scalar,
    dyn_weights: Vec<Scalar>,
    dyn_points: Vec<Option<RistrettoPoint>>,
}

impl<R: RngCore + CryptoRng> BatchVerifier<R> {
    /// Returns a new instance for batch verification
    pub fn new(rng: R) -> Self {
        Self::with_capacity(rng, 0)
    }

    /// Returns a new instance for batch verification with pre-allocated capacity `n`
    /// for verifying `n` simple schnorr signatures.
    pub fn with_capacity(rng: R, capacity: usize) -> Self {
        Self {
            rng,
            basepoint_scalar: Scalar::zero(),
            dyn_weights: Vec::with_capacity(capacity * 2),
            dyn_points: Vec::with_capacity(capacity * 2),
        }
    }

    /// Performs the verification and returns the result.
    pub fn verify(self) -> Result<(), SchnorrError> {
        let result = RistrettoPoint::optional_multiscalar_mul(
            // Add base points
            iter::once(self.basepoint_scalar).chain(self.dyn_weights.into_iter()),
            iter::once(Some(RISTRETTO_BASEPOINT_POINT)).chain(self.dyn_points.into_iter()),
        )
        .ok_or(SchnorrError::InvalidBatch)?;

        if result.is_identity() {
            Ok(())
        } else {
            Err(SchnorrError::InvalidBatch)
        }
    }
}

impl<R: RngCore + CryptoRng> BatchVerification for BatchVerifier<R> {
    fn append<I, J>(&mut self, basepoint_scalar: I::Item, dynamic_scalars: I, dynamic_points: J)
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<RistrettoPoint>>,
    {
        // Random factor `r` for each set of operations guarantees that
        // individual operations are unlikely (p < 2^-252) to cancel each other,
        // and therefore each operation must produce an identity point.
        let mut r = Scalar::random(&mut self.rng);

        // Compute the basepoint coefficient, running summation
        self.basepoint_scalar += r * basepoint_scalar.borrow();

        // Add weights and points for arbitrary points
        self.dyn_weights
            .extend(dynamic_scalars.into_iter().map(|f| r * f.borrow()));

        self.dyn_points.extend(dynamic_points);

        //zero out secret r
        mohan::zeroize_hack(&mut r);
    }
}