//! The crate's error type.

use thiserror::Error;

/// The ways X-Wing operations can fail. None of the variants holds key bytes, so they are
/// safe to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    /// A byte string has the wrong length for the value it should hold.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// The length the value needs, in bytes.
        expected: usize,
        /// The length that was given, in bytes.
        actual: usize,
    },
    /// The ML-KEM-768 part of an encapsulation key (`pk_m`) fails the FIPS 203 modulus check.
    #[error("encapsulation key fails the FIPS 203 modulus check")]
    InvalidEncapsulationKey,
    /// The operating system's random number generator failed.
    #[error("random number generator failed")]
    Random,
}

#[cfg(test)]
mod tests;
