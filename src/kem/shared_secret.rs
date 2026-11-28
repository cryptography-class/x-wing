//! The X-Wing shared secret.

use core::fmt;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SHARED_SECRET_SIZE;

/// An X-Wing shared secret: 32 bytes, erased from memory when dropped.
///
/// It has no `Clone`, and `Debug` doesn't show the bytes. Comparisons with `==` run in constant
/// time.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    /// The secret bytes, the SHA3-256 output of the combiner.
    ss: [u8; SHARED_SECRET_SIZE],
}

impl SharedSecret {
    /// Wraps the combiner output `ss`.
    pub(crate) fn new(ss: [u8; SHARED_SECRET_SIZE]) -> Self {
        Self { ss }
    }

    /// Returns the 32 secret bytes, for use as a symmetric key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.ss
    }
}

impl ConstantTimeEq for SharedSecret {
    /// Compares the secrets in constant time.
    fn ct_eq(&self, other: &Self) -> Choice {
        self.ss.ct_eq(&other.ss)
    }
}

impl PartialEq for SharedSecret {
    /// Compares the secrets in constant time, through [`ConstantTimeEq`].
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SharedSecret {}

impl fmt::Debug for SharedSecret {
    /// Writes `SharedSecret { .. }`, leaving out the secret bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret").finish_non_exhaustive()
    }
}
