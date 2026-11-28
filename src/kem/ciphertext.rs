//! The X-Wing ciphertext.

use core::fmt;

use ml_kem::array::Array;
use ml_kem::ml_kem_768;
use x25519_dalek::PublicKey;

use crate::{CIPHERTEXT_SIZE, Error};

/// The length of `ct_m`, 1088 bytes. It comes first in `ct`.
const CT_M_SIZE: usize = 1088;

/// The length of `ct_x`, 32 bytes. It fills the rest of `ct`.
const CT_X_SIZE: usize = CIPHERTEXT_SIZE - CT_M_SIZE;

/// An X-Wing ciphertext: `ct_m` followed by `ct_x`, 1120 bytes in all.
///
/// Any 1120 bytes are a valid ciphertext, so building one can't fail. It's public, so `Debug`
/// shows its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext {
    /// The serialized ciphertext, `ct_m ‖ ct_x`.
    ct: [u8; CIPHERTEXT_SIZE],
}

impl Ciphertext {
    /// Builds the ciphertext from the ML-KEM-768 ciphertext `ct_m` and the X25519 ciphertext
    /// `ct_x`.
    pub(crate) fn new(ct_m: &ml_kem_768::Ciphertext, ct_x: &PublicKey) -> Self {
        let mut ct = [0u8; CIPHERTEXT_SIZE];
        let (ct_m_bytes, ct_x_bytes) = ct.split_at_mut(CT_M_SIZE);
        ct_m_bytes.copy_from_slice(ct_m);
        ct_x_bytes.copy_from_slice(ct_x.as_bytes());
        Self { ct }
    }

    /// Returns the ML-KEM-768 ciphertext `ct_m`, the first 1088 bytes.
    pub(crate) fn ct_m(&self) -> ml_kem_768::Ciphertext {
        // The index range lies inside the fixed-size `ct`, so this copy can't fail.
        Array::from_fn(|i| self.ct[i])
    }

    /// Returns the X25519 ciphertext `ct_x`, the last 32 bytes.
    pub(crate) fn ct_x(&self) -> [u8; CT_X_SIZE] {
        core::array::from_fn(|i| self.ct[CT_M_SIZE + i])
    }

    /// Returns the 1120-byte serialized ciphertext, `ct_m` followed by `ct_x`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_SIZE] {
        &self.ct
    }
}

impl From<[u8; CIPHERTEXT_SIZE]> for Ciphertext {
    /// Wraps the 1120 bytes `ct`. Any bytes are accepted.
    fn from(ct: [u8; CIPHERTEXT_SIZE]) -> Self {
        Self { ct }
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = Error;

    /// Wraps a ciphertext given as a slice.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `ct` isn't 1120 bytes long.
    fn try_from(ct: &[u8]) -> Result<Self, Error> {
        let ct: [u8; CIPHERTEXT_SIZE] = ct.try_into().map_err(|_| Error::InvalidLength {
            expected: CIPHERTEXT_SIZE,
            actual: ct.len(),
        })?;
        Ok(Self { ct })
    }
}

impl fmt::Debug for Ciphertext {
    /// Writes the serialized ciphertext.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ciphertext").field("ct", &self.ct).finish()
    }
}
