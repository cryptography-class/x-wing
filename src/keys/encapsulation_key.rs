//! The X-Wing encapsulation key.

use core::fmt;

use ml_kem::array::Array;
use ml_kem::{KeyExport, ml_kem_768};
use x25519_dalek::PublicKey;

use crate::{ENCAPSULATION_KEY_SIZE, Error};

/// The length of `pk_m`, 1184 bytes. It comes first in `pk`.
const PK_M_SIZE: usize = 1184;

/// The length of `pk_x`, 32 bytes. It fills the rest of `pk`.
const PK_X_SIZE: usize = ENCAPSULATION_KEY_SIZE - PK_M_SIZE;

/// An X-Wing encapsulation key: `pk_m` followed by `pk_x`, 1216 bytes in all.
///
/// `pk_m` has passed the FIPS 203 modulus check, so encapsulation can't fail on it. The key keeps
/// both its bytes and the parsed `pk_m` and `pk_x`. It's public, so `Debug` shows its bytes.
#[derive(Clone)]
pub struct EncapsulationKey {
    /// The serialized key, `pk_m ‖ pk_x`.
    pk: [u8; ENCAPSULATION_KEY_SIZE],
    /// The parsed ML-KEM-768 encapsulation key.
    pk_m: ml_kem_768::EncapsulationKey,
    /// The parsed X25519 public key.
    pk_x: PublicKey,
}

impl EncapsulationKey {
    /// Builds the key from the `pk_m` and `pk_x` of an expanded decapsulation key.
    ///
    /// `pk_m` comes straight from ML-KEM-768 key generation, so the modulus check isn't run again.
    pub(super) fn new(pk_m: &ml_kem_768::EncapsulationKey, pk_x: &PublicKey) -> Self {
        let mut pk = [0u8; ENCAPSULATION_KEY_SIZE];
        let (pk_m_bytes, pk_x_bytes) = pk.split_at_mut(PK_M_SIZE);
        pk_m_bytes.copy_from_slice(&pk_m.to_bytes());
        pk_x_bytes.copy_from_slice(pk_x.as_bytes());
        Self {
            pk,
            pk_m: pk_m.clone(),
            pk_x: *pk_x,
        }
    }

    /// Returns the 1216-byte serialized key, `pk_m` followed by `pk_x`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ENCAPSULATION_KEY_SIZE] {
        &self.pk
    }

    /// Returns the parsed ML-KEM-768 encapsulation key `pk_m`.
    pub(crate) fn pk_m(&self) -> &ml_kem_768::EncapsulationKey {
        &self.pk_m
    }

    /// Returns the parsed X25519 public key `pk_x`.
    pub(crate) fn pk_x(&self) -> &PublicKey {
        &self.pk_x
    }
}

impl TryFrom<&[u8; ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    type Error = Error;

    /// Parses `pk` and runs the FIPS 203 modulus check on `pk_m`.
    ///
    /// `pk_x` isn't checked, because the X25519 part needs no check: any 32 bytes are a valid
    /// public key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEncapsulationKey`] if `pk_m` fails the FIPS 203 modulus check.
    ///
    /// # Examples
    ///
    /// ```
    /// use x_wing::{DecapsulationKey, EncapsulationKey};
    ///
    /// let dk = DecapsulationKey::generate()?;
    /// let bytes = *dk.encapsulation_key().as_bytes();
    /// let pk = EncapsulationKey::try_from(&bytes)?;
    /// assert_eq!(pk.as_bytes(), &bytes);
    /// # Ok::<(), x_wing::Error>(())
    /// ```
    fn try_from(pk: &[u8; ENCAPSULATION_KEY_SIZE]) -> Result<Self, Error> {
        // Both index ranges lie inside the fixed-size `pk`, so these copies can't fail.
        let pk_m_bytes = Array::from_fn(|i| pk[i]);
        let pk_x_bytes: [u8; PK_X_SIZE] = core::array::from_fn(|i| pk[PK_M_SIZE + i]);

        let pk_m = ml_kem_768::EncapsulationKey::new(&pk_m_bytes)
            .map_err(|_| Error::InvalidEncapsulationKey)?;
        // No check on `pk_x`; the draft defines none for X25519.
        let pk_x = PublicKey::from(pk_x_bytes);
        Ok(Self {
            pk: *pk,
            pk_m,
            pk_x,
        })
    }
}

impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = Error;

    /// Parses `pk` from a slice, as the array version does.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] if `pk` isn't 1216 bytes long.
    /// - [`Error::InvalidEncapsulationKey`] if `pk_m` fails the FIPS 203 modulus check.
    fn try_from(pk: &[u8]) -> Result<Self, Error> {
        let pk: &[u8; ENCAPSULATION_KEY_SIZE] =
            pk.try_into().map_err(|_| Error::InvalidLength {
                expected: ENCAPSULATION_KEY_SIZE,
                actual: pk.len(),
            })?;
        Self::try_from(pk)
    }
}

impl PartialEq for EncapsulationKey {
    /// Compares the serialized keys. The parsed parts follow from them.
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
}

impl Eq for EncapsulationKey {}

impl fmt::Debug for EncapsulationKey {
    /// Writes the serialized key, leaving out the parsed ML-KEM-768 internals.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncapsulationKey")
            .field("pk", &self.pk)
            .finish_non_exhaustive()
    }
}
