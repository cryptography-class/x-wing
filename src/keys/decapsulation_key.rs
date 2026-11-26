//! The X-Wing decapsulation key and its expansion.

use core::fmt;

use ml_kem::ml_kem_768;
use rand_core::CryptoRng;
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::EncapsulationKey;
use crate::{DECAPSULATION_KEY_SIZE, Error};

/// The parts that expandDecapsulationKey derives from `sk`: `(sk_m, sk_x, pk_m, pk_x)`.
type ExpandedKey = (
    ml_kem_768::DecapsulationKey,
    StaticSecret,
    ml_kem_768::EncapsulationKey,
    PublicKey,
);

/// Expands the 32-byte seed `sk` into `(sk_m, sk_x, pk_m, pk_x)`.
///
/// `SHAKE256(sk)` gives 96 bytes. The first 64 are `d ‖ z` for the FIPS 203 ML-KEM-768 key
/// generation, which yields `sk_m` and `pk_m`. The last 32 are `sk_x`, and `pk_x` is `sk_x`
/// times the X25519 base point.
pub(super) fn expand_decapsulation_key(sk: &[u8; DECAPSULATION_KEY_SIZE]) -> ExpandedKey {
    let mut shake = Shake256::default();
    shake.update(sk);
    let mut expanded = shake.finalize_xof();

    // Reading 64 bytes and then 32 gives the same bytes as splitting a 96-byte output.
    let mut seed_m = Zeroizing::new(ml_kem::Seed::default());
    expanded.read(&mut seed_m);
    let mut seed_x = Zeroizing::new([0u8; 32]);
    expanded.read(&mut *seed_x);

    let sk_m = ml_kem_768::DecapsulationKey::from_seed(*seed_m);
    let pk_m = sk_m.encapsulation_key().clone();
    let sk_x = StaticSecret::from(*seed_x);
    let pk_x = PublicKey::from(&sk_x);
    (sk_m, sk_x, pk_m, pk_x)
}

/// An X-Wing decapsulation key: the 32-byte seed `sk`, plus the parts expanded from it.
///
/// Only `sk` is serialized. The expanded parts are kept in memory so that decapsulation doesn't
/// repeat the expansion. Everything secret is erased from memory when the key is dropped. It has
/// no `Clone`, and `Debug` doesn't show any key bytes.
pub struct DecapsulationKey {
    /// The seed that every other part is derived from.
    sk: [u8; DECAPSULATION_KEY_SIZE],
    /// The ML-KEM-768 decapsulation key.
    #[expect(
        dead_code,
        reason = "decapsulate reads it from feature/encapsulation on"
    )]
    sk_m: ml_kem_768::DecapsulationKey,
    /// The X25519 secret key.
    #[expect(
        dead_code,
        reason = "decapsulate reads it from feature/encapsulation on"
    )]
    sk_x: StaticSecret,
    /// The matching encapsulation key.
    pk: EncapsulationKey,
}

impl DecapsulationKey {
    /// Generates a new key pair from the operating system's random number generator.
    ///
    /// This is GenerateKeyPair: a random 32-byte seed, expanded as in [`Self::from_seed`].
    ///
    /// # Errors
    ///
    /// [`Error::Random`] if the operating system's random number generator fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use x_wing::DecapsulationKey;
    ///
    /// let dk = DecapsulationKey::generate()?;
    /// let pk = dk.encapsulation_key();
    /// # Ok::<(), x_wing::Error>(())
    /// ```
    pub fn generate() -> Result<Self, Error> {
        let mut sk = Zeroizing::new([0u8; DECAPSULATION_KEY_SIZE]);
        getrandom::fill(&mut *sk).map_err(|_| Error::Random)?;
        Ok(Self::from_seed(*sk))
    }

    /// Generates a new key pair, taking the 32-byte seed from `rng`.
    ///
    /// `rng` must be cryptographically secure. Apart from where the seed comes from, this is the
    /// same as [`Self::generate`].
    pub fn generate_with_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut sk = Zeroizing::new([0u8; DECAPSULATION_KEY_SIZE]);
        rng.fill_bytes(&mut *sk);
        Self::from_seed(*sk)
    }

    /// Builds the key pair from the 32-byte seed `sk`.
    ///
    /// This is GenerateKeyPairDerand. The same seed always gives the same keys, so it also
    /// restores a key stored with [`Self::as_bytes`]. A fresh seed must come from a
    /// cryptographically secure random number generator.
    ///
    /// # Examples
    ///
    /// ```
    /// use x_wing::DecapsulationKey;
    ///
    /// let dk = DecapsulationKey::generate()?;
    /// let restored = DecapsulationKey::from_seed(*dk.as_bytes());
    /// assert_eq!(restored.encapsulation_key(), dk.encapsulation_key());
    /// # Ok::<(), x_wing::Error>(())
    /// ```
    #[must_use]
    pub fn from_seed(sk: [u8; DECAPSULATION_KEY_SIZE]) -> Self {
        let (sk_m, sk_x, pk_m, pk_x) = expand_decapsulation_key(&sk);
        Self {
            sk,
            sk_m,
            sk_x,
            pk: EncapsulationKey::new(&pk_m, &pk_x),
        }
    }

    /// Returns the 32-byte seed `sk`, the only form in which the key is serialized.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; DECAPSULATION_KEY_SIZE] {
        &self.sk
    }

    /// Returns the matching encapsulation key, to be sent to the other party.
    #[must_use]
    pub fn encapsulation_key(&self) -> &EncapsulationKey {
        &self.pk
    }
}

impl From<[u8; DECAPSULATION_KEY_SIZE]> for DecapsulationKey {
    /// Builds the key pair from the seed `sk`, as [`DecapsulationKey::from_seed`] does.
    fn from(sk: [u8; DECAPSULATION_KEY_SIZE]) -> Self {
        Self::from_seed(sk)
    }
}

impl TryFrom<&[u8]> for DecapsulationKey {
    type Error = Error;

    /// Builds the key pair from a seed given as a slice.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if `sk` isn't 32 bytes long.
    fn try_from(sk: &[u8]) -> Result<Self, Error> {
        let sk = Zeroizing::new(<[u8; DECAPSULATION_KEY_SIZE]>::try_from(sk).map_err(|_| {
            Error::InvalidLength {
                expected: DECAPSULATION_KEY_SIZE,
                actual: sk.len(),
            }
        })?);
        Ok(Self::from_seed(*sk))
    }
}

impl fmt::Debug for DecapsulationKey {
    /// Writes `DecapsulationKey { .. }`, leaving out every key byte.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecapsulationKey").finish_non_exhaustive()
    }
}

impl Drop for DecapsulationKey {
    /// Erases `sk`. `sk_m` and `sk_x` erase themselves when they're dropped.
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

impl ZeroizeOnDrop for DecapsulationKey {}
