//! Encapsulation: Encapsulate and EncapsulateDerand.

use ml_kem::B32;
use rand_core::CryptoRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::{Ciphertext, SharedSecret};
use crate::combiner::combiner;
use crate::{EncapsulationKey, Error};

/// The length of `eseed`, 64 bytes: the ML-KEM-768 message, then `ek_x`.
pub(crate) const ESEED_SIZE: usize = 64;

/// Encapsulates a shared secret to `pk`, taking all randomness from `eseed`.
///
/// This is EncapsulateDerand. The first 32 bytes of `eseed` are the ML-KEM-768 message and the
/// last 32 are `ek_x`. Returns the ciphertext and the shared secret.
pub(crate) fn encapsulate_derand(
    pk: &EncapsulationKey,
    eseed: &[u8; ESEED_SIZE],
) -> (Ciphertext, SharedSecret) {
    // Both index ranges lie inside the fixed-size `eseed`, so these copies can't fail.
    let m = Zeroizing::new(B32::from_fn(|i| eseed[i]));
    let ek_x_bytes = Zeroizing::new(core::array::from_fn::<u8, 32, _>(|i| eseed[32 + i]));
    let ek_x = StaticSecret::from(*ek_x_bytes);

    let (ct_m, ss_m) = pk.pk_m().encapsulate_deterministic(&m);
    let ss_m = Zeroizing::new(ss_m);
    let ct_x = PublicKey::from(&ek_x);
    let ss_x = ek_x.diffie_hellman(pk.pk_x());

    let ss = combiner(
        &ss_m.0,
        ss_x.as_bytes(),
        ct_x.as_bytes(),
        pk.pk_x().as_bytes(),
    );
    (Ciphertext::new(&ct_m, &ct_x), ss)
}

impl EncapsulationKey {
    /// Encapsulates a fresh shared secret to this key, with randomness from the operating system.
    ///
    /// This is Encapsulate. Returns the ciphertext to send to the key's owner and the shared
    /// secret to keep.
    ///
    /// # Errors
    ///
    /// [`Error::Random`] if the operating system's random number generator fails.
    pub fn encapsulate(&self) -> Result<(Ciphertext, SharedSecret), Error> {
        let mut eseed = Zeroizing::new([0u8; ESEED_SIZE]);
        getrandom::fill(&mut *eseed).map_err(|_| Error::Random)?;
        Ok(encapsulate_derand(self, &eseed))
    }

    /// Encapsulates a fresh shared secret to this key, taking the 64-byte `eseed` from `rng`.
    ///
    /// `rng` must be cryptographically secure. Apart from where `eseed` comes from, this is the
    /// same as [`Self::encapsulate`].
    pub fn encapsulate_with_rng<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> (Ciphertext, SharedSecret) {
        let mut eseed = Zeroizing::new([0u8; ESEED_SIZE]);
        rng.fill_bytes(&mut *eseed);
        encapsulate_derand(self, &eseed)
    }

    /// Encapsulates a shared secret to this key, taking all randomness from `eseed`.
    ///
    /// This is EncapsulateDerand. **Derandomized functions are for test vectors only.** Reusing
    /// an `eseed`, or using one that isn't uniformly random, breaks the security of X-Wing.
    ///
    /// # Examples
    ///
    /// ```
    /// use x_wing::DecapsulationKey;
    ///
    /// let dk = DecapsulationKey::from_seed([1; 32]);
    /// let eseed = [2; 64];
    /// let (ct, ss) = dk.encapsulation_key().encapsulate_derand(&eseed);
    /// let (ct_again, ss_again) = dk.encapsulation_key().encapsulate_derand(&eseed);
    /// assert_eq!((ct, ss), (ct_again, ss_again));
    /// ```
    #[cfg(feature = "hazmat")]
    #[must_use]
    pub fn encapsulate_derand(&self, eseed: &[u8; ESEED_SIZE]) -> (Ciphertext, SharedSecret) {
        encapsulate_derand(self, eseed)
    }
}
