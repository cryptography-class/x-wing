//! Decapsulation: Decapsulate.

use ml_kem::Decapsulate;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

use super::{Ciphertext, SharedSecret};
use crate::DecapsulationKey;
use crate::combiner::combiner;

impl DecapsulationKey {
    /// Recovers the shared secret from the ciphertext `ct`.
    ///
    /// This is Decapsulate. It can't fail: a tampered or wrong `ct` gives an unrelated secret
    /// instead of an error, through ML-KEM-768's implicit rejection.
    #[must_use]
    pub fn decapsulate(&self, ct: &Ciphertext) -> SharedSecret {
        let ct_x = ct.ct_x();
        let ss_m = Zeroizing::new(self.sk_m().decapsulate(&ct.ct_m()));
        // No all-zero check on `ss_x`; the draft defines none for X25519.
        let ss_x = self.sk_x().diffie_hellman(&PublicKey::from(ct_x));
        combiner(
            &ss_m.0,
            ss_x.as_bytes(),
            &ct_x,
            self.encapsulation_key().pk_x().as_bytes(),
        )
    }
}
