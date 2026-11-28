//! X-Wing encapsulation and decapsulation.
//!
//! Encapsulation has one code path. [`EncapsulationKey::encapsulate`] and
//! [`EncapsulationKey::encapsulate_with_rng`] draw a 64-byte `eseed` and pass it to
//! EncapsulateDerand, so the test vectors cover the randomized functions too.
//! EncapsulateDerand is public only with the `hazmat` feature.
//! **Derandomized functions are for test vectors only.**
//!
//! Decapsulation never fails on a ciphertext of the right length. ML-KEM-768 answers a tampered
//! `ct_m` with an unrelated secret (implicit rejection), and X25519 accepts any `ct_x`.
//!
//! - `ciphertext` holds [`Ciphertext`].
//! - `shared_secret` holds [`SharedSecret`].
//! - `encapsulate` holds EncapsulateDerand and the encapsulation methods on
//!   [`EncapsulationKey`].
//! - `decapsulate` holds [`DecapsulationKey::decapsulate`].
//!
//! [`EncapsulationKey`]: crate::EncapsulationKey
//! [`EncapsulationKey::encapsulate`]: crate::EncapsulationKey::encapsulate
//! [`EncapsulationKey::encapsulate_with_rng`]: crate::EncapsulationKey::encapsulate_with_rng
//! [`DecapsulationKey::decapsulate`]: crate::DecapsulationKey::decapsulate

mod ciphertext;
mod decapsulate;
mod encapsulate;
mod shared_secret;

pub use ciphertext::Ciphertext;
pub use shared_secret::SharedSecret;

#[cfg(test)]
mod tests;
