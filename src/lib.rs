//! The X-Wing hybrid key encapsulation mechanism (KEM), as specified in
//! [draft-connolly-cfrg-xwing-kem-11](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html).
//!
//! X-Wing combines ML-KEM-768 (FIPS 203) with X25519 (RFC 7748) and hashes both
//! shared secrets with SHA3-256. X-Wing is secure if SHA3 is secure, and at least one
//! of X25519 or ML-KEM-768 is secure.
//!
//! This crate implements the X-Wing construction itself. The primitives come from
//! the `ml-kem`, `x25519-dalek`, `sha3` and `shake` crates.
//!
//! # Naming
//!
//! Values are named as in the draft, in lowercase:
//!
//! | Name | Meaning       |
//! |------|---------------|
//! | `ss` | shared secret |
//! | `ct` | ciphertext    |
//! | `ek` | ephemeral key |
//! | `pk` | public key    |
//! | `sk` | secret key    |
//!
//! The postfix `_m` marks an ML-KEM-768 value and `_x` an X25519 value, so `ss_m` is
//! ML-KEM's shared secret and `ct_x` is X25519's part of the ciphertext. `ek` means
//! the ephemeral X25519 secret (`ek_x`), not the FIPS 203 encapsulation key, which
//! is `pk_m` here.

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "encapsulate and decapsulate use it from feature/encapsulation on"
    )
)]
mod combiner;
mod errors;

pub use errors::Error;

/// The decapsulation key length, 32 bytes: the seed that every other key part is derived
/// from.
pub const DECAPSULATION_KEY_SIZE: usize = 32;

/// The encapsulation key length, 1216 bytes: `pk_m` (1184) followed by `pk_x` (32).
pub const ENCAPSULATION_KEY_SIZE: usize = 1216;

/// The ciphertext length, 1120 bytes: `ct_m` (1088) followed by `ct_x` (32).
pub const CIPHERTEXT_SIZE: usize = 1120;

/// The shared secret length, 32 bytes: the SHA3-256 output of the combiner.
pub const SHARED_SECRET_SIZE: usize = 32;

#[cfg(test)]
mod tests;
