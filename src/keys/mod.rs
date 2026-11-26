//! X-Wing keys.
//!
//! A decapsulation key is stored and serialized as its 32-byte seed `sk` and nothing else.
//! expandDecapsulationKey derives `sk_m`, `sk_x`, `pk_m` and `pk_x` from it once, when the key
//! is built, and the key keeps them in memory so that decapsulation doesn't repeat the
//! expansion. The expanded parts are never serialized.
//!
//! An encapsulation key runs the FIPS 203 modulus check on `pk_m` when it's parsed, and can't be
//! built any other way from outside the crate. Encapsulation can then rely on a checked key and
//! has no error case of its own for it. `pk_x` isn't checked, because X25519 needs no check.
//!
//! - `decapsulation_key` holds expandDecapsulationKey and [`DecapsulationKey`], which covers
//!   GenerateKeyPair and GenerateKeyPairDerand.
//! - `encapsulation_key` holds [`EncapsulationKey`] and its parsing.
//!
//! Keys are generated with [`DecapsulationKey::generate`] and rebuilt from a stored seed with
//! [`DecapsulationKey::from_seed`]. A received public key is parsed with
//! [`EncapsulationKey::try_from`].

mod decapsulation_key;
mod encapsulation_key;

pub use decapsulation_key::DecapsulationKey;
pub use encapsulation_key::EncapsulationKey;

#[cfg(test)]
mod tests;
