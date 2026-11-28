//! The X-Wing combiner.
//!
//! The combiner hashes both shared secrets together with the X25519 ciphertext `ct_x` and
//! public key `pk_x`. It leaves out `ct_m` and `pk_m`. That's safe only because of the
//! Fujisaki-Okamoto transform inside ML-KEM-768, so this combiner mustn't be reused with
//! another KEM.
//!
//! `XWING_LABEL` goes last. All 134 bytes of input fit in one SHA3-256 block, so its
//! position doesn't change the cost.

use sha3::{Digest, Sha3_256};

use crate::SharedSecret;

/// The X-Wing label, the 6 ASCII bytes `\.//^\` (`5c2e2f2f5e5c` in hex).
pub(crate) const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// Derives the X-Wing shared secret from `ss_m` and `ss_x`.
///
/// Returns `SHA3-256(ss_m ‖ ss_x ‖ ct_x ‖ pk_x ‖ XWING_LABEL)`, which erases itself when it's
/// dropped.
pub(crate) fn combiner(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> SharedSecret {
    // `sha3` is built with its `zeroize` feature, so the hasher erases its state, which has
    // absorbed `ss_m` and `ss_x`, when it's dropped.
    let mut hasher = Sha3_256::new();
    hasher.update(ss_m);
    hasher.update(ss_x);
    hasher.update(ct_x);
    hasher.update(pk_x);
    hasher.update(XWING_LABEL);
    SharedSecret::new(hasher.finalize().into())
}

#[cfg(test)]
mod tests;
