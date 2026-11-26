use ml_kem::array::typenum::Unsigned;
use ml_kem::{KeySizeUser, ml_kem_768};
use x25519_dalek::X25519_BASEPOINT_BYTES;

use super::{CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE, ENCAPSULATION_KEY_SIZE, SHARED_SECRET_SIZE};

/// Returns the length of an ML-KEM-768 encapsulation key (`pk_m`), as the `ml-kem` crate encodes it.
fn pk_m_size() -> usize {
    <ml_kem_768::EncapsulationKey as KeySizeUser>::KeySize::USIZE
}

/// Returns the length of an ML-KEM-768 ciphertext (`ct_m`), as the `ml-kem` crate encodes it.
fn ct_m_size() -> usize {
    size_of::<ml_kem_768::Ciphertext>()
}

/// Returns the length of an X25519 public key, which is also the length of `ct_x`.
fn x25519_size() -> usize {
    X25519_BASEPOINT_BYTES.len()
}

// ---- size constants ----

#[test]
fn sizes_match_reference_crate() {
    assert_eq!(
        ENCAPSULATION_KEY_SIZE,
        x_wing_ref::ENCAPSULATION_KEY_SIZE,
        "ENCAPSULATION_KEY_SIZE"
    );
    assert_eq!(
        DECAPSULATION_KEY_SIZE,
        x_wing_ref::DECAPSULATION_KEY_SIZE,
        "DECAPSULATION_KEY_SIZE"
    );
    assert_eq!(
        CIPHERTEXT_SIZE,
        x_wing_ref::CIPHERTEXT_SIZE,
        "CIPHERTEXT_SIZE"
    );
}

#[test]
fn sizes_are_sum_of_components() {
    assert_eq!(
        ENCAPSULATION_KEY_SIZE,
        pk_m_size() + x25519_size(),
        "ENCAPSULATION_KEY_SIZE is pk_m followed by pk_x"
    );
    assert_eq!(
        CIPHERTEXT_SIZE,
        ct_m_size() + x25519_size(),
        "CIPHERTEXT_SIZE is ct_m followed by ct_x"
    );
}

#[test]
fn sizes_match_draft() {
    assert_eq!(DECAPSULATION_KEY_SIZE, 32, "DECAPSULATION_KEY_SIZE");
    assert_eq!(ENCAPSULATION_KEY_SIZE, 1216, "ENCAPSULATION_KEY_SIZE");
    assert_eq!(CIPHERTEXT_SIZE, 1120, "CIPHERTEXT_SIZE");
    assert_eq!(SHARED_SECRET_SIZE, 32, "SHARED_SECRET_SIZE");
}
