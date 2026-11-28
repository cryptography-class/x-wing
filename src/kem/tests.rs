use ml_kem::B32;
use x_wing_ref::Decapsulate as _;
use x25519_dalek::{PublicKey, X25519_BASEPOINT_BYTES, x25519};

use super::encapsulate::encapsulate_derand;
use super::{Ciphertext, SharedSecret};
use crate::test_rng::FixedRng;
use crate::test_vectors::{TestVector, VECTOR_1, VECTORS};
use crate::{CIPHERTEXT_SIZE, DecapsulationKey, EncapsulationKey, Error};

/// The length of `ct_m`, 1088 bytes. It comes first in `ct`.
const CT_M_SIZE: usize = 1088;

/// How many random key pairs the round-trip test tries.
const ROUNDS: usize = 16;

/// Parses the Appendix C `pk` of `vector`. Test helper only; panics if it's rejected.
fn pk_of(vector: &TestVector) -> EncapsulationKey {
    EncapsulationKey::try_from(&vector.pk).expect("Appendix C pk is valid")
}

// ---- Ciphertext ----

#[test]
fn ciphertext_from_slice_rejects_wrong_length() {
    for length in [0, CIPHERTEXT_SIZE - 1, CIPHERTEXT_SIZE + 1] {
        let bytes = vec![0u8; length];
        assert_eq!(
            Ciphertext::try_from(bytes.as_slice()).err(),
            Some(Error::InvalidLength {
                expected: CIPHERTEXT_SIZE,
                actual: length,
            }),
            "length {length}"
        );
    }
}

#[test]
fn ciphertext_from_slice_keeps_bytes() {
    let ct = Ciphertext::try_from(VECTOR_1.ct.as_slice()).expect("1120 bytes");
    assert_eq!(ct.as_bytes(), &VECTOR_1.ct, "vector 1 ct");
}

#[test]
fn ciphertext_splits_into_ct_m_then_ct_x() {
    let ct = Ciphertext::from(VECTOR_1.ct);
    assert_eq!(
        ct.ct_m().as_slice(),
        &VECTOR_1.ct[..CT_M_SIZE],
        "ct_m is the first 1088 bytes"
    );
    assert_eq!(
        ct.ct_x().as_slice(),
        &VECTOR_1.ct[CT_M_SIZE..],
        "ct_x is the last 32 bytes"
    );
}

#[test]
fn ciphertext_new_joins_ct_m_and_ct_x() {
    let ct = Ciphertext::from(VECTOR_1.ct);
    let joined = Ciphertext::new(&ct.ct_m(), &PublicKey::from(ct.ct_x()));
    assert_eq!(joined, ct, "vector 1 ct split and joined again");
}

// ---- SharedSecret ----

#[test]
fn shared_secret_debug_hides_bytes() {
    let ss = SharedSecret::new(VECTOR_1.ss);
    assert_eq!(format!("{ss:?}"), "SharedSecret { .. }", "Debug output");
}

#[test]
fn shared_secret_eq_compares_bytes() {
    let mut flipped = VECTOR_1.ss;
    flipped[31] ^= 0x01;
    assert_eq!(
        SharedSecret::new(VECTOR_1.ss),
        SharedSecret::new(VECTOR_1.ss),
        "same bytes"
    );
    assert_ne!(
        SharedSecret::new(VECTOR_1.ss),
        SharedSecret::new(flipped),
        "last bit flipped"
    );
}

// ---- encapsulate_derand ----

#[test]
fn encapsulate_derand_gives_appendix_c_ct_and_ss() {
    for (index, vector) in VECTORS.into_iter().enumerate() {
        let (ct, ss) = encapsulate_derand(&pk_of(vector), &vector.eseed);
        assert_eq!(ct.as_bytes(), &vector.ct, "vector {} ct", index + 1);
        assert_eq!(ss.as_bytes(), &vector.ss, "vector {} ss", index + 1);
    }
}

#[test]
fn encapsulate_derand_splits_eseed_in_draft_order() {
    let pk = pk_of(&VECTOR_1);
    let (ct, _) = encapsulate_derand(&pk, &VECTOR_1.eseed);

    let m = B32::try_from(&VECTOR_1.eseed[..32]).expect("32 bytes");
    let (ct_m, _) = pk.pk_m().encapsulate_deterministic(&m);
    let ek_x: [u8; 32] = VECTOR_1.eseed[32..].try_into().expect("32 bytes");

    assert_eq!(
        &ct.as_bytes()[..CT_M_SIZE],
        ct_m.as_slice(),
        "ct_m comes from the message eseed[0..32]"
    );
    assert_eq!(
        &ct.as_bytes()[CT_M_SIZE..],
        x25519(ek_x, X25519_BASEPOINT_BYTES).as_slice(),
        "ct_x is X25519(ek_x, X25519_BASE) with ek_x = eseed[32..64]"
    );
}

#[cfg(feature = "hazmat")]
#[test]
fn encapsulate_derand_method_gives_appendix_c_ct_and_ss() {
    for (index, vector) in VECTORS.into_iter().enumerate() {
        let (ct, ss) = pk_of(vector).encapsulate_derand(&vector.eseed);
        assert_eq!(ct.as_bytes(), &vector.ct, "vector {} ct", index + 1);
        assert_eq!(ss.as_bytes(), &vector.ss, "vector {} ss", index + 1);
    }
}

// ---- EncapsulationKey::encapsulate_with_rng ----

#[test]
fn encapsulate_with_rng_uses_rng_bytes_as_eseed() {
    let mut rng = FixedRng {
        bytes: VECTOR_1.eseed.to_vec(),
    };
    let (ct, ss) = pk_of(&VECTOR_1).encapsulate_with_rng(&mut rng);
    assert_eq!(ct.as_bytes(), &VECTOR_1.ct, "vector 1 ct");
    assert_eq!(ss.as_bytes(), &VECTOR_1.ss, "vector 1 ss");
    assert!(rng.bytes.is_empty(), "exactly 64 bytes are drawn");
}

// ---- EncapsulationKey::encapsulate ----

#[test]
fn encapsulate_gives_distinct_ciphertexts() {
    let pk = pk_of(&VECTOR_1);
    let (first_ct, first_ss) = pk.encapsulate().expect("first encapsulation");
    let (second_ct, second_ss) = pk.encapsulate().expect("second encapsulation");
    assert_ne!(first_ct, second_ct, "ciphertexts");
    assert_ne!(first_ss, second_ss, "shared secrets");
}

#[test]
fn encapsulate_then_decapsulate_gives_same_secret() {
    for round in 0..ROUNDS {
        let dk = DecapsulationKey::generate().expect("key generation");
        let (ct, ss) = dk.encapsulation_key().encapsulate().expect("encapsulation");
        assert_eq!(dk.decapsulate(&ct), ss, "round {round}");
    }
}

// ---- DecapsulationKey::decapsulate ----

#[test]
fn decapsulate_gives_appendix_c_ss() {
    for (index, vector) in VECTORS.into_iter().enumerate() {
        let dk = DecapsulationKey::from_seed(vector.seed);
        let ss = dk.decapsulate(&Ciphertext::from(vector.ct));
        assert_eq!(ss.as_bytes(), &vector.ss, "vector {}", index + 1);
    }
}

#[test]
fn decapsulate_tampered_ciphertext_gives_different_secret() {
    let dk = DecapsulationKey::from_seed(VECTOR_1.seed);
    for (byte, part) in [(0, "ct_m"), (CT_M_SIZE, "ct_x")] {
        let mut tampered = VECTOR_1.ct;
        tampered[byte] ^= 0x01;
        let ss = dk.decapsulate(&Ciphertext::from(tampered));
        assert_ne!(
            ss.as_bytes(),
            &VECTOR_1.ss,
            "flipping a bit of {part} didn't change the secret"
        );
    }
}

#[test]
fn decapsulate_accepts_all_zero_ct_x() {
    let mut ct = VECTOR_1.ct;
    ct[CT_M_SIZE..].fill(0);

    let ss = DecapsulationKey::from_seed(VECTOR_1.seed).decapsulate(&Ciphertext::from(ct));
    let ss_ref = x_wing_ref::DecapsulationKey::from(VECTOR_1.seed)
        .decapsulate(&x_wing_ref::Ciphertext::from(ct));
    assert_eq!(
        ss.as_bytes().as_slice(),
        ss_ref.as_slice(),
        "all-zero ct_x gives the reference crate's secret"
    );
}
