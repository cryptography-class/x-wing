use shake::{ExtendableOutput, Shake256, Update, XofReader};
use x_wing_ref::{Decapsulator, KeyExport};
use x25519_dalek::{PublicKey, X25519_BASEPOINT_BYTES, x25519};

use super::decapsulation_key::expand_decapsulation_key;
use super::{DecapsulationKey, EncapsulationKey};
use crate::test_rng::FixedRng;
use crate::test_vectors::{VECTOR_1, VECTORS};
use crate::{DECAPSULATION_KEY_SIZE, ENCAPSULATION_KEY_SIZE, Error};

/// The ML-KEM-768 modulus `q`. Every coefficient of `pk_m` must be below it.
const Q: u16 = 3329;

/// How many random seeds the cross-check against the reference crate tries.
const RANDOM_SEEDS: usize = 32;

/// Returns `pk` with the first 12-bit coefficient of `pk_m` set to `value`. The coefficient's
/// low 8 bits are byte 0 and its high 4 bits are the low nibble of byte 1.
fn with_first_coefficient(
    pk: &[u8; ENCAPSULATION_KEY_SIZE],
    value: u16,
) -> [u8; ENCAPSULATION_KEY_SIZE] {
    let [low, high] = value.to_le_bytes();
    let mut pk = *pk;
    pk[0] = low;
    pk[1] = (pk[1] & 0xf0) | (high & 0x0f);
    pk
}

// ---- expand_decapsulation_key ----

#[test]
fn expand_decapsulation_key_splits_shake256_output_in_draft_order() {
    let sk = VECTOR_1.sk;
    let mut expanded = [0u8; 96];
    let mut shake = Shake256::default();
    shake.update(&sk);
    shake.finalize_xof().read(&mut expanded);

    let (sk_m, sk_x, pk_m, pk_x) = expand_decapsulation_key(&sk);

    assert_eq!(
        sk_m.to_seed().map(|seed| seed.to_vec()),
        Some(expanded[..64].to_vec()),
        "sk_m comes from d = [0..32] and z = [32..64]"
    );
    assert_eq!(sk_x.to_bytes(), expanded[64..96], "sk_x is [64..96]");
    assert_eq!(
        pk_m,
        *sk_m.encapsulation_key(),
        "pk_m is the encapsulation key of sk_m"
    );
    assert_eq!(
        pk_x,
        PublicKey::from(x25519(sk_x.to_bytes(), X25519_BASEPOINT_BYTES)),
        "pk_x is X25519(sk_x, X25519_BASE)"
    );
}

// ---- DecapsulationKey::from_seed ----

#[test]
fn from_seed_gives_appendix_c_pk() {
    for (index, vector) in VECTORS.into_iter().enumerate() {
        let dk = DecapsulationKey::from_seed(vector.seed);
        assert_eq!(
            dk.encapsulation_key().as_bytes(),
            &vector.pk,
            "vector {}",
            index + 1
        );
    }
}

#[test]
fn from_seed_keeps_seed_as_sk() {
    for (index, vector) in VECTORS.into_iter().enumerate() {
        let dk = DecapsulationKey::from_seed(vector.seed);
        assert_eq!(dk.as_bytes(), &vector.sk, "vector {}", index + 1);
    }
}

#[test]
fn from_seed_matches_reference_crate_for_random_seeds() {
    for _ in 0..RANDOM_SEEDS {
        let mut seed = [0u8; DECAPSULATION_KEY_SIZE];
        getrandom::fill(&mut seed).expect("OS random number generator");

        let dk = DecapsulationKey::from_seed(seed);
        let pk_ref = x_wing_ref::DecapsulationKey::from(seed)
            .encapsulation_key()
            .to_bytes();
        assert_eq!(
            dk.encapsulation_key().as_bytes().as_slice(),
            pk_ref.as_slice(),
            "seed {seed:02x?}"
        );
    }
}

// ---- DecapsulationKey::generate ----

#[test]
fn generate_with_rng_uses_rng_bytes_as_seed() {
    let mut rng = FixedRng {
        bytes: VECTOR_1.seed.to_vec(),
    };
    let dk = DecapsulationKey::generate_with_rng(&mut rng);
    assert_eq!(dk.as_bytes(), &VECTOR_1.sk, "vector 1 sk");
    assert_eq!(
        dk.encapsulation_key().as_bytes(),
        &VECTOR_1.pk,
        "vector 1 pk"
    );
}

#[test]
fn generate_gives_distinct_keys() {
    let first = DecapsulationKey::generate().expect("first key");
    let second = DecapsulationKey::generate().expect("second key");
    assert_ne!(first.as_bytes(), second.as_bytes(), "seeds");
    assert_ne!(
        first.encapsulation_key(),
        second.encapsulation_key(),
        "encapsulation keys"
    );
}

// ---- DecapsulationKey::try_from ----

#[test]
fn decapsulation_key_from_slice_rejects_wrong_length() {
    for length in [0, DECAPSULATION_KEY_SIZE - 1, DECAPSULATION_KEY_SIZE + 1] {
        let bytes = vec![0u8; length];
        assert_eq!(
            DecapsulationKey::try_from(bytes.as_slice()).err(),
            Some(Error::InvalidLength {
                expected: DECAPSULATION_KEY_SIZE,
                actual: length,
            }),
            "length {length}"
        );
    }
}

#[test]
fn decapsulation_key_from_slice_accepts_32_bytes() {
    let dk = DecapsulationKey::try_from(VECTOR_1.sk.as_slice()).expect("32 bytes");
    assert_eq!(
        dk.encapsulation_key().as_bytes(),
        &VECTOR_1.pk,
        "vector 1 pk"
    );
}

// ---- DecapsulationKey Debug ----

#[test]
fn decapsulation_key_debug_hides_seed() {
    let dk = DecapsulationKey::from_seed(VECTOR_1.seed);
    assert_eq!(format!("{dk:?}"), "DecapsulationKey { .. }", "Debug output");
}

// ---- EncapsulationKey::try_from ----

#[test]
fn encapsulation_key_round_trips_appendix_c_pk() {
    for (index, vector) in VECTORS.into_iter().enumerate() {
        let pk = EncapsulationKey::try_from(&vector.pk).expect("valid pk");
        assert_eq!(pk.as_bytes(), &vector.pk, "vector {}", index + 1);
    }
}

#[test]
fn encapsulation_key_from_slice_rejects_wrong_length() {
    for length in [ENCAPSULATION_KEY_SIZE - 1, ENCAPSULATION_KEY_SIZE + 1] {
        let bytes = vec![0u8; length];
        assert_eq!(
            EncapsulationKey::try_from(bytes.as_slice()).err(),
            Some(Error::InvalidLength {
                expected: ENCAPSULATION_KEY_SIZE,
                actual: length,
            }),
            "length {length}"
        );
    }
}

#[test]
fn encapsulation_key_rejects_coefficient_equal_to_modulus() {
    let pk = with_first_coefficient(&VECTOR_1.pk, Q);
    assert_eq!(
        EncapsulationKey::try_from(&pk).err(),
        Some(Error::InvalidEncapsulationKey),
        "first coefficient of pk_m set to q"
    );
    assert_eq!(
        EncapsulationKey::try_from(pk.as_slice()).err(),
        Some(Error::InvalidEncapsulationKey),
        "same key as a slice"
    );
}

#[test]
fn encapsulation_key_accepts_coefficient_just_below_modulus() {
    let pk = with_first_coefficient(&VECTOR_1.pk, Q - 1);
    let parsed = EncapsulationKey::try_from(&pk).expect("first coefficient of pk_m set to q - 1");
    assert_eq!(parsed.as_bytes(), &pk, "bytes are kept as given");
}

#[test]
fn encapsulation_key_accepts_all_zero_pk_x() {
    let mut pk = VECTOR_1.pk;
    pk[ENCAPSULATION_KEY_SIZE - 32..].fill(0);
    assert!(
        EncapsulationKey::try_from(&pk).is_ok(),
        "an all-zero pk_x is accepted"
    );
}

// ---- DecapsulationKey::encapsulation_key ----

#[test]
fn encapsulation_key_of_decapsulation_key_equals_parsed_pk() {
    let dk = DecapsulationKey::from_seed(VECTOR_1.seed);
    let parsed = EncapsulationKey::try_from(&VECTOR_1.pk).expect("valid pk");
    assert_eq!(dk.encapsulation_key(), &parsed, "vector 1");
}
