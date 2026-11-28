//! Cross-checks this crate against the RustCrypto `x-wing` crate on random inputs.

use x_wing::{CIPHERTEXT_SIZE, Ciphertext, DecapsulationKey, EncapsulationKey};
use x_wing_ref::{Decapsulate as _, Decapsulator as _, KeyExport as _};

/// How many random inputs each test tries.
const ROUNDS: usize = 16;

/// Returns `N` bytes from the operating system's random number generator. Test helper only;
/// panics if the generator fails.
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("OS random number generator");
    bytes
}

// ---- EncapsulationKey::encapsulate_derand ----

#[cfg(feature = "hazmat")]
#[test]
fn encapsulate_derand_matches_reference_crate() {
    for round in 0..ROUNDS {
        let seed = random();
        let eseed = random::<64>();

        let (ct, ss) = DecapsulationKey::from_seed(seed)
            .encapsulation_key()
            .encapsulate_derand(&eseed);
        let (ct_ref, ss_ref) = x_wing_ref::DecapsulationKey::from(seed)
            .encapsulation_key()
            .encapsulate_deterministic(&eseed.into());

        assert_eq!(
            ct.as_bytes().as_slice(),
            ct_ref.as_slice(),
            "round {round} ct"
        );
        assert_eq!(
            ss.as_bytes().as_slice(),
            ss_ref.as_slice(),
            "round {round} ss"
        );
    }
}

// ---- EncapsulationKey::encapsulate ----

#[test]
fn reference_crate_decapsulates_our_ciphertexts() {
    for round in 0..ROUNDS {
        let dk_ref = x_wing_ref::DecapsulationKey::from(random::<32>());
        let pk_bytes = dk_ref.encapsulation_key().to_bytes();
        let pk = EncapsulationKey::try_from(pk_bytes.as_slice()).expect("reference pk is valid");

        let (ct, ss) = pk.encapsulate().expect("encapsulation");
        let ss_ref = dk_ref.decapsulate(&x_wing_ref::Ciphertext::from(*ct.as_bytes()));

        assert_eq!(ss.as_bytes().as_slice(), ss_ref.as_slice(), "round {round}");
    }
}

// ---- DecapsulationKey::decapsulate ----

#[test]
fn we_decapsulate_reference_crate_ciphertexts() {
    for round in 0..ROUNDS {
        let dk = DecapsulationKey::from_seed(random());
        let pk_ref =
            x_wing_ref::EncapsulationKey::try_from(dk.encapsulation_key().as_bytes().as_slice())
                .expect("our pk is valid");

        let (ct_ref, ss_ref) = pk_ref.encapsulate_deterministic(&random::<64>().into());
        let ct_bytes: [u8; CIPHERTEXT_SIZE] = ct_ref.into();
        let ss = dk.decapsulate(&Ciphertext::from(ct_bytes));

        assert_eq!(ss.as_bytes().as_slice(), ss_ref.as_slice(), "round {round}");
    }
}

#[test]
fn random_ciphertexts_decapsulate_to_reference_crate_secret() {
    for round in 0..ROUNDS {
        let seed = random();
        let ct_bytes = random::<CIPHERTEXT_SIZE>();

        let ss = DecapsulationKey::from_seed(seed).decapsulate(&Ciphertext::from(ct_bytes));
        let ss_ref = x_wing_ref::DecapsulationKey::from(seed)
            .decapsulate(&x_wing_ref::Ciphertext::from(ct_bytes));

        assert_eq!(ss.as_bytes().as_slice(), ss_ref.as_slice(), "round {round}");
    }
}
