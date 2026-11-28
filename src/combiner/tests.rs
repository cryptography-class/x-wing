use sha3::{Digest, Sha3_256};

use super::{XWING_LABEL, combiner};

/// SHA3-256 of 128 zero bytes followed by `XWING_LABEL`, i.e. the combiner on all-zero inputs.
/// Computed independently of the `sha3` crate, with Python's
/// `hashlib.sha3_256(bytes(128) + bytes.fromhex("5c2e2f2f5e5c")).hexdigest()`.
const ZERO_INPUTS_SS: &str = "d363b9b9b060f3efcb3e0d2915df5f3bb8d07c2ba1f542a7d83668cbf2c85af4";

/// Returns four distinct inputs `[ss_m, ss_x, ct_x, pk_x]`, each filled with its own byte, so
/// a swap of any two changes the hash.
fn distinct_inputs() -> [[u8; 32]; 4] {
    [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]]
}

/// Decodes a hex string into 32 bytes. Test helper only; panics on bad input.
fn hex_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "hex string must be 64 characters");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("valid hex");
    }
    out
}

// ---- XWING_LABEL ----

#[test]
fn xwing_label_matches_draft_bytes() {
    assert_eq!(
        XWING_LABEL,
        [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c],
        "hex form"
    );
    assert_eq!(XWING_LABEL, *br"\.//^\", "ASCII form");
}

// ---- combiner ----

#[test]
fn combiner_known_answer_for_zero_inputs() {
    let zero = [0u8; 32];
    assert_eq!(
        combiner(&zero, &zero, &zero, &zero).as_bytes(),
        &hex_32(ZERO_INPUTS_SS),
        "all-zero inputs"
    );
}

#[test]
fn combiner_hashes_inputs_in_draft_order_with_label_last() {
    let [ss_m, ss_x, ct_x, pk_x] = distinct_inputs();

    let mut input = Vec::with_capacity(4 * 32 + XWING_LABEL.len());
    input.extend_from_slice(&ss_m);
    input.extend_from_slice(&ss_x);
    input.extend_from_slice(&ct_x);
    input.extend_from_slice(&pk_x);
    input.extend_from_slice(&[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
    let expected: [u8; 32] = Sha3_256::digest(&input).into();

    assert_eq!(
        combiner(&ss_m, &ss_x, &ct_x, &pk_x).as_bytes(),
        &expected,
        "SHA3-256(ss_m || ss_x || ct_x || pk_x || XWING_LABEL)"
    );
}

#[test]
fn combiner_output_changes_when_any_input_changes() {
    let inputs = distinct_inputs();
    let [ss_m, ss_x, ct_x, pk_x] = inputs;
    let original = combiner(&ss_m, &ss_x, &ct_x, &pk_x);

    for (index, name) in ["ss_m", "ss_x", "ct_x", "pk_x"].into_iter().enumerate() {
        let mut changed = inputs;
        changed[index][0] ^= 0x01;
        let [ss_m, ss_x, ct_x, pk_x] = changed;
        assert_ne!(
            combiner(&ss_m, &ss_x, &ct_x, &pk_x),
            original,
            "flipping a bit of {name} didn't change the output"
        );
    }
}
