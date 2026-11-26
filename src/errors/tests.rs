use super::Error;

/// Returns one value of every `Error` variant, paired with its name for assertion messages.
fn all_variants() -> [(&'static str, Error); 3] {
    [
        (
            "InvalidLength",
            Error::InvalidLength {
                expected: 32,
                actual: 31,
            },
        ),
        ("InvalidEncapsulationKey", Error::InvalidEncapsulationKey),
        ("Random", Error::Random),
    ]
}

// ---- Display ----

#[test]
fn error_messages_match_expected_text() {
    let expected = [
        "invalid length: expected 32 bytes, got 31",
        "encapsulation key fails the FIPS 203 modulus check",
        "random number generator failed",
    ];
    for ((name, error), message) in all_variants().into_iter().zip(expected) {
        assert_eq!(error.to_string(), message, "{name}");
    }
}

#[test]
fn error_messages_are_lowercase_without_trailing_period() {
    for (name, error) in all_variants() {
        let message = error.to_string();
        assert!(!message.is_empty(), "{name}: empty message");
        assert!(
            message.starts_with(|c: char| c.is_ascii_lowercase()),
            "{name}: message doesn't start lowercase: {message:?}"
        );
        assert!(
            !message.ends_with('.'),
            "{name}: message ends with a period: {message:?}"
        );
    }
}
