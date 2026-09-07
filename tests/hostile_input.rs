//! Parsing is the attack surface.
//!
//! The threat model says the attacker holds the database, so every serialized
//! value handed to Vaulted may have been written by them. These tests take
//! valid values and corrupt them in every way that is cheap to generate,
//! asserting one thing above all: **no input causes a panic**. A parser that
//! panics on hostile input turns a database dump into a denial of service.
//!
//! The seeds are fixed, so a failure reported here reproduces exactly. For
//! coverage-guided fuzzing over the same entry points, see `fuzz/`.

mod support;

use support::{test_vault, Rng};
use vaulted_core::{BlindIndex, EncryptedValue, Error, LocalKeyProvider};

/// Every entry point that consumes attacker-controlled text.
fn feed(input: &str) {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());

    // Parsing must either succeed or return an error; it must never panic.
    if let Ok(value) = EncryptedValue::parse(input) {
        // A parsed value must still refuse to decrypt under keys that did not
        // produce it. Forging a structurally valid value is easy; forging one
        // that authenticates is the part that must be impossible.
        assert!(matches!(
            vault.decrypt("users.email", &value),
            Err(Error::AuthenticationFailed) | Err(Error::UnknownKey { .. })
        ));
        // Re-serializing a parsed value must round trip.
        assert_eq!(EncryptedValue::parse(&value.to_string()).unwrap(), value);
    }

    let _ = vault.decrypt_str("users.email", input);
    let _ = BlindIndex::parse(input);
    let _ = vault.blind_index("users.email", input);
}

#[test]
fn fixed_hostile_strings_are_handled() {
    let cases = [
        "",
        ":",
        ":::::::::",
        "vlt",
        "vlt:",
        "vlt:v1",
        "vlt:v1:",
        "vlt:v1::",
        "vlt:v1:::",
        "vlt:v1:key:aes256gcm:",
        "vlt:v0:key:aes256gcm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "vlt:v4294967295:key:aes256gcm:AAAA",
        "vlt:v99999999999999999999:key:aes256gcm:AAAA",
        "vlt:v-1:key:aes256gcm:AAAA",
        "vlt:v1:key:aes256gcm:====",
        "vlt:v1:key:aes256gcm:AAAA/AAA+AAA", // standard base64, not URL-safe
        "vlt:v1:key:aes256gcm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "vlt:v1:../../etc/passwd:aes256gcm:AAAA",
        "vlt:v1:key\u{0}:aes256gcm:AAAA",
        "vlt:v1:key:aes256gcm\u{0}:AAAA",
        "VLT:V1:KEY:AES256GCM:AAAA",
        "bi:v1:key-0001:00",
        "bi:v1:key-0001:",
        "bi:v1::0011223344556677",
        "\u{feff}vlt:v1:key:aes256gcm:AAAA",
        "vlt:v1:key:aes256gcm:AAAA\n",
        "vlt:v1:key:aes256gcm:AAAA ",
        "🔐",
        "vlt:v1:key:aes256gcm:🔐",
    ];

    for case in cases {
        feed(case);
    }
}

#[test]
fn very_long_inputs_are_handled() {
    // Length alone must not be able to knock the parser over.
    feed(&"A".repeat(1_000_000));
    feed(&format!(
        "vlt:v1:key-0001:aes256gcm:{}",
        "A".repeat(1_000_000)
    ));
    feed(&format!("vlt:v1:{}:aes256gcm:AAAA", "k".repeat(100_000)));
    feed(&"vlt:".repeat(100_000));
    feed(&format!("bi:v1:key-0001:{}", "ab".repeat(500_000)));
}

#[test]
fn byte_level_mutations_of_valid_values_never_panic() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let valid = vault
        .encrypt("users.email", "alp@example.com")
        .unwrap()
        .to_string();

    let mut rng = Rng::new(0x5EED_1234);
    for _ in 0..2_000 {
        let mut bytes = valid.clone().into_bytes();
        // One to four random single-byte edits.
        for _ in 0..=rng.below(4) {
            match rng.below(3) {
                0 if !bytes.is_empty() => {
                    let at = rng.below(bytes.len());
                    bytes[at] = rng.byte();
                }
                1 if !bytes.is_empty() => {
                    let at = rng.below(bytes.len());
                    bytes.remove(at);
                }
                _ => {
                    let at = rng.below(bytes.len() + 1);
                    bytes.insert(at, rng.byte());
                }
            }
        }
        // Mutations that leave valid UTF-8 go through the string API; the rest
        // exercise the lossy path, which is what a text column would produce.
        match String::from_utf8(bytes) {
            Ok(mutated) => feed(&mutated),
            Err(err) => feed(&String::from_utf8_lossy(err.as_bytes())),
        }
    }
}

#[test]
fn a_mutated_value_never_decrypts() {
    // Stronger than "does not panic": no single-byte edit to a valid value can
    // produce something that decrypts, unless it edits nothing meaningful.
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let value = vault.encrypt("users.email", "alp@example.com").unwrap();
    let serialized = value.to_string();

    for at in 0..serialized.len() {
        for delta in [1u8, 0x20, 0x80] {
            let mut bytes = serialized.clone().into_bytes();
            bytes[at] ^= delta;
            let Ok(mutated) = String::from_utf8(bytes) else {
                continue;
            };
            if mutated == serialized {
                continue;
            }
            assert!(
                vault.decrypt_str("users.email", &mutated).is_err(),
                "byte {at} of the serialized value was not authenticated"
            );
        }
    }
}

#[test]
fn random_garbage_is_rejected_cleanly() {
    let mut rng = Rng::new(0xC0FF_EE01);
    for _ in 0..2_000 {
        let len = rng.below(96);
        let bytes = rng.bytes(len);
        feed(&String::from_utf8_lossy(&bytes));

        // Also feed garbage that keeps the shape of a real value, so the
        // interesting branches past prefix validation get exercised.
        let shaped = format!(
            "vlt:v{}:{}:{}:{}",
            rng.below(4),
            String::from_utf8_lossy(&rng.bytes_below(8)),
            ["aes256gcm", "xchacha20poly1305", "rot13", ""][rng.below(4)],
            String::from_utf8_lossy(&rng.bytes_below(64)),
        );
        feed(&shaped);
    }
}

#[test]
fn hostile_keyring_documents_are_rejected() {
    // The keyring is a second parser fed by a file an attacker might swap.
    let cases = [
        "",
        "{",
        "null",
        "[]",
        "\"vaulted-keyring\"",
        r#"{"format":"vaulted-keyring","version":1,"primary_key_id":"","keys":[]}"#,
        r#"{"format":"vaulted-keyring","version":1,"primary_key_id":"k","keys":[{"id":"k","encryption_key":"!!","blind_index_key":"!!"}]}"#,
        r#"{"format":"vaulted-keyring","version":1,"primary_key_id":"k","keys":[{"id":"k:x","encryption_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","blind_index_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#,
    ];
    for case in cases {
        assert!(
            LocalKeyProvider::from_json(case).is_err(),
            "{case} should be rejected"
        );
    }
}
