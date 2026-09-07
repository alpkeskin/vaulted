//! Keyring documents. A keyring is not usually attacker-controlled, but it is
//! a file, and files get swapped, truncated and half-written.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaulted_core::{KeyProvider, LocalKeyProvider};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(provider) = LocalKeyProvider::from_json(text) {
        // A keyring that loads must be internally consistent: the primary key
        // has to be one of the keys it holds, or later lookups would fail in
        // ways that look like corruption rather than misconfiguration.
        let primary = provider.primary_key_id().expect("a loaded keyring has a primary");
        assert!(
            provider.key_ids().expect("enumerable").contains(&primary),
            "primary key is not in the keyring"
        );

        // Round-tripping must preserve it exactly.
        let json = provider.to_json().expect("serializable");
        let restored = LocalKeyProvider::from_json(&json).expect("round trip");
        assert_eq!(restored.primary_key_id().unwrap(), primary);
    }
});
