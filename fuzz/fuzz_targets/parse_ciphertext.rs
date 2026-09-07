//! Ciphertext parsing must survive anything a database can hold.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaulted_core::EncryptedValue;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(value) = EncryptedValue::parse(text) {
        // Anything that parses must serialize back to something that parses to
        // the same value: one value, one canonical serialization.
        let reserialized = value.to_string();
        let reparsed = EncryptedValue::parse(&reserialized)
            .expect("a value produced by Display must parse");
        assert_eq!(reparsed, value);

        // Accessors must be consistent with the payload the parser accepted,
        // since they index into it.
        assert_eq!(value.nonce().unwrap().len(), value.algorithm().nonce_len());
        assert_eq!(
            value.payload().len(),
            value.algorithm().nonce_len() + value.plaintext_len() + value.algorithm().tag_len()
        );
    }
});
