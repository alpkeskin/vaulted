//! Blind index parsing. Indexes come back from the database as strings, so
//! this parser is fed by the same untrusted source as the ciphertext parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vaulted_core::BlindIndex;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(index) = BlindIndex::parse(text) {
        // Length bounds are a correctness property: a short index means silent
        // collisions, a long one means the parser invented bytes.
        let len = index.as_bytes().len();
        assert!((8..=32).contains(&len), "accepted a {len}-byte index");
        assert_eq!(index.to_hex().len(), len * 2);

        let reparsed = BlindIndex::parse(&index.to_string()).expect("Display must round trip");
        assert!(reparsed.matches(&index));
    }
});
