//! Decryption of attacker-supplied values.
//!
//! The vault holds keys the fuzzer has never seen, so no input should ever
//! decrypt. If one does, forging a ciphertext is possible and the failure is
//! about as serious as they come.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use vaulted_core::{
    BlindIndexConfig, FieldConfig, LocalKeyProvider, Normalization, Vault,
};

fn vault() -> &'static Vault {
    // Built once: key generation per input would dominate the run.
    static VAULT: OnceLock<Vault> = OnceLock::new();
    VAULT.get_or_init(|| {
        Vault::builder()
            .key_provider(LocalKeyProvider::generate().expect("key generation"))
            .field(
                FieldConfig::new("users.email")
                    .expect("valid field name")
                    .with_normalization(Normalization::Email)
                    .with_blind_index(BlindIndexConfig::new()),
            )
            .build()
            .expect("vault")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let vault = vault();

    if vault.decrypt_str("users.email", text).is_ok() {
        panic!("a value not produced by this vault decrypted successfully");
    }

    // Blind indexing takes arbitrary text straight from user input.
    let _ = vault.blind_index("users.email", text);
});
