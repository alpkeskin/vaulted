//! Key rotation, from both ends: encryption keys and blind index keys.

mod support;

use support::test_vault;
use vaulted_core::{
    BlindIndexConfig, Error, FieldConfig, KeyId, KeyProvider, KeyPurpose, Keyring,
    LocalKeyProvider, Normalization, Vault,
};

#[test]
fn old_values_stay_readable_while_new_values_use_the_new_key() {
    // The state a deployment sits in for as long as a backfill takes: two key
    // versions live at once, and nothing is broken in the meantime.
    let provider = std::sync::Arc::new(LocalKeyProvider::generate().unwrap());
    let vault = Vault::builder()
        .key_provider_arc(provider.clone())
        .field(
            FieldConfig::new("users.email")
                .unwrap()
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .build()
        .unwrap();

    let old_value = vault.encrypt("users.email", "alp@example.com").unwrap();
    assert_eq!(old_value.key_id().as_str(), "key-0001");

    let key_0002 = KeyId::new("key-0002").unwrap();
    provider.add_generated_key(key_0002.clone(), true).unwrap();

    let new_value = vault.encrypt("users.email", "alp@example.com").unwrap();
    assert_eq!(new_value.key_id(), &key_0002);

    // Both decrypt, because each names the key it needs.
    assert_eq!(
        &*vault.decrypt("users.email", &old_value).unwrap(),
        "alp@example.com"
    );
    assert_eq!(
        &*vault.decrypt("users.email", &new_value).unwrap(),
        "alp@example.com"
    );
    assert_eq!(provider.key_ids().unwrap().len(), 2);
}

#[test]
fn rotate_re_encrypts_and_reports_whether_anything_changed() {
    let provider = std::sync::Arc::new(LocalKeyProvider::generate().unwrap());
    let vault = Vault::builder()
        .key_provider_arc(provider.clone())
        .field(
            FieldConfig::new("users.email")
                .unwrap()
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .build()
        .unwrap();

    let original = vault.encrypt("users.email", "alp@example.com").unwrap();
    assert!(!vault.needs_rotation("users.email", &original).unwrap());

    // Already current: rotating is a no-op, so a backfill job can skip the row.
    let noop = vault.rotate("users.email", &original).unwrap();
    assert!(!noop.changed);

    provider
        .add_generated_key(KeyId::new("key-0002").unwrap(), true)
        .unwrap();
    assert!(vault.needs_rotation("users.email", &original).unwrap());

    let rotated = vault.rotate("users.email", &original).unwrap();
    assert!(rotated.changed);
    assert_eq!(rotated.ciphertext.key_id().as_str(), "key-0002");
    assert_eq!(
        &*vault.decrypt("users.email", &rotated.ciphertext).unwrap(),
        "alp@example.com"
    );

    // The old ciphertext is untouched: rotation returns a new value and leaves
    // persisting it to the caller, which is what makes it resumable.
    assert_eq!(original.key_id().as_str(), "key-0001");
    assert_eq!(
        &*vault.decrypt("users.email", &original).unwrap(),
        "alp@example.com"
    );
}

#[test]
fn rotation_recomputes_the_blind_index_too() {
    let provider = std::sync::Arc::new(LocalKeyProvider::generate().unwrap());
    let vault = Vault::builder()
        .key_provider_arc(provider.clone())
        .field(
            FieldConfig::new("users.email")
                .unwrap()
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .build()
        .unwrap();

    let original = vault.protect("users.email", "alp@example.com").unwrap();
    let old_index = original.blind_index.clone().unwrap();

    provider
        .add_generated_key(KeyId::new("key-0002").unwrap(), true)
        .unwrap();

    let rotated = vault.rotate("users.email", &original.ciphertext).unwrap();
    let new_index = rotated.blind_index.unwrap();

    // The index moved to the new key version, so the old stored index would no
    // longer match a query -- which is exactly why rotate returns it.
    assert_ne!(old_index.to_hex(), new_index.to_hex());
    assert_eq!(new_index.key_id().as_str(), "key-0002");
    assert_eq!(
        new_index.to_hex(),
        vault
            .blind_index("users.email", "ALP@example.com")
            .unwrap()
            .to_hex()
    );
}

#[test]
fn pinning_the_blind_index_key_survives_encryption_key_rotation() {
    // The reason pinning exists: rotating the encryption key needs only
    // ciphertext, but rotating the index key needs plaintext for every row.
    // Pinning lets the cheap rotation happen without triggering the expensive
    // one, so stored indexes stay valid.
    let provider = std::sync::Arc::new(LocalKeyProvider::generate().unwrap());
    let vault = Vault::builder()
        .key_provider_arc(provider.clone())
        .field(
            FieldConfig::new("users.email")
                .unwrap()
                .with_normalization(Normalization::Email)
                .with_blind_index(
                    BlindIndexConfig::new().with_key_id(KeyId::new("key-0001").unwrap()),
                ),
        )
        .build()
        .unwrap();

    let before = vault.blind_index("users.email", "alp@example.com").unwrap();
    provider
        .add_generated_key(KeyId::new("key-0002").unwrap(), true)
        .unwrap();
    let after = vault.blind_index("users.email", "alp@example.com").unwrap();

    assert_eq!(before.to_hex(), after.to_hex());
    assert_eq!(after.key_id().as_str(), "key-0001");

    // Encryption still moved to the new key.
    let value = vault.encrypt("users.email", "alp@example.com").unwrap();
    assert_eq!(value.key_id().as_str(), "key-0002");
}

#[test]
fn a_retired_key_makes_its_values_unreadable_and_says_so() {
    // Removing a key version from the keyring before its values are rotated is
    // the one irreversible mistake in a rotation. The error has to name the
    // missing key so an operator can put it back.
    let json = LocalKeyProvider::generate().unwrap().to_json().unwrap();
    let full = LocalKeyProvider::from_json(&json).unwrap();
    let vault_a = test_vault(LocalKeyProvider::from_json(&json).unwrap());
    let value = vault_a.encrypt("users.email", "alp@example.com").unwrap();

    // Build a keyring that holds key-0002 and nothing else, as if key-0001 had
    // been deleted while values still referred to it.
    let key_0002 = KeyId::new("key-0002").unwrap();
    let replacement = LocalKeyProvider::generate().unwrap();
    replacement
        .add_generated_key(key_0002.clone(), true)
        .unwrap();
    let keyring = Keyring::new(replacement.keyring().get(&key_0002).unwrap().clone());
    let vault_b = test_vault(LocalKeyProvider::new(keyring));

    match vault_b.decrypt("users.email", &value) {
        Err(Error::UnknownKey { key_id }) => assert_eq!(key_id, "key-0001"),
        other => panic!("expected UnknownKey, got {other:?}"),
    }

    // The original keyring still reads it.
    assert!(full.key(value.key_id(), KeyPurpose::Encryption).is_ok());
}

#[test]
fn rotation_can_also_change_algorithm() {
    // v1 -> v2 style migration: the field switches algorithm, and rotate moves
    // existing values across without the application knowing.
    let provider = std::sync::Arc::new(LocalKeyProvider::generate().unwrap());
    let aes_vault = Vault::builder()
        .key_provider_arc(provider.clone())
        .field(FieldConfig::new("users.note").unwrap())
        .build()
        .unwrap();
    let value = aes_vault.encrypt("users.note", "hello").unwrap();
    assert_eq!(value.algorithm(), vaulted_core::Algorithm::Aes256Gcm);

    let xchacha_vault = Vault::builder()
        .key_provider_arc(provider)
        .algorithm(vaulted_core::Algorithm::XChaCha20Poly1305)
        .field(FieldConfig::new("users.note").unwrap())
        .build()
        .unwrap();

    assert!(xchacha_vault.needs_rotation("users.note", &value).unwrap());
    let rotated = xchacha_vault.rotate("users.note", &value).unwrap();
    assert!(rotated.changed);
    assert_eq!(
        rotated.ciphertext.algorithm(),
        vaulted_core::Algorithm::XChaCha20Poly1305
    );
    assert_eq!(
        &*xchacha_vault
            .decrypt("users.note", &rotated.ciphertext)
            .unwrap(),
        "hello"
    );
    // And the old AES value still reads, because the algorithm travels with it.
    assert_eq!(
        &*xchacha_vault.decrypt("users.note", &value).unwrap(),
        "hello"
    );
}
