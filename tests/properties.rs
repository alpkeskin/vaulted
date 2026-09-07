//! Properties that must hold for every value, checked over many generated
//! inputs with a fixed seed so failures reproduce.

mod support;

use std::collections::HashSet;

use support::{test_vault, Rng};
use vaulted_core::{
    Algorithm, BlindIndexConfig, Error, FieldConfig, KeyId, LocalKeyProvider, Normalization, Vault,
};

fn arbitrary_string(rng: &mut Rng) -> String {
    let len = rng.below(64);
    (0..len)
        .map(|_| match rng.below(5) {
            0 => char::from(b'a' + (rng.below(26) as u8)),
            1 => char::from(b'0' + (rng.below(10) as u8)),
            2 => ['@', '.', ' ', '-', '+', '_'][rng.below(6)],
            3 => ['Ä', 'ß', 'ı', 'Ş', '中', '🔐'][rng.below(6)],
            _ => char::from(b'A' + (rng.below(26) as u8)),
        })
        .collect()
}

#[test]
fn encrypt_then_decrypt_returns_the_input_exactly() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut rng = Rng::new(0xA11C_E001);

    for _ in 0..500 {
        let plaintext = arbitrary_string(&mut rng);
        let value = vault.encrypt("users.email", &plaintext).unwrap();
        assert_eq!(*vault.decrypt("users.email", &value).unwrap(), plaintext);
    }
}

#[test]
fn encrypt_then_decrypt_returns_arbitrary_bytes_exactly() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut rng = Rng::new(0xB0B0_0002);

    for _ in 0..500 {
        let plaintext = rng.bytes_below(512);
        let value = vault.encrypt_bytes("users.note", &plaintext).unwrap();
        assert_eq!(
            vault
                .decrypt_bytes("users.note", &value)
                .unwrap()
                .as_slice(),
            plaintext.as_slice()
        );
    }
}

#[test]
fn ciphertext_is_never_repeated() {
    // A repeated ciphertext would mean a repeated nonce, which is the one
    // failure AES-GCM does not survive. Encrypting one value many times is the
    // cheapest way to notice if nonce generation ever degenerates.
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut seen = HashSet::new();

    for _ in 0..5_000 {
        let value = vault
            .encrypt("users.email", "same value every time")
            .unwrap();
        assert!(
            seen.insert(value.nonce().unwrap().as_bytes().to_vec()),
            "a nonce was reused"
        );
        assert!(
            seen.insert(value.to_string().into_bytes()),
            "a ciphertext repeated"
        );
    }
}

#[test]
fn serialization_round_trips_for_every_value() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut rng = Rng::new(0xC0DE_0003);

    for _ in 0..500 {
        let plaintext = rng.bytes_below(300);
        let value = vault.encrypt_bytes("users.note", &plaintext).unwrap();
        let serialized = value.to_string();

        let parsed: vaulted_core::EncryptedValue = serialized.parse().unwrap();
        assert_eq!(parsed, value);
        assert_eq!(parsed.to_string(), serialized);
        assert_eq!(parsed.plaintext_len(), plaintext.len());
        // The format leaks length and nothing else about the value.
        assert_eq!(
            serialized.len(),
            expected_serialized_len(&value, plaintext.len())
        );
    }
}

fn expected_serialized_len(value: &vaulted_core::EncryptedValue, plaintext_len: usize) -> usize {
    let payload = value.algorithm().nonce_len() + plaintext_len + value.algorithm().tag_len();
    let base64_len = payload.div_ceil(3) * 4 - (3 - payload % 3) % 3;
    value.header().len() + 1 + base64_len
}

#[test]
fn blind_indexes_are_deterministic_and_collision_free_in_practice() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut rng = Rng::new(0xD1CE_0004);
    let mut seen: HashSet<String> = HashSet::new();
    let mut values: Vec<String> = Vec::new();

    for _ in 0..1_000 {
        let value = arbitrary_string(&mut rng);
        let index = vault.blind_index("users.email", &value).unwrap().to_hex();

        // Same value, same index -- every time.
        assert_eq!(
            index,
            vault.blind_index("users.email", &value).unwrap().to_hex()
        );

        // Distinct normalized values must not share an index.
        let normalized = value.trim().to_lowercase();
        if seen.contains(&index) {
            assert!(
                values.iter().any(|v| v.trim().to_lowercase() == normalized),
                "two different values collided"
            );
        }
        seen.insert(index);
        values.push(value);
    }
}

#[test]
fn truncated_indexes_stay_prefixes_of_the_full_one() {
    let provider = std::sync::Arc::new(LocalKeyProvider::generate().unwrap());
    let full = index_vault(provider.clone(), 32);
    let short = index_vault(provider, 8);
    let mut rng = Rng::new(0xE001_0005);

    for _ in 0..200 {
        let value = arbitrary_string(&mut rng);
        let full_index = full.blind_index("users.email", &value).unwrap().to_hex();
        let short_index = short.blind_index("users.email", &value).unwrap().to_hex();
        assert_eq!(short_index.len(), 16);
        assert!(full_index.starts_with(&short_index));
    }
}

fn index_vault(provider: std::sync::Arc<LocalKeyProvider>, bytes: usize) -> Vault {
    Vault::builder()
        .key_provider_arc(provider)
        .field(
            FieldConfig::new("users.email")
                .unwrap()
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new().with_output_bytes(bytes).unwrap()),
        )
        .build()
        .unwrap()
}

#[test]
fn every_value_survives_a_full_rotation_cycle() {
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

    let mut rng = Rng::new(0xF001_0006);
    let originals: Vec<(String, vaulted_core::EncryptedValue)> = (0..200)
        .map(|_| {
            let plaintext = arbitrary_string(&mut rng);
            let value = vault.encrypt("users.email", &plaintext).unwrap();
            (plaintext, value)
        })
        .collect();

    for generation in 2..=4u32 {
        let key_id = KeyId::new(format!("key-{generation:04}")).unwrap();
        provider.add_generated_key(key_id.clone(), true).unwrap();

        for (plaintext, value) in &originals {
            let rotated = vault.rotate("users.email", value).unwrap();
            assert!(rotated.changed);
            assert_eq!(rotated.ciphertext.key_id(), &key_id);
            assert_eq!(
                &*vault.decrypt("users.email", &rotated.ciphertext).unwrap(),
                plaintext.as_str()
            );
            // The index follows the new key and still matches a fresh lookup.
            assert_eq!(
                rotated.blind_index.unwrap().to_hex(),
                vault
                    .blind_index("users.email", plaintext)
                    .unwrap()
                    .to_hex()
            );
        }
    }
}

#[test]
fn a_value_never_decrypts_under_a_field_it_was_not_written_for() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let fields = ["users.email", "users.phone", "users.note"];
    let mut rng = Rng::new(0x0BAD_0007);

    for _ in 0..200 {
        let plaintext = arbitrary_string(&mut rng);
        for written_as in fields {
            let value = vault.encrypt(written_as, &plaintext).unwrap();
            for read_as in fields {
                let result = vault.decrypt(read_as, &value);
                if read_as == written_as {
                    assert_eq!(*result.unwrap(), plaintext);
                } else {
                    assert!(matches!(result, Err(Error::AuthenticationFailed)));
                }
            }
        }
    }
}

#[test]
fn both_algorithms_behave_identically_from_the_outside() {
    for algorithm in [Algorithm::Aes256Gcm, Algorithm::XChaCha20Poly1305] {
        if !algorithm.is_available() {
            continue;
        }
        let vault = Vault::builder()
            .key_provider(LocalKeyProvider::generate().unwrap())
            .algorithm(algorithm)
            .field(FieldConfig::new("users.note").unwrap())
            .build()
            .unwrap();

        let mut rng = Rng::new(0x1234_0008);
        for _ in 0..200 {
            let plaintext = rng.bytes_below(256);
            let value = vault.encrypt_bytes("users.note", &plaintext).unwrap();
            assert_eq!(value.algorithm(), algorithm);
            assert_eq!(
                value.nonce().unwrap().len(),
                algorithm.nonce_len(),
                "nonce length must match the algorithm"
            );
            assert_eq!(
                vault
                    .decrypt_bytes("users.note", &value)
                    .unwrap()
                    .as_slice(),
                plaintext.as_slice()
            );
        }
    }
}
