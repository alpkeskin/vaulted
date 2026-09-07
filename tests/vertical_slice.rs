//! The end-to-end path an application actually takes:
//!
//! ```text
//! plaintext -> protect -> (ciphertext, blind index) -> row -> query -> decrypt
//! ```
//!
//! These tests stand in for the database with an in-memory table, so they
//! exercise the same call sequence a PostgreSQL-backed application would use
//! without depending on a database being present.

mod support;

use std::collections::HashMap;

use support::test_vault;
use vaulted_core::{EncryptedValue, Error, LocalKeyProvider, Vault};

/// A stand-in for a table with one encrypted column and its search column.
#[derive(Default)]
struct Table {
    rows: Vec<Row>,
}

struct Row {
    id: u64,
    email_ciphertext: String,
    email_blind_index: String,
}

impl Table {
    fn insert(&mut self, vault: &Vault, id: u64, email: &str) {
        let protected = vault.protect("users.email", email).unwrap();
        self.rows.push(Row {
            id,
            email_ciphertext: protected.ciphertext.to_string(),
            email_blind_index: protected
                .blind_index
                .expect("users.email declares a blind index")
                .to_hex(),
        });
    }

    /// `SELECT * FROM users WHERE email_blind_index = $1`
    fn find_by_email(&self, vault: &Vault, email: &str) -> Vec<&Row> {
        let index = vault.blind_index("users.email", email).unwrap().to_hex();
        self.rows
            .iter()
            .filter(|row| row.email_blind_index == index)
            .collect()
    }
}

#[test]
fn insert_then_query_by_blind_index_then_decrypt() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut table = Table::default();

    table.insert(&vault, 1, "alp@example.com");
    table.insert(&vault, 2, "other@example.com");

    // The query normalizes the same way the write did, so case and padding
    // differences do not matter.
    let found = table.find_by_email(&vault, "  ALP@Example.COM ");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, 1);

    let plaintext = vault
        .decrypt_str("users.email", &found[0].email_ciphertext)
        .unwrap();
    assert_eq!(&*plaintext, "alp@example.com");

    assert!(table.find_by_email(&vault, "nobody@example.com").is_empty());
}

#[test]
fn the_stored_row_contains_no_plaintext() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut table = Table::default();
    table.insert(&vault, 1, "alp@example.com");

    let row = &table.rows[0];
    for stored in [&row.email_ciphertext, &row.email_blind_index] {
        assert!(!stored.contains("alp"));
        assert!(!stored.contains("example.com"));
        assert!(!stored.contains('@'));
    }
    // What the row does reveal, by design: format, key version, algorithm.
    assert!(row.email_ciphertext.starts_with("vlt:v1:"));
}

#[test]
fn equal_values_share_an_index_and_that_is_visible_in_the_dump() {
    // This is the documented leak, asserted so that it stays deliberate: two
    // rows holding the same address are linkable without decrypting either.
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut table = Table::default();
    table.insert(&vault, 1, "shared@example.com");
    table.insert(&vault, 2, "shared@example.com");
    table.insert(&vault, 3, "unique@example.com");

    assert_eq!(
        table.rows[0].email_blind_index,
        table.rows[1].email_blind_index
    );
    assert_ne!(
        table.rows[0].email_blind_index,
        table.rows[2].email_blind_index
    );
    // Ciphertexts, in contrast, differ even for identical plaintext.
    assert_ne!(
        table.rows[0].email_ciphertext,
        table.rows[1].email_ciphertext
    );
}

#[test]
fn a_dump_is_useless_without_the_keyring() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut table = Table::default();
    table.insert(&vault, 1, "alp@example.com");

    // The attacker has the whole table and builds their own vault. Key
    // identifiers match, because they are just labels.
    let attacker = test_vault(LocalKeyProvider::generate().unwrap());
    let stolen = &table.rows[0].email_ciphertext;

    assert!(matches!(
        attacker.decrypt_str("users.email", stolen),
        Err(Error::AuthenticationFailed)
    ));
    // Nor can they confirm a guess through the blind index.
    assert_ne!(
        attacker
            .blind_index("users.email", "alp@example.com")
            .unwrap()
            .to_hex(),
        table.rows[0].email_blind_index
    );
}

#[test]
fn moving_a_value_between_columns_fails() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let email = vault.encrypt("users.email", "alp@example.com").unwrap();

    // An attacker with write access copies the email ciphertext into the note
    // column, hoping the application will display it somewhere else.
    let serialized = email.to_string();
    assert!(matches!(
        vault.decrypt_str("users.note", &serialized),
        Err(Error::AuthenticationFailed)
    ));

    // And the reverse: a note cannot be promoted into the email column.
    let note = vault.encrypt("users.note", "hello").unwrap();
    assert!(matches!(
        vault.decrypt("users.email", &note),
        Err(Error::AuthenticationFailed)
    ));
}

#[test]
fn normalization_never_reaches_the_stored_value() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());

    // users.phone strips everything but digits for indexing. The stored value
    // must still come back formatted exactly as the user typed it.
    let typed = "+90 (555) 111 22 33";
    let protected = vault.protect("users.phone", typed).unwrap();
    assert_eq!(
        &*vault.decrypt("users.phone", &protected.ciphertext).unwrap(),
        typed
    );

    // ... while the index matches the same number written differently.
    assert_eq!(
        protected.blind_index.unwrap().to_hex(),
        vault
            .blind_index("users.phone", "905551112233")
            .unwrap()
            .to_hex()
    );
}

#[test]
fn the_same_value_in_two_columns_is_not_linkable() {
    // A user whose phone number is also their username: the two columns must
    // not produce the same index, or the dump joins them for free.
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let email = vault.blind_index("users.email", "5551112233").unwrap();
    let phone = vault.blind_index("users.phone", "5551112233").unwrap();
    assert_ne!(email.to_hex(), phone.to_hex());
}

#[test]
fn values_survive_a_json_round_trip() {
    // Applications persist through serde as often as through Display.
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let value = vault.encrypt("users.email", "alp@example.com").unwrap();

    let json = serde_json::to_string(&value).unwrap();
    assert!(json.starts_with("\"vlt:v1:"));

    let restored: EncryptedValue = serde_json::from_str(&json).unwrap();
    assert_eq!(
        &*vault.decrypt("users.email", &restored).unwrap(),
        "alp@example.com"
    );

    assert!(serde_json::from_str::<EncryptedValue>("\"garbage\"").is_err());
}

#[test]
fn binary_values_round_trip() {
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let blob: Vec<u8> = (0..=255u8).collect();
    let value = vault.encrypt_bytes("users.note", &blob).unwrap();
    assert_eq!(
        vault
            .decrypt_bytes("users.note", &value)
            .unwrap()
            .as_slice(),
        &blob[..]
    );
}

#[test]
fn a_shared_provider_serves_several_vaults() {
    use std::sync::Arc;
    use vaulted_core::{FieldConfig, KeyProvider};

    let provider: Arc<dyn KeyProvider> = Arc::new(LocalKeyProvider::generate().unwrap());
    let writer = Vault::builder()
        .key_provider_arc(Arc::clone(&provider))
        .field(FieldConfig::new("users.note").unwrap())
        .build()
        .unwrap();
    let reader = Vault::builder()
        .key_provider_arc(provider)
        .field(FieldConfig::new("users.note").unwrap())
        .build()
        .unwrap();

    let value = writer.encrypt("users.note", "hello").unwrap();
    assert_eq!(&*reader.decrypt("users.note", &value).unwrap(), "hello");
}

#[test]
fn a_lookup_table_of_indexes_behaves_like_a_unique_index() {
    // Blind indexes are used as database index keys, so they have to behave
    // sanely as hash map keys: stable across calls, distinct across values.
    let vault = test_vault(LocalKeyProvider::generate().unwrap());
    let mut by_index: HashMap<String, u64> = HashMap::new();

    for (id, email) in [
        (1, "a@example.com"),
        (2, "b@example.com"),
        (3, "c@example.com"),
    ] {
        by_index.insert(
            vault.blind_index("users.email", email).unwrap().to_hex(),
            id,
        );
    }
    assert_eq!(by_index.len(), 3);

    let looked_up = vault
        .blind_index("users.email", "B@EXAMPLE.COM")
        .unwrap()
        .to_hex();
    assert_eq!(by_index.get(&looked_up), Some(&2));
}
