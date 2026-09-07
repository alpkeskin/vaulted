//! What a PostgreSQL-backed application actually does, with an in-memory table
//! standing in for the database.
//!
//! ```sh
//! cargo run -p vaulted-examples --example postgres_workflow
//! ```
//!
//! The schema this models:
//!
//! ```sql
//! CREATE TABLE users (
//!     id                 bigserial PRIMARY KEY,
//!     name               text        NOT NULL,        -- not sensitive, stored as-is
//!     email_ciphertext   text        NOT NULL,        -- vlt:v1:...
//!     email_blind_index  bytea       NOT NULL,        -- HMAC-SHA256
//!     phone_ciphertext   text,
//!     phone_blind_index  bytea
//! );
//!
//! CREATE INDEX users_email_blind_index_idx ON users (email_blind_index);
//! ```
//!
//! Two notes on the schema. The ciphertext column is `text` because the
//! serialized format is ASCII; `bytea` works too if you prefer. And the blind
//! index is what gets the database index — the ciphertext column never will,
//! since it is different for every write.

use std::collections::HashMap;

use vaulted_core::{BlindIndexConfig, Error, FieldConfig, LocalKeyProvider, Normalization, Vault};

/// Stands in for the `users` table.
#[derive(Default)]
struct Users {
    rows: Vec<UserRow>,
    /// Stands in for `users_email_blind_index_idx`.
    by_email_index: HashMap<Vec<u8>, usize>,
}

struct UserRow {
    id: i64,
    name: String,
    email_ciphertext: String,
    email_blind_index: Vec<u8>,
}

impl Users {
    /// `INSERT INTO users (name, email_ciphertext, email_blind_index) VALUES ($1, $2, $3)`
    fn insert(&mut self, vault: &Vault, id: i64, name: &str, email: &str) -> Result<(), Error> {
        let protected = vault.protect("users.email", email)?;
        let index = protected
            .blind_index
            .expect("users.email declares a blind index")
            .as_bytes()
            .to_vec();

        self.by_email_index.insert(index.clone(), self.rows.len());
        self.rows.push(UserRow {
            id,
            name: name.to_string(),
            email_ciphertext: protected.ciphertext.to_string(),
            email_blind_index: index,
        });
        Ok(())
    }

    /// `SELECT * FROM users WHERE email_blind_index = $1`
    fn find_by_email(&self, vault: &Vault, email: &str) -> Result<Option<&UserRow>, Error> {
        let index = vault.blind_index("users.email", email)?;
        Ok(self
            .by_email_index
            .get(index.as_bytes())
            .map(|position| &self.rows[*position]))
    }
}

fn main() -> Result<(), Error> {
    let vault = Vault::builder()
        .key_provider(LocalKeyProvider::generate()?)
        .field(
            FieldConfig::new("users.email")?
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .field(
            FieldConfig::new("users.phone")?
                .with_normalization(Normalization::DigitsOnly)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .build()?;

    let mut users = Users::default();
    users.insert(&vault, 1, "Alp", "alp@example.com")?;
    users.insert(&vault, 2, "Deniz", "deniz@example.com")?;
    users.insert(&vault, 3, "Ece", "ece@example.com")?;

    println!("-- what the table holds --");
    for row in &users.rows {
        println!(
            "id={} name={} email_ciphertext={} email_blind_index=\\x{}",
            row.id,
            row.name,
            row.email_ciphertext,
            row.email_blind_index
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }

    println!();
    println!("-- login by email --");
    // The user typed their address with different casing; the blind index does
    // not care, because the field normalizes before hashing.
    match users.find_by_email(&vault, "DENIZ@Example.com")? {
        Some(row) => {
            let email = vault.decrypt_str("users.email", &row.email_ciphertext)?;
            println!("found id={} name={} email={}", row.id, row.name, *email);
        }
        None => println!("no such user"),
    }

    println!();
    println!("-- a phone number, formatted freely --");
    // Phone numbers are stored exactly as typed and indexed on digits only, so
    // punctuation stops mattering -- but nothing more than punctuation does.
    // A country prefix written differently is a different number to
    // DigitsOnly, which is why anything that needs real phone-number semantics
    // should normalize to E.164 in the application and index the result with
    // Normalization::None.
    let stored = vault.protect("users.phone", "+90 (555) 111 22 33")?;
    let stored_index = stored.blind_index.unwrap().to_hex();
    for typed in ["+905551112233", "90-555-111-22-33", "0555 111 22 33"] {
        let index = vault.blind_index("users.phone", typed)?.to_hex();
        println!(
            "{typed:<20} -> {}",
            if index == stored_index {
                "match"
            } else {
                "no match (different digits)"
            }
        );
    }
    println!(
        "stored value comes back as typed: {}",
        *vault.decrypt("users.phone", &stored.ciphertext)?
    );

    println!();
    println!("-- what an attacker with the dump sees --");
    println!("value lengths, row counts, which rows share an email -- and nothing else.");

    Ok(())
}
