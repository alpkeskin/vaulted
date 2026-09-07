//! A zero-downtime key rotation, start to finish.
//!
//! ```sh
//! cargo run -p vaulted-examples --example key_rotation
//! ```
//!
//! The shape of the operation:
//!
//! ```text
//! 1. add a key version, promote it        new writes use it immediately
//! 2. backfill in batches                  old values re-encrypted, resumable
//! 3. verify nothing refers to the old key
//! 4. retire the old key                   only now, and never before step 3
//! ```
//!
//! Nothing is ever rewritten in place by the library: `rotate` returns the new
//! value and leaves persisting it to the caller, so a crashed job resumes by
//! simply running again.

use std::sync::Arc;

use vaulted_core::{
    BlindIndexConfig, EncryptedValue, Error, FieldConfig, KeyId, LocalKeyProvider, Normalization,
    Vault,
};

/// Stands in for the rows a backfill job walks.
struct Row {
    id: i64,
    email_ciphertext: String,
    email_blind_index: String,
}

fn main() -> Result<(), Error> {
    let provider = Arc::new(LocalKeyProvider::generate()?);
    let vault = Vault::builder()
        .key_provider_arc(provider.clone())
        .field(
            FieldConfig::new("users.email")?
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .build()?;

    // -- before ------------------------------------------------------------
    let mut rows: Vec<Row> = ["alp@example.com", "deniz@example.com", "ece@example.com"]
        .iter()
        .enumerate()
        .map(|(i, email)| {
            let protected = vault.protect("users.email", email)?;
            Ok(Row {
                id: i as i64 + 1,
                email_ciphertext: protected.ciphertext.to_string(),
                email_blind_index: protected.blind_index.unwrap().to_hex(),
            })
        })
        .collect::<Result<_, Error>>()?;

    println!("primary key: {}", vault.primary_key_id()?);
    for row in &rows {
        println!("  row {} -> {}", row.id, key_of(&row.email_ciphertext)?);
    }

    // -- step 1: add and promote a key -------------------------------------
    let new_key = KeyId::new("key-0002")?;
    provider.add_generated_key(new_key.clone(), true)?;
    println!("\npromoted {new_key}; existing rows still decrypt");

    // Old rows are readable throughout: each names the key it needs.
    for row in &rows {
        let email = vault.decrypt_str("users.email", &row.email_ciphertext)?;
        println!("  row {} still reads as {}", row.id, &*email);
    }

    // A write during the rotation lands on the new key straight away.
    let fresh = vault.encrypt("users.email", "new@example.com")?;
    println!("  a new write uses {}", fresh.key_id());

    // -- step 2: backfill ---------------------------------------------------
    println!("\nbackfilling");
    let mut rotated = 0;
    for row in &mut rows {
        let value: EncryptedValue = row.email_ciphertext.parse()?;
        if !vault.needs_rotation("users.email", &value)? {
            continue; // already current: cheap to skip, so the job is resumable
        }

        let result = vault.rotate("users.email", &value)?;
        // UPDATE users SET email_ciphertext = $1, email_blind_index = $2 WHERE id = $3
        row.email_ciphertext = result.ciphertext.to_string();
        row.email_blind_index = result.blind_index.unwrap().to_hex();
        rotated += 1;
    }
    println!("  rotated {rotated} rows");

    // The blind index moved with the key, so lookups must use the new index --
    // which is why `rotate` hands it back rather than making you recompute it
    // from a plaintext you would otherwise have to decrypt twice.
    let lookup = vault
        .blind_index("users.email", "ALP@example.com")?
        .to_hex();
    assert_eq!(lookup, rows[0].email_blind_index);
    println!("  lookups still find the rows");

    // -- step 3: verify -----------------------------------------------------
    let stragglers = rows
        .iter()
        .filter(|row| {
            key_of(&row.email_ciphertext)
                .map(|k| k != new_key)
                .unwrap_or(true)
        })
        .count();
    println!("\nrows still on an old key: {stragglers}");
    assert_eq!(stragglers, 0);

    // -- step 4: retire -----------------------------------------------------
    // Only now is it safe to remove key-0001 from the keyring. Do it earlier
    // and every row that still names it becomes permanently unreadable, which
    // is why this library will not delete a key for you.
    println!("key-0001 can now be retired");

    for row in &rows {
        let email = vault.decrypt_str("users.email", &row.email_ciphertext)?;
        println!(
            "  row {} -> {} ({})",
            row.id,
            &*email,
            key_of(&row.email_ciphertext)?
        );
    }

    Ok(())
}

fn key_of(serialized: &str) -> Result<KeyId, Error> {
    Ok(serialized.parse::<EncryptedValue>()?.key_id().clone())
}
