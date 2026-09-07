//! Declaring encrypted fields on the struct instead of three times over.
//!
//! ```sh
//! cargo run -p vaulted-examples --example derive --features derive
//! ```
//!
//! Compare with `postgres_workflow.rs`, which spells out the same schema by
//! hand. The difference is not how much is typed; it is that there is now one
//! place to typo. A field name is authenticated associated data, so a mismatch
//! between the vault's configuration and a call site does not misbehave
//! loudly — it writes a column nothing can decrypt.
//!
//! No database is opened here. The statements are printed rather than executed,
//! which is the whole of what `vaulted-postgres` does: it generates SQL and
//! binds parameters, and leaves running them to your driver.

use vaulted_core::{LocalKeyProvider, Vault, Vaulted, VaultedSchema};
use vaulted_postgres::ddl;

/// The `users` row, as the application sees it.
///
/// `id` and `name` carry no attribute, so they are outside the schema entirely:
/// plain columns, stored as-is.
#[derive(Vaulted)]
#[vaulted(table = "users")]
struct User {
    id: i64,
    name: String,

    /// Searchable, and matched case-insensitively.
    #[vaulted(encrypt, blind_index, normalize = "email")]
    email: String,

    /// Searchable across formatting differences: `+90 555 111 22 33` and
    /// `905551112233` land on the same index.
    #[vaulted(encrypt, blind_index, normalize = "digits_only")]
    phone: Option<String>,

    /// Encrypted, but deliberately not searchable. A blind index over a
    /// national ID would reveal which rows share one, and there is no query
    /// that needs it.
    ///
    /// `rename` sets the vault field name, and the columns follow it: this one
    /// lands in `tckn_ciphertext`, not `national_id_ciphertext`. One value, one
    /// name, wherever it appears.
    #[vaulted(encrypt, rename = "tckn")]
    national_id: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The schema knows the columns it needs, so a migration can be read off the
    // struct rather than kept in step with it by hand.
    println!("-- a new table:\nCREATE TABLE users (");
    println!("    id bigserial PRIMARY KEY,");
    println!("    name text NOT NULL,");
    println!("    {}", ddl::column_definitions::<User>().join(",\n    "));
    println!(");");

    // Adding the columns to a table that already has rows is a different
    // statement, and a three-step migration: the columns arrive nullable,
    // because a NOT NULL column cannot be added to a populated table without a
    // default — and a default for a ciphertext column is a plaintext value
    // sitting in your schema.
    println!("\n-- or, on an existing table:");
    for statement in ddl::add_column_statements::<User>(User::TABLE) {
        println!("{statement}");
    }
    println!("-- ... backfill every row, then:");
    for statement in ddl::set_not_null_statements::<User>(User::TABLE) {
        println!("{statement}");
    }

    // Only the blind index columns are worth indexing: a fresh nonce per write
    // makes each ciphertext different, so an index on one can never serve a
    // query.
    println!();
    for statement in ddl::create_index_statements::<User>(User::TABLE) {
        println!("{statement}");
    }
    println!();

    // One declaration, so the vault cannot disagree with the struct about
    // which fields exist or how they are normalized.
    let vault = Vault::builder()
        .key_provider(LocalKeyProvider::generate()?) // a KMS in production
        .fields(User::field_configs()?)
        .build()?;

    let user = User {
        id: 1,
        name: "Alp".into(),
        email: "Alp@Example.com".into(),
        phone: Some("+90 555 111 22 33".into()),
        national_id: "11111111111".into(),
    };

    // `User::EMAIL_FIELD` is `"users.email"` — but a typo in it does not
    // compile, where a typo in the string would have reached production.
    let email = vault.protect(User::EMAIL_FIELD, &user.email)?;
    let national_id = vault.protect(User::NATIONAL_ID_FIELD, &user.national_id)?;

    println!(
        "INSERT INTO users (id, name, ...) VALUES ({}, {:?}, ...)",
        user.id, user.name
    );
    println!("  email_ciphertext   {}", email.ciphertext);
    println!(
        "  email_blind_index  \\x{}",
        email
            .blind_index
            .as_ref()
            .expect("email is searchable")
            .to_hex()
    );
    println!("  tckn_ciphertext    {}", national_id.ciphertext);
    println!(
        "  (no national_id index: {} is not searchable)\n",
        User::NATIONAL_ID_FIELD
    );

    // A lookup normalizes the same way the write did, because the rule lives in
    // the field configuration rather than at either call site. The predicate
    // comes from the schema too, so the column name is not retyped here either.
    let predicate = ddl::blind_index_predicate::<User>("email", 1).expect("email is searchable");
    println!("SELECT id, email_ciphertext FROM users WHERE {predicate}");
    let lookup = vault.blind_index(User::EMAIL_FIELD, "  alp@EXAMPLE.com ")?;
    println!("  $1 = \\x{}", lookup.to_hex());
    println!(
        "  matches the stored index: {}",
        lookup.matches(email.blind_index.as_ref().expect("email is searchable"))
    );

    // And what comes back is what went in, capitals and all.
    let decrypted = vault.decrypt(User::EMAIL_FIELD, &email.ciphertext)?;
    println!("  decrypted: {}", *decrypted);
    assert_eq!(&*decrypted, &user.email);

    // The phone is an Option, so its columns are nullable; nothing is written
    // when there is nothing to write.
    if let Some(phone) = &user.phone {
        let protected = vault.protect(User::PHONE_FIELD, phone)?;
        let lookup = vault.blind_index(User::PHONE_FIELD, "905551112233")?;
        println!(
            "\nphone written; a differently formatted lookup matches: {}",
            lookup.matches(protected.blind_index.as_ref().expect("phone is searchable"))
        );
    }

    Ok(())
}
