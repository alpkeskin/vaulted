//! The smallest useful program: encrypt a value, search for it, read it back.
//!
//! ```sh
//! cargo run -p vaulted-examples --example basic
//! ```

use vaulted_core::{BlindIndexConfig, Error, FieldConfig, LocalKeyProvider, Normalization, Vault};

fn main() -> Result<(), Error> {
    // In production this is a KMS-backed provider. Keys generated here live
    // only as long as the process.
    let vault = Vault::builder()
        .key_provider(LocalKeyProvider::generate()?)
        .field(
            FieldConfig::new("users.email")?
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .build()?;

    // One call produces both columns of an INSERT.
    let row = vault.protect("users.email", "Alp@Example.com")?;
    let ciphertext = row.ciphertext.to_string();
    let blind_index = row.blind_index.expect("the field declares one").to_hex();

    println!("ciphertext   {ciphertext}");
    println!("blind index  {blind_index}");

    // The query recomputes the index from whatever the user typed. Casing and
    // stray spaces do not matter, because the field's normalization is applied
    // on both sides.
    let lookup = vault
        .blind_index("users.email", "  ALP@example.COM ")?
        .to_hex();
    assert_eq!(lookup, blind_index);
    println!("lookup       matches");

    // What comes back is exactly what went in -- normalization never touches
    // the stored value.
    let plaintext = vault.decrypt_str("users.email", &ciphertext)?;
    println!("plaintext    {}", &*plaintext);
    assert_eq!(&*plaintext, "Alp@Example.com");

    // Encrypting the same value twice gives different ciphertext, so a dump
    // cannot tell which rows are equal from the ciphertext alone.
    let again = vault.encrypt("users.email", "Alp@Example.com")?;
    assert_ne!(again.to_string(), ciphertext);
    println!("second write differs from the first");

    // A value is bound to its field: the same ciphertext under another column
    // fails to authenticate.
    match vault.decrypt_str("users.phone", &ciphertext) {
        Err(Error::AuthenticationFailed) => println!("cross-field reuse rejected"),
        other => panic!("expected an authentication failure, got {other:?}"),
    }

    Ok(())
}
