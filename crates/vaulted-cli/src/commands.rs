//! Command implementations.
//!
//! Two rules hold throughout: no command touches a database, and no command
//! prints key material. `decrypt` prints plaintext, because that is what it was
//! asked to do — everything else stays quiet about values.

use std::io::{Read, Write};

use vaulted_core::{EncryptedValue, KeyId, KeyProvider, Keyring, LocalKeyProvider};

use crate::args::{
    Cli, FieldArgs, InitArgs, InspectArgs, KeyCreateArgs, KeyRotateArgs, ValueArgs, KEYRING_ENV,
};
use crate::context::{load_provider, vault_for_field, Error, KeyringSource, Result};

/// `vaulted init`
pub fn init(cli: &Cli, args: &InitArgs) -> Result<()> {
    let source = KeyringSource::resolve(cli);
    let Some(path) = source.path() else {
        return Err(Error::Usage(format!(
            "{KEYRING_ENV} holds an inline keyring; pass --keyring PATH to write a file"
        )));
    };

    if path.exists() && !args.force {
        // Overwriting a keyring destroys the ability to read everything
        // encrypted with it. That has to be deliberate.
        return Err(Error::Usage(format!(
            "{} already exists; refusing to overwrite it (pass --force if the old keys are truly not needed)",
            path.display()
        )));
    }

    let provider = LocalKeyProvider::new(Keyring::generate()?);
    provider.save_file(path)?;

    let mut out = std::io::stdout().lock();
    writeln!(out, "Created keyring   {}", path.display())?;
    writeln!(out, "Primary key       {}", provider.primary_key_id()?)?;
    writeln!(out, "Permissions       0600 (owner only)")?;
    writeln!(out)?;
    writeln!(
        out,
        "This file is the plaintext of your database. Back it up somewhere the\n\
         database backups do not reach, and keep it out of version control."
    )?;
    Ok(())
}

/// `vaulted key create`
pub fn key_create(cli: &Cli, args: &KeyCreateArgs) -> Result<()> {
    add_key(cli, args.id.as_deref(), args.primary)
}

/// `vaulted key rotate`
pub fn key_rotate(cli: &Cli, args: &KeyRotateArgs) -> Result<()> {
    add_key(cli, args.id.as_deref(), true)
}

fn add_key(cli: &Cli, id: Option<&str>, make_primary: bool) -> Result<()> {
    let (provider, source) = load_provider(cli)?;
    let Some(path) = source.path().cloned() else {
        return Err(Error::Usage(
            "the keyring is held in an environment variable and cannot be modified in place"
                .to_string(),
        ));
    };

    let key_id = match id {
        Some(id) => KeyId::new(id)?,
        None => provider.keyring().next_key_id()?,
    };
    if provider.keyring().get(&key_id).is_some() {
        return Err(Error::Usage(format!("{key_id} already exists")));
    }

    provider.add_generated_key(key_id.clone(), make_primary)?;
    provider.save_file(&path)?;

    let mut out = std::io::stdout().lock();
    writeln!(out, "Added key         {key_id}")?;
    writeln!(out, "Primary key       {}", provider.primary_key_id()?)?;
    if make_primary {
        writeln!(out)?;
        writeln!(
            out,
            "New values are now encrypted with {key_id}. Existing values still name the\n\
             key they were written with and keep decrypting; move them over with\n\
             `vaulted rotate`, then retire the old key once no value refers to it."
        )?;
    }
    Ok(())
}

/// `vaulted key list`
pub fn key_list(cli: &Cli) -> Result<()> {
    let (provider, _) = load_provider(cli)?;
    let keyring = provider.keyring();
    let primary = keyring.primary().clone();

    let mut out = std::io::stdout().lock();
    writeln!(out, "{:<20} {:<12} CREATED", "KEY ID", "ROLE")?;
    for version in keyring.versions() {
        let role = if *version.id() == primary {
            "primary"
        } else {
            "retained"
        };
        let created = version
            .created_at()
            .map(|secs| format!("unix:{secs}"))
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            out,
            "{:<20} {:<12} {}",
            version.id().as_str(),
            role,
            created
        )?;
    }
    Ok(())
}

/// `vaulted status`
pub fn status(cli: &Cli) -> Result<()> {
    let (provider, source) = load_provider(cli)?;
    let keyring = provider.keyring();

    let mut out = std::io::stdout().lock();
    writeln!(out, "Keyring           {source}")?;
    writeln!(out, "Key versions      {}", keyring.len())?;
    writeln!(out, "Primary key       {}", keyring.primary())?;
    writeln!(out, "Format version    v{}", vaulted_core::FORMAT_VERSION)?;
    writeln!(
        out,
        "Algorithms        {}",
        [
            vaulted_core::Algorithm::Aes256Gcm,
            vaulted_core::Algorithm::XChaCha20Poly1305
        ]
        .iter()
        .filter(|a| a.is_available())
        .map(|a| a.wire_name())
        .collect::<Vec<_>>()
        .join(", ")
    )?;
    writeln!(out)?;
    // Field and blind index inventory would need to read the database schema,
    // which this tool deliberately does not do yet.
    writeln!(
        out,
        "Encrypted field inventory is not tracked by the CLI; it lives in your\n\
         application's vault configuration."
    )?;
    Ok(())
}

/// `vaulted inspect`
pub fn inspect(args: &InspectArgs) -> Result<()> {
    let serialized = if args.value == "-" {
        read_stdin_line()?
    } else {
        args.value.clone()
    };

    let value = EncryptedValue::parse(serialized.trim())?;

    let mut out = std::io::stdout().lock();
    writeln!(out, "Format version    v{}", value.version())?;
    writeln!(out, "Key id            {}", value.key_id())?;
    writeln!(out, "Algorithm         {}", value.algorithm().wire_name())?;
    writeln!(
        out,
        "Nonce length      {} bytes",
        value.algorithm().nonce_len()
    )?;
    writeln!(
        out,
        "Tag length        {} bytes",
        value.algorithm().tag_len()
    )?;
    // The plaintext length is derivable from the ciphertext by anyone holding
    // it, so showing it discloses nothing new -- but it is worth seeing,
    // because it is the one thing this format does leak.
    writeln!(out, "Plaintext length  {} bytes", value.plaintext_len())?;
    Ok(())
}

/// `vaulted blind-index`
pub fn blind_index(cli: &Cli, args: &ValueArgs) -> Result<()> {
    let (provider, _) = load_provider(cli)?;
    let vault = vault_for_field(provider, &args.field, true)?;
    let value = value_input(args)?;

    let index = vault.blind_index(&args.field.field, &value)?;
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", index.to_hex())?;
    Ok(())
}

/// `vaulted encrypt`
pub fn encrypt(cli: &Cli, args: &ValueArgs) -> Result<()> {
    let (provider, _) = load_provider(cli)?;
    let vault = vault_for_field(provider, &args.field, false)?;
    let value = value_input(args)?;

    let protected = vault.protect(&args.field.field, &value)?;
    let mut out = std::io::stdout().lock();
    match protected.blind_index {
        Some(index) => writeln!(out, "{}\t{}", protected.ciphertext, index.to_hex())?,
        None => writeln!(out, "{}", protected.ciphertext)?,
    }
    Ok(())
}

/// `vaulted decrypt`
pub fn decrypt(cli: &Cli, args: &FieldArgs) -> Result<()> {
    let (provider, _) = load_provider(cli)?;
    let vault = vault_for_field(provider, args, false)?;
    let serialized = read_stdin_line()?;

    let plaintext = vault.decrypt_str(&args.field, serialized.trim())?;
    let mut out = std::io::stdout().lock();
    out.write_all(plaintext.as_bytes())?;
    out.write_all(b"\n")?;
    Ok(())
}

/// `vaulted rotate`
///
/// Reads serialized values from stdin, one per line, and writes the
/// re-encrypted values to stdout in the same order. Values already using the
/// primary key are passed through unchanged and reported at the end.
pub fn rotate(cli: &Cli, args: &FieldArgs) -> Result<()> {
    let (provider, _) = load_provider(cli)?;
    let vault = vault_for_field(provider, args, false)?;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let mut out = std::io::stdout().lock();
    let (mut rotated, mut unchanged) = (0usize, 0usize);

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = EncryptedValue::parse(line)?;
        let result = vault.rotate(&args.field, &value)?;
        if result.changed {
            rotated += 1;
        } else {
            unchanged += 1;
        }
        match result.blind_index {
            Some(index) => writeln!(out, "{}\t{}", result.ciphertext, index.to_hex())?,
            None => writeln!(out, "{}", result.ciphertext)?,
        }
    }

    // Counts go to stderr so stdout stays a clean stream of values.
    eprintln!("rotated {rotated}, already current {unchanged}");
    Ok(())
}

/// Reads a value from `--value` or from stdin.
fn value_input(args: &ValueArgs) -> Result<String> {
    match &args.value {
        Some(value) => Ok(value.clone()),
        None => read_stdin_line(),
    }
}

/// Reads stdin and strips one trailing newline.
///
/// The newline a shell adds is almost never part of the value; stripping
/// exactly one, and no other whitespace, keeps `echo -n` and `echo` equivalent
/// without silently mangling data.
fn read_stdin_line() -> Result<String> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;
    if buffer.ends_with('\n') {
        buffer.pop();
        if buffer.ends_with('\r') {
            buffer.pop();
        }
    }
    Ok(buffer)
}
