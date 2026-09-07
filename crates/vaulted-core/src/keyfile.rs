//! JSON keyfiles for [`LocalKeyProvider`].
//!
//! A keyfile is the simplest thing that can work for development and for
//! single-node deployments: a JSON document holding one or more key versions.
//!
//! ```json
//! {
//!   "format": "vaulted-keyring",
//!   "version": 1,
//!   "primary_key_id": "key-0001",
//!   "keys": [
//!     {
//!       "id": "key-0001",
//!       "created_at": 1770000000,
//!       "encryption_key": "<base64, 32 bytes>",
//!       "blind_index_key": "<base64, 32 bytes>"
//!     }
//!   ]
//! }
//! ```
//!
//! # Handling
//!
//! This file *is* the plaintext of your database. Treat it accordingly:
//!
//! - It must never live in the database, in the repository, or in a backup
//!   taken alongside the data it protects.
//! - [`LocalKeyProvider::save_file`] creates it `0600`, and
//!   [`LocalKeyProvider::load_file`] refuses to read a file that anyone but its
//!   owner can open. That check is a guardrail, not protection — anyone who can
//!   read the process's memory has the keys regardless.
//! - Rotating away from a leaked key requires re-encrypting the data; see
//!   `docs/KEY_MANAGEMENT.md`.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use vaulted_crypto::{SecretKey, Zeroizing};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::key::KeyId;
use crate::provider::{KeyVersion, Keyring, LocalKeyProvider};

/// Value of the `format` field, so a keyfile is recognizable on sight.
pub const KEYRING_FORMAT: &str = "vaulted-keyring";

/// Version of the keyfile schema this build reads and writes.
pub const KEYRING_FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct KeyringFile {
    format: String,
    version: u32,
    primary_key_id: String,
    keys: Vec<KeyEntryFile>,
}

#[derive(Serialize, Deserialize)]
struct KeyEntryFile {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<u64>,
    encryption_key: String,
    blind_index_key: String,
}

impl Drop for KeyEntryFile {
    /// The base64 strings hold key material; wipe them rather than leaving
    /// copies in freed heap memory.
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.blind_index_key.zeroize();
    }
}

/// Serializes a keyring to JSON.
///
/// The returned string contains key material and is zeroized on drop. Do not
/// log it, and do not put it anywhere the database's backups reach.
pub fn keyring_to_json(keyring: &Keyring) -> Result<Zeroizing<String>> {
    use crate::key::KeyPurpose;

    let file = KeyringFile {
        format: KEYRING_FORMAT.to_string(),
        version: KEYRING_FORMAT_VERSION,
        primary_key_id: keyring.primary().to_string(),
        keys: keyring
            .versions()
            .map(|version| KeyEntryFile {
                id: version.id().to_string(),
                created_at: version.created_at(),
                encryption_key: BASE64.encode(version.key(KeyPurpose::Encryption).expose_secret()),
                blind_index_key: BASE64.encode(version.key(KeyPurpose::BlindIndex).expose_secret()),
            })
            .collect(),
    };

    let json = serde_json::to_string_pretty(&file).map_err(|_| Error::InvalidKeyring {
        reason: "keyring could not be serialized",
    })?;
    Ok(Zeroizing::new(json))
}

/// Parses a keyring from JSON.
pub fn keyring_from_json(json: &str) -> Result<Keyring> {
    let file: KeyringFile = serde_json::from_str(json).map_err(|_| Error::InvalidKeyring {
        reason: "not a valid keyring document",
    })?;

    if file.format != KEYRING_FORMAT {
        return Err(Error::InvalidKeyring {
            reason: "unrecognized format marker",
        });
    }
    if file.version != KEYRING_FORMAT_VERSION {
        return Err(Error::InvalidKeyring {
            reason: "unsupported keyring version",
        });
    }
    if file.keys.is_empty() {
        return Err(Error::InvalidKeyring {
            reason: "keyring contains no keys",
        });
    }

    let primary = KeyId::new(file.primary_key_id.clone())?;
    let mut keyring: Option<Keyring> = None;

    for entry in &file.keys {
        let version = KeyVersion::new(
            KeyId::new(entry.id.clone())?,
            decode_key(&entry.encryption_key)?,
            decode_key(&entry.blind_index_key)?,
        )
        .with_created_at(entry.created_at);

        match keyring.as_mut() {
            Some(keyring) => keyring.insert(version),
            None => keyring = Some(Keyring::new(version)),
        }
    }

    let mut keyring = keyring.expect("keys were checked to be non-empty");
    keyring
        .set_primary(&primary)
        .map_err(|_| Error::InvalidKeyring {
            reason: "primary_key_id does not name a key in this keyring",
        })?;
    Ok(keyring)
}

fn decode_key(encoded: &str) -> Result<SecretKey> {
    let mut bytes = BASE64.decode(encoded).map_err(|_| Error::InvalidKeyring {
        reason: "key material is not valid base64",
    })?;
    let key = SecretKey::from_slice(&bytes).map_err(|_| Error::InvalidKeyring {
        reason: "key material is not 32 bytes",
    });
    bytes.zeroize();
    key
}

impl LocalKeyProvider {
    /// Loads a provider from a JSON keyring document.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(Self::new(keyring_from_json(json)?))
    }

    /// Serializes the keyring. The result contains key material.
    pub fn to_json(&self) -> Result<Zeroizing<String>> {
        keyring_to_json(&self.keyring())
    }

    /// Loads a keyring from an environment variable holding the JSON document.
    ///
    /// Convenient for containers, and the usual caveats apply: the value is
    /// visible to anything that can read the process environment, and it tends
    /// to end up in orchestrator manifests and crash dumps. A file with
    /// restrictive permissions is the better default.
    pub fn from_env(var: &str) -> Result<Self> {
        let mut json = std::env::var(var).map_err(|_| Error::InvalidKeyring {
            reason: "environment variable is not set or not valid UTF-8",
        })?;
        let provider = Self::from_json(&json);
        json.zeroize();
        provider
    }

    /// Loads a keyring from a file, refusing one that others can read.
    ///
    /// On Unix the file must not be readable or writable by group or other. Use
    /// [`LocalKeyProvider::load_file_ignoring_permissions`] to override, which
    /// you should have a reason for.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        check_permissions(path)?;
        Self::load_file_ignoring_permissions(path)
    }

    /// Loads a keyring from a file without checking its permissions.
    pub fn load_file_ignoring_permissions(path: impl AsRef<Path>) -> Result<Self> {
        let mut json = std::fs::read_to_string(path).map_err(Error::KeyringIo)?;
        let provider = Self::from_json(&json);
        json.zeroize();
        provider
    }

    /// Writes the keyring to a file, owner-readable only.
    pub fn save_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let json = self.to_json()?;
        write_private_file(path, json.as_bytes())
    }
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).map_err(Error::KeyringIo)?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::InsecureKeyringPermissions { mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(path: &Path) -> Result<()> {
    // No portable equivalent of the Unix mode check; make sure the file at
    // least exists so the error is about the file rather than its contents.
    std::fs::metadata(path).map_err(Error::KeyringIo)?;
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(Error::KeyringIo)?;
    // An existing file keeps its original mode, so set it explicitly too.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(Error::KeyringIo)?;
    file.write_all(contents).map_err(Error::KeyringIo)?;
    file.sync_all().map_err(Error::KeyringIo)
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).map_err(Error::KeyringIo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPurpose;
    use crate::provider::KeyProvider;
    use vaulted_crypto::KEY_LEN;

    #[test]
    fn keyring_round_trips_through_json() {
        let provider = LocalKeyProvider::generate().unwrap();
        provider
            .add_generated_key(KeyId::new("key-0002").unwrap(), true)
            .unwrap();

        let json = provider.to_json().unwrap();
        let restored = LocalKeyProvider::from_json(&json).unwrap();

        assert_eq!(
            restored.primary_key_id().unwrap().as_str(),
            "key-0002",
            "the primary marker must survive a round trip"
        );
        assert_eq!(restored.key_ids().unwrap().len(), 2);

        for id in provider.key_ids().unwrap() {
            for purpose in [KeyPurpose::Encryption, KeyPurpose::BlindIndex] {
                assert_eq!(
                    provider.key(&id, purpose).unwrap().expose_secret(),
                    restored.key(&id, purpose).unwrap().expose_secret()
                );
            }
        }
    }

    #[test]
    fn rejects_malformed_documents() {
        let cases = [
            "",
            "{}",
            r#"{"format":"something-else","version":1,"primary_key_id":"key-0001","keys":[]}"#,
            r#"{"format":"vaulted-keyring","version":2,"primary_key_id":"key-0001","keys":[]}"#,
            r#"{"format":"vaulted-keyring","version":1,"primary_key_id":"key-0001","keys":[]}"#,
        ];
        for case in cases {
            assert!(
                matches!(keyring_from_json(case), Err(Error::InvalidKeyring { .. })),
                "{case} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_key_material_of_the_wrong_size() {
        let short = BASE64.encode([0u8; KEY_LEN - 1]);
        let json = format!(
            r#"{{"format":"vaulted-keyring","version":1,"primary_key_id":"key-0001",
                 "keys":[{{"id":"key-0001","encryption_key":"{short}","blind_index_key":"{short}"}}]}}"#
        );
        assert!(matches!(
            keyring_from_json(&json),
            Err(Error::InvalidKeyring {
                reason: "key material is not 32 bytes"
            })
        ));
    }

    #[test]
    fn rejects_a_primary_that_is_not_in_the_keyring() {
        let provider = LocalKeyProvider::generate().unwrap();
        let json = provider.to_json().unwrap().replace("key-0001", "key-0002");
        // Both the marker and the entry were renamed, so this one must load.
        assert!(keyring_from_json(&json).is_ok());

        let json = provider.to_json().unwrap().replace(
            r#""primary_key_id": "key-0001""#,
            r#""primary_key_id": "key-0009""#,
        );
        assert!(matches!(
            keyring_from_json(&json),
            Err(Error::InvalidKeyring { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_written_private_and_read_back() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "vaulted-keyfile-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keyring.json");

        let provider = LocalKeyProvider::generate().unwrap();
        provider.save_file(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "keyfiles must be owner-only");

        let loaded = LocalKeyProvider::load_file(&path).unwrap();
        assert_eq!(
            loaded.primary_key_id().unwrap(),
            provider.primary_key_id().unwrap()
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            LocalKeyProvider::load_file(&path),
            Err(Error::InsecureKeyringPermissions { mode: 0o644 })
        ));
        assert!(LocalKeyProvider::load_file_ignoring_permissions(&path).is_ok());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_files_report_io_errors() {
        assert!(matches!(
            LocalKeyProvider::load_file("/nonexistent/vaulted/keyring.json"),
            Err(Error::KeyringIo(_))
        ));
    }
}
