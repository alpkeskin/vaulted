//! Key providers.
//!
//! Vaulted never stores keys in the database it protects — that would make the
//! whole exercise pointless, since the threat model starts with an attacker
//! holding a full dump. Instead, a [`KeyProvider`] resolves the key identifier
//! embedded in a ciphertext to key material, from wherever your deployment
//! keeps it.
//!
//! The MVP ships one implementation, [`LocalKeyProvider`], which holds keys in
//! process memory and can load them from a file or an environment variable. It
//! is suitable for development, tests and single-node deployments where the key
//! file is managed by something outside the database.
//!
//! # Envelope encryption
//!
//! The trait is shaped so that a KMS-backed provider fits without changing
//! anything above it. Such a provider holds *wrapped* data keys, calls the KMS
//! to unwrap them, and caches the result:
//!
//! ```text
//!   KMS master key
//!         │  unwrap
//!         ▼
//!   data encryption key ──► KeyProvider::key(key_id, purpose)
//! ```
//!
//! `key_id` is the caller's handle for a key version; how a provider maps that
//! to bytes — a local file, an unwrapped DEK, a Vault lease — is its business.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::RwLock;

use vaulted_crypto::{derive_subkey, SecretKey};

use crate::error::{Error, Result};
use crate::key::{KeyId, KeyPurpose};

/// HKDF salt used when both subkeys are derived from a single root secret.
const KEYRING_HKDF_SALT: &[u8] = b"vaulted/v1/keyring";

/// Resolves key identifiers to key material.
///
/// Implementations must be cheap enough to call once per operation, or do their
/// own caching. They must never log, print or serialize key material, and their
/// errors must not describe it.
pub trait KeyProvider: fmt::Debug + Send + Sync {
    /// The key version new values should be encrypted with.
    ///
    /// Changing what this returns is how a rotation begins: new writes use the
    /// new key immediately, while old values keep naming the key they need.
    fn primary_key_id(&self) -> Result<KeyId>;

    /// Resolves key material for a key version and purpose.
    ///
    /// Must return [`Error::UnknownKey`] for a version it does not have, so
    /// that a value encrypted under a retired key produces a clear operational
    /// error rather than an authentication failure.
    fn key(&self, key_id: &KeyId, purpose: KeyPurpose) -> Result<SecretKey>;

    /// Every key version this provider can resolve, oldest first where known.
    ///
    /// Used by tooling (`vaulted key list`, `vaulted status`). Providers that
    /// cannot enumerate — a KMS that resolves on demand — may return an empty
    /// list; that is not an error.
    fn key_ids(&self) -> Result<Vec<KeyId>> {
        Ok(Vec::new())
    }
}

/// One key version: independent material for each purpose.
#[derive(Clone)]
pub struct KeyVersion {
    id: KeyId,
    created_at: Option<u64>,
    encryption_key: SecretKey,
    blind_index_key: SecretKey,
}

impl KeyVersion {
    /// Builds a version from two independently generated keys.
    pub fn new(id: KeyId, encryption_key: SecretKey, blind_index_key: SecretKey) -> Self {
        Self {
            id,
            created_at: now_unix_seconds(),
            encryption_key,
            blind_index_key,
        }
    }

    /// Generates a version with fresh, independent keys.
    ///
    /// The two keys share no material at all — not even a common root. That is
    /// the strongest form of the separation the design requires.
    pub fn generate(id: KeyId) -> Result<Self> {
        Ok(Self::new(
            id,
            SecretKey::generate().map_err(|_| Error::Rng)?,
            SecretKey::generate().map_err(|_| Error::Rng)?,
        ))
    }

    /// Derives a version from a single root secret using HKDF-SHA256.
    ///
    /// For providers that get one secret per version from elsewhere — an
    /// unwrapped KMS data key, a Vault lease. The subkeys are computationally
    /// independent, though they do share a compromise domain: whoever learns
    /// the root learns both.
    pub fn from_root(id: KeyId, root: &SecretKey) -> Result<Self> {
        let encryption_key =
            derive_subkey(root, KEYRING_HKDF_SALT, KeyPurpose::Encryption.hkdf_info())
                .map_err(Error::from)?;
        let blind_index_key =
            derive_subkey(root, KEYRING_HKDF_SALT, KeyPurpose::BlindIndex.hkdf_info())
                .map_err(Error::from)?;
        Ok(Self::new(id, encryption_key, blind_index_key))
    }

    /// The identifier of this version.
    pub fn id(&self) -> &KeyId {
        &self.id
    }

    /// When the version was created, as Unix seconds, if known.
    pub fn created_at(&self) -> Option<u64> {
        self.created_at
    }

    /// Sets the creation timestamp (used when loading a keyring).
    pub fn with_created_at(mut self, created_at: Option<u64>) -> Self {
        self.created_at = created_at;
        self
    }

    /// The key for a purpose.
    pub fn key(&self, purpose: KeyPurpose) -> SecretKey {
        match purpose {
            KeyPurpose::Encryption => self.encryption_key.clone(),
            KeyPurpose::BlindIndex => self.blind_index_key.clone(),
        }
    }
}

impl fmt::Debug for KeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyVersion")
            .field("id", &self.id.as_str())
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// An ordered set of key versions with one marked primary.
#[derive(Debug, Clone)]
pub struct Keyring {
    primary: KeyId,
    versions: BTreeMap<KeyId, KeyVersion>,
}

impl Keyring {
    /// Creates a keyring holding a single version, which becomes primary.
    pub fn new(version: KeyVersion) -> Self {
        let primary = version.id().clone();
        let mut versions = BTreeMap::new();
        versions.insert(primary.clone(), version);
        Self { primary, versions }
    }

    /// Creates a keyring with one freshly generated version, `key-0001`.
    pub fn generate() -> Result<Self> {
        Ok(Self::new(KeyVersion::generate(KeyId::new("key-0001")?)?))
    }

    /// Adds a version. Existing values remain decryptable.
    pub fn insert(&mut self, version: KeyVersion) {
        self.versions.insert(version.id().clone(), version);
    }

    /// Makes `key_id` the version used for new encryptions.
    pub fn set_primary(&mut self, key_id: &KeyId) -> Result<()> {
        if !self.versions.contains_key(key_id) {
            return Err(Error::UnknownKey {
                key_id: key_id.to_string(),
            });
        }
        self.primary = key_id.clone();
        Ok(())
    }

    /// The primary key identifier.
    pub fn primary(&self) -> &KeyId {
        &self.primary
    }

    /// Looks up a version.
    pub fn get(&self, key_id: &KeyId) -> Option<&KeyVersion> {
        self.versions.get(key_id)
    }

    /// All versions, ordered by identifier.
    pub fn versions(&self) -> impl Iterator<Item = &KeyVersion> {
        self.versions.values()
    }

    /// The number of versions held.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Whether the keyring is empty. Only possible before the first insert.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Suggests the next identifier in the `key-NNNN` sequence.
    pub fn next_key_id(&self) -> Result<KeyId> {
        let highest = self
            .versions
            .keys()
            .filter_map(|id| id.as_str().strip_prefix("key-"))
            .filter_map(|n| n.parse::<u32>().ok())
            .max()
            .unwrap_or(0);
        KeyId::new(format!("key-{:04}", highest.saturating_add(1)))
    }
}

/// A keyring held in process memory.
///
/// # Where the keys come from
///
/// [`LocalKeyProvider::from_env`] and [`LocalKeyProvider::load_file`] are the
/// two supported paths, and both put the operator in charge of protecting the
/// material: file permissions, a secrets manager writing the file at boot, a
/// systemd credential. What this provider will never do is read keys from the
/// database it is protecting.
///
/// # When not to use it
///
/// It has no audit trail, no access control and no hardware protection. For
/// production, put a KMS behind the [`KeyProvider`] trait instead; nothing above
/// this layer has to change.
#[derive(Debug)]
pub struct LocalKeyProvider {
    keyring: RwLock<Keyring>,
}

impl LocalKeyProvider {
    /// Wraps an existing keyring.
    pub fn new(keyring: Keyring) -> Self {
        Self {
            keyring: RwLock::new(keyring),
        }
    }

    /// Creates a provider with one freshly generated key version.
    ///
    /// Convenient for tests and examples. Keys generated this way live only as
    /// long as the process, so anything encrypted with them is unrecoverable
    /// afterwards — which is exactly what you want in a test, and never what
    /// you want in production.
    pub fn generate() -> Result<Self> {
        Ok(Self::new(Keyring::generate()?))
    }

    /// A snapshot of the keyring.
    pub fn keyring(&self) -> Keyring {
        self.read().clone()
    }

    /// Adds a freshly generated key version, optionally promoting it.
    pub fn add_generated_key(&self, key_id: KeyId, make_primary: bool) -> Result<()> {
        let version = KeyVersion::generate(key_id.clone())?;
        let mut keyring = self.write();
        keyring.insert(version);
        if make_primary {
            keyring.set_primary(&key_id)?;
        }
        Ok(())
    }

    /// Promotes an existing key version to primary.
    pub fn set_primary(&self, key_id: &KeyId) -> Result<()> {
        self.write().set_primary(key_id)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Keyring> {
        // A poisoned lock means another thread panicked while holding it. The
        // keyring is a plain map, so the data is still consistent; refusing to
        // decrypt anything ever again would be the worse outcome.
        self.keyring.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Keyring> {
        self.keyring.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl KeyProvider for LocalKeyProvider {
    fn primary_key_id(&self) -> Result<KeyId> {
        Ok(self.read().primary().clone())
    }

    fn key(&self, key_id: &KeyId, purpose: KeyPurpose) -> Result<SecretKey> {
        self.read()
            .get(key_id)
            .map(|version| version.key(purpose))
            .ok_or_else(|| Error::UnknownKey {
                key_id: key_id.to_string(),
            })
    }

    fn key_ids(&self) -> Result<Vec<KeyId>> {
        Ok(self.read().versions().map(|v| v.id().clone()).collect())
    }
}

fn now_unix_seconds() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_versions_use_independent_keys() {
        let version = KeyVersion::generate(KeyId::new("key-0001").unwrap()).unwrap();
        assert_ne!(
            version.key(KeyPurpose::Encryption).expose_secret(),
            version.key(KeyPurpose::BlindIndex).expose_secret()
        );
    }

    #[test]
    fn derived_versions_separate_purposes() {
        let root = SecretKey::from_bytes([3u8; 32]);
        let version = KeyVersion::from_root(KeyId::new("key-0001").unwrap(), &root).unwrap();
        let enc = version.key(KeyPurpose::Encryption);
        let bi = version.key(KeyPurpose::BlindIndex);
        assert_ne!(enc.expose_secret(), bi.expose_secret());
        assert_ne!(enc.expose_secret(), root.expose_secret());
        assert_ne!(bi.expose_secret(), root.expose_secret());

        // Deterministic: the same root always yields the same subkeys.
        let again = KeyVersion::from_root(KeyId::new("key-0001").unwrap(), &root).unwrap();
        assert_eq!(
            again.key(KeyPurpose::Encryption).expose_secret(),
            enc.expose_secret()
        );
    }

    #[test]
    fn debug_output_hides_key_material() {
        let version = KeyVersion::generate(KeyId::new("key-0001").unwrap()).unwrap();
        let rendered = format!("{version:?}");
        assert!(rendered.contains("key-0001"));
        assert!(!rendered.contains("SecretKey"));

        let provider = LocalKeyProvider::generate().unwrap();
        assert!(!format!("{provider:?}").contains("expose"));
    }

    #[test]
    fn unknown_keys_are_reported_as_such() {
        let provider = LocalKeyProvider::generate().unwrap();
        let missing = KeyId::new("key-9999").unwrap();
        assert!(matches!(
            provider.key(&missing, KeyPurpose::Encryption),
            Err(Error::UnknownKey { .. })
        ));
        assert!(matches!(
            provider.set_primary(&missing),
            Err(Error::UnknownKey { .. })
        ));
    }

    #[test]
    fn adding_a_key_does_not_change_the_primary_unless_asked() {
        let provider = LocalKeyProvider::generate().unwrap();
        let first = provider.primary_key_id().unwrap();

        let second = KeyId::new("key-0002").unwrap();
        provider.add_generated_key(second.clone(), false).unwrap();
        assert_eq!(provider.primary_key_id().unwrap(), first);

        provider.set_primary(&second).unwrap();
        assert_eq!(provider.primary_key_id().unwrap(), second);

        // The old version stays resolvable, which is what keeps existing
        // ciphertext readable during a rotation.
        assert!(provider.key(&first, KeyPurpose::Encryption).is_ok());
        assert_eq!(provider.key_ids().unwrap().len(), 2);
    }

    #[test]
    fn next_key_id_continues_the_sequence() {
        let keyring = Keyring::generate().unwrap();
        assert_eq!(keyring.primary().as_str(), "key-0001");
        assert_eq!(keyring.next_key_id().unwrap().as_str(), "key-0002");

        let mut keyring = keyring;
        keyring.insert(KeyVersion::generate(KeyId::new("key-0042").unwrap()).unwrap());
        assert_eq!(keyring.next_key_id().unwrap().as_str(), "key-0043");

        // Identifiers that are not part of the sequence are simply ignored.
        keyring.insert(KeyVersion::generate(KeyId::new("kms.prod").unwrap()).unwrap());
        assert_eq!(keyring.next_key_id().unwrap().as_str(), "key-0043");
    }
}
