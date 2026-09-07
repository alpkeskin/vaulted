//! Implementing [`KeyProvider`], the extension point that connects Vaulted to
//! whatever holds your keys.
//!
//! ```sh
//! cargo run -p vaulted-examples --example custom_key_provider
//! ```
//!
//! The provider below sketches envelope encryption: it holds *wrapped* data
//! keys, asks a "KMS" to unwrap one the first time it is needed, and caches the
//! result. A real implementation would call AWS KMS, GCP KMS, Azure Key Vault
//! or HashiCorp Vault at the marked line; nothing else about the shape changes,
//! and nothing above this layer changes at all.
//!
//! ```text
//!   master key (never leaves the KMS)
//!         │  Decrypt(wrapped_dek)
//!         ▼
//!   data key ──► KeyProvider::key(key_id, purpose) ──► Vault
//! ```

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use vaulted_core::{Error, FieldConfig, KeyId, KeyProvider, KeyPurpose, KeyVersion, Result, Vault};

/// A key provider backed by wrapped data keys and an unwrapping service.
#[derive(Debug)]
struct EnvelopeKeyProvider {
    primary: KeyId,
    /// What you would actually store in config: ciphertext blobs, safe at rest
    /// because only the KMS can unwrap them.
    wrapped: HashMap<KeyId, Vec<u8>>,
    /// Unwrapped keys, kept in memory so that one KMS call serves many rows.
    ///
    /// This cache is the reason the trait can be called per operation without
    /// making every INSERT a network round trip. Give it a TTL in production.
    cache: RwLock<HashMap<KeyId, Arc<KeyVersion>>>,
}

impl EnvelopeKeyProvider {
    fn new(primary: KeyId, wrapped: HashMap<KeyId, Vec<u8>>) -> Self {
        Self {
            primary,
            wrapped,
            cache: RwLock::new(HashMap::new()),
        }
    }

    fn version(&self, key_id: &KeyId) -> Result<Arc<KeyVersion>> {
        if let Some(cached) = self.cache.read().unwrap().get(key_id) {
            return Ok(Arc::clone(cached));
        }

        let wrapped = self.wrapped.get(key_id).ok_or_else(|| Error::UnknownKey {
            key_id: key_id.to_string(),
        })?;

        // >>> A real provider calls the KMS here, e.g. kms.decrypt(wrapped). <<<
        let root = pretend_to_unwrap(wrapped)?;

        // One root secret per version, split into an encryption key and a blind
        // index key by HKDF. The two are computationally independent, which is
        // what the design requires; a provider that can fetch two separate
        // secrets should do that instead and use `KeyVersion::new`.
        let version = Arc::new(KeyVersion::from_root(key_id.clone(), &root)?);
        self.cache
            .write()
            .unwrap()
            .insert(key_id.clone(), Arc::clone(&version));
        Ok(version)
    }
}

impl KeyProvider for EnvelopeKeyProvider {
    fn primary_key_id(&self) -> Result<KeyId> {
        Ok(self.primary.clone())
    }

    fn key(&self, key_id: &KeyId, purpose: KeyPurpose) -> Result<vaulted_core::SecretKey> {
        Ok(self.version(key_id)?.key(purpose))
    }

    fn key_ids(&self) -> Result<Vec<KeyId>> {
        // A provider that cannot enumerate its keys may return an empty list;
        // only tooling uses this.
        let mut ids: Vec<KeyId> = self.wrapped.keys().cloned().collect();
        ids.sort();
        Ok(ids)
    }
}

/// Stands in for `kms.Decrypt`. Deterministic so the example is reproducible;
/// a real unwrap returns key material the KMS alone could produce.
fn pretend_to_unwrap(wrapped: &[u8]) -> Result<vaulted_core::SecretKey> {
    let mut root = [0u8; 32];
    for (i, slot) in root.iter_mut().enumerate() {
        *slot = wrapped[i % wrapped.len()] ^ (i as u8);
    }
    vaulted_core::SecretKey::from_slice(&root).map_err(|err| Error::KeyProvider(Box::new(err)))
}

fn main() -> Result<()> {
    let key_0001 = KeyId::new("kms.dek-0001")?;
    let key_0002 = KeyId::new("kms.dek-0002")?;

    let mut wrapped = HashMap::new();
    wrapped.insert(key_0001.clone(), b"wrapped-blob-for-dek-0001".to_vec());
    wrapped.insert(key_0002.clone(), b"wrapped-blob-for-dek-0002".to_vec());

    let provider = Arc::new(EnvelopeKeyProvider::new(key_0001.clone(), wrapped));
    let vault = Vault::builder()
        .key_provider_arc(provider.clone())
        .field(FieldConfig::new("users.email")?)
        .build()?;

    let value = vault.encrypt("users.email", "alp@example.com")?;
    println!("encrypted under {}", value.key_id());
    println!("plaintext       {}", *vault.decrypt("users.email", &value)?);

    // A value naming a key the provider cannot resolve fails loudly, and names
    // the key so an operator can fix the configuration.
    let elsewhere = "vlt:v1:kms.dek-9999:aes256gcm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    match vault.decrypt_str("users.email", elsewhere) {
        Err(Error::UnknownKey { key_id }) => println!("unknown key reported: {key_id}"),
        other => println!("unexpected: {other:?}"),
    }

    println!("available keys  {:?}", provider.key_ids()?);
    Ok(())
}
