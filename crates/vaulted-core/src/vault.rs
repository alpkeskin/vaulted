//! The developer-facing API.
//!
//! A [`Vault`] ties together a key provider, a default algorithm and the field
//! policy, and exposes four operations: encrypt, decrypt, blind index, rotate.
//! Nonces, tags, serialization and key lookup stay on this side of the
//! boundary.

use std::sync::Arc;

use vaulted_crypto::{open, seal, Algorithm, Nonce, SecretKey, Zeroizing};

use crate::aad;
use crate::blind_index::BlindIndex;
use crate::error::{BlindIndexError, Error, Result};
use crate::field::{validate_field_name, FieldConfig, FieldRegistry, Normalization};
use crate::format::{EncryptedValue, FORMAT_VERSION};
use crate::key::{KeyId, KeyPurpose};
use crate::provider::KeyProvider;

/// A value ready to be written to the database: ciphertext plus, if the field
/// is searchable, its blind index.
#[derive(Debug, Clone)]
pub struct ProtectedValue {
    /// The encrypted value, for the ciphertext column.
    pub ciphertext: EncryptedValue,
    /// The blind index, for the search column. `None` when the field has no
    /// blind index configured.
    pub blind_index: Option<BlindIndex>,
}

/// The result of re-encrypting a value under the current primary key.
#[derive(Debug, Clone)]
pub struct Rotated {
    /// The value re-encrypted under the primary key.
    pub ciphertext: EncryptedValue,
    /// The recomputed blind index, when the field has one.
    pub blind_index: Option<BlindIndex>,
    /// Whether anything actually changed.
    ///
    /// `false` means the value was already current: no write is needed, which
    /// lets a rotation job skip rows cheaply and stay resumable.
    pub changed: bool,
}

/// Field-level encryption over a key provider.
///
/// ```
/// use vaulted_core::{BlindIndexConfig, FieldConfig, LocalKeyProvider, Normalization, Vault};
///
/// let vault = Vault::builder()
///     .key_provider(LocalKeyProvider::generate()?)
///     .field(
///         FieldConfig::new("users.email")?
///             .with_normalization(Normalization::Email)
///             .with_blind_index(BlindIndexConfig::new()),
///     )
///     .build()?;
///
/// let encrypted = vault.encrypt("users.email", "user@example.com")?;
/// let index = vault.blind_index("users.email", "USER@example.com")?;
///
/// // Store `encrypted.to_string()` and `index.to_hex()`; query by the index.
/// assert_eq!(&*vault.decrypt("users.email", &encrypted)?, "user@example.com");
/// # Ok::<(), vaulted_core::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Vault {
    provider: Arc<dyn KeyProvider>,
    algorithm: Algorithm,
    fields: FieldRegistry,
}

impl Vault {
    /// Starts building a vault.
    pub fn builder() -> VaultBuilder {
        VaultBuilder::new()
    }

    /// The default algorithm for fields without an override.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The declared fields.
    pub fn fields(&self) -> &FieldRegistry {
        &self.fields
    }

    /// The key provider.
    pub fn key_provider(&self) -> &Arc<dyn KeyProvider> {
        &self.provider
    }

    /// The key version new values are encrypted with.
    pub fn primary_key_id(&self) -> Result<KeyId> {
        self.provider.primary_key_id()
    }

    // -- encryption ---------------------------------------------------------

    /// Encrypts a string value for `field`.
    ///
    /// The value is encrypted exactly as given — normalization applies to blind
    /// indexes only, never to stored data.
    pub fn encrypt(&self, field: &str, plaintext: &str) -> Result<EncryptedValue> {
        self.encrypt_bytes(field, plaintext.as_bytes())
    }

    /// Encrypts raw bytes for `field`.
    pub fn encrypt_bytes(&self, field: &str, plaintext: &[u8]) -> Result<EncryptedValue> {
        validate_field_name(field)?;
        let algorithm = self.algorithm_for(field);
        if !algorithm.is_available() {
            return Err(Error::UnsupportedAlgorithm);
        }

        let key_id = self.provider.primary_key_id()?;
        let key = self.provider.key(&key_id, KeyPurpose::Encryption)?;
        // A fresh nonce per operation, from the OS CSPRNG. Nothing in the API
        // lets a caller supply one, because nonce reuse under a shared key is
        // the one mistake AES-GCM does not survive.
        let nonce = Nonce::random(algorithm)?;
        let aad = aad::build(FORMAT_VERSION, &key_id, algorithm, field);

        let sealed = seal(algorithm, &key, &nonce, &aad, plaintext)?;
        let mut payload = Vec::with_capacity(nonce.len() + sealed.len());
        payload.extend_from_slice(nonce.as_bytes());
        payload.extend_from_slice(&sealed);

        EncryptedValue::new(key_id, algorithm, payload)
    }

    // -- decryption ---------------------------------------------------------

    /// Decrypts a value stored in `field` and returns it as text.
    ///
    /// The returned string is zeroized when dropped. Fails with
    /// [`Error::InvalidUtf8`] if the plaintext is not text; use
    /// [`Vault::decrypt_bytes`] for binary values.
    pub fn decrypt(&self, field: &str, value: &EncryptedValue) -> Result<Zeroizing<String>> {
        let bytes = self.decrypt_bytes(field, value)?;
        let text = core::str::from_utf8(&bytes).map_err(|_| Error::InvalidUtf8)?;
        Ok(Zeroizing::new(text.to_owned()))
    }

    /// Decrypts a value stored in `field`.
    ///
    /// `field` must be the same name the value was encrypted under: it is part
    /// of the authenticated associated data, so a ciphertext moved between
    /// columns fails here with [`Error::AuthenticationFailed`], the same error
    /// any other tampering produces.
    pub fn decrypt_bytes(&self, field: &str, value: &EncryptedValue) -> Result<Zeroizing<Vec<u8>>> {
        validate_field_name(field)?;
        let algorithm = value.algorithm();
        let key = self.provider.key(value.key_id(), KeyPurpose::Encryption)?;
        let aad = aad::build(value.version(), value.key_id(), algorithm, field);
        let nonce = value.nonce()?;
        Ok(open(
            algorithm,
            &key,
            &nonce,
            &aad,
            value.ciphertext_with_tag(),
        )?)
    }

    /// Parses and decrypts a serialized value in one step.
    pub fn decrypt_str(&self, field: &str, serialized: &str) -> Result<Zeroizing<String>> {
        self.decrypt(field, &EncryptedValue::parse(serialized)?)
    }

    // -- blind indexes ------------------------------------------------------

    /// Computes the blind index used to search `field` for `value`.
    ///
    /// Requires the field to declare a blind index; see
    /// [`FieldConfig::with_blind_index`]. The value is normalized according to
    /// the field's rule first, so writes and queries agree by construction.
    pub fn blind_index(&self, field: &str, value: &str) -> Result<BlindIndex> {
        validate_field_name(field)?;
        self.blind_index_config(field)?;
        let normalized = self.normalization_for(field).apply(value);
        self.compute_blind_index(field, normalized.as_bytes())
    }

    /// Computes the blind index for raw bytes.
    ///
    /// Only valid for fields whose normalization is [`Normalization::None`];
    /// any other rule operates on text, and silently reinterpreting arbitrary
    /// bytes as text would make indexes disagree between writes and queries.
    pub fn blind_index_bytes(&self, field: &str, value: &[u8]) -> Result<BlindIndex> {
        validate_field_name(field)?;
        let _ = self.blind_index_config(field)?;
        if self.normalization_for(field).requires_text() {
            return Err(BlindIndexError::RequiresText.into());
        }
        self.compute_blind_index(field, value)
    }

    // -- combined -----------------------------------------------------------

    /// Encrypts and, if the field is searchable, indexes a value.
    ///
    /// The convenient shape for an INSERT: one call produces both columns.
    pub fn protect(&self, field: &str, value: &str) -> Result<ProtectedValue> {
        let ciphertext = self.encrypt(field, value)?;
        let blind_index = if self.is_searchable(field) {
            Some(self.blind_index(field, value)?)
        } else {
            None
        };
        Ok(ProtectedValue {
            ciphertext,
            blind_index,
        })
    }

    /// Encrypts and, if the field is searchable, indexes raw bytes.
    pub fn protect_bytes(&self, field: &str, value: &[u8]) -> Result<ProtectedValue> {
        let ciphertext = self.encrypt_bytes(field, value)?;
        let blind_index = if self.is_searchable(field) {
            Some(self.blind_index_bytes(field, value)?)
        } else {
            None
        };
        Ok(ProtectedValue {
            ciphertext,
            blind_index,
        })
    }

    // -- rotation -----------------------------------------------------------

    /// Whether a value would change if re-encrypted now.
    ///
    /// True when it names a key version that is no longer primary, or an
    /// algorithm that is no longer the field's choice.
    pub fn needs_rotation(&self, field: &str, value: &EncryptedValue) -> Result<bool> {
        validate_field_name(field)?;
        let primary = self.provider.primary_key_id()?;
        Ok(*value.key_id() != primary
            || value.algorithm() != self.algorithm_for(field)
            || value.version() != FORMAT_VERSION)
    }

    /// Re-encrypts a value under the current primary key.
    ///
    /// Non-destructive by design: this returns the new value and leaves the old
    /// one untouched. Persisting it — and deciding whether to do so in the same
    /// transaction as the read — is the caller's call, which is what makes a
    /// zero-downtime rotation possible. See `docs/KEY_MANAGEMENT.md`.
    ///
    /// The blind index is recomputed too, because rotating a blind index key
    /// needs the plaintext and this is the one moment a rotation job has it.
    pub fn rotate(&self, field: &str, value: &EncryptedValue) -> Result<Rotated> {
        let plaintext = self.decrypt_bytes(field, value)?;
        let ciphertext = self.encrypt_bytes(field, &plaintext)?;

        let blind_index = match (
            self.is_searchable(field),
            self.normalization_for(field).requires_text(),
        ) {
            (true, true) => {
                let text = core::str::from_utf8(&plaintext).map_err(|_| Error::InvalidUtf8)?;
                Some(self.blind_index(field, text)?)
            }
            (true, false) => Some(self.blind_index_bytes(field, &plaintext)?),
            (false, _) => None,
        };

        Ok(Rotated {
            changed: *value.key_id() != *ciphertext.key_id()
                || value.algorithm() != ciphertext.algorithm()
                || value.version() != ciphertext.version(),
            ciphertext,
            blind_index,
        })
    }

    // -- internals ----------------------------------------------------------

    fn algorithm_for(&self, field: &str) -> Algorithm {
        self.fields
            .get(field)
            .and_then(FieldConfig::algorithm)
            .unwrap_or(self.algorithm)
    }

    fn normalization_for(&self, field: &str) -> Normalization {
        self.fields
            .get(field)
            .map(FieldConfig::normalization)
            .unwrap_or_default()
    }

    /// Whether the field declares a blind index.
    pub fn is_searchable(&self, field: &str) -> bool {
        self.fields
            .get(field)
            .and_then(FieldConfig::blind_index)
            .is_some()
    }

    fn blind_index_config(&self, field: &str) -> Result<&crate::field::BlindIndexConfig> {
        self.fields
            .get(field)
            .and_then(FieldConfig::blind_index)
            .ok_or_else(|| BlindIndexError::NotConfigured.into())
    }

    fn compute_blind_index(&self, field: &str, normalized: &[u8]) -> Result<BlindIndex> {
        let config = self.blind_index_config(field)?;
        let key_id = match config.key_id() {
            Some(pinned) => pinned.clone(),
            None => self.provider.primary_key_id()?,
        };
        let key: SecretKey = self.provider.key(&key_id, KeyPurpose::BlindIndex)?;
        BlindIndex::compute(&key, &key_id, field, normalized, config.output_bytes())
    }
}

/// Builder for [`Vault`].
#[derive(Debug, Default)]
pub struct VaultBuilder {
    provider: Option<Arc<dyn KeyProvider>>,
    algorithm: Option<Algorithm>,
    fields: FieldRegistry,
    /// The first field name declared twice, reported by [`VaultBuilder::build`].
    /// Held rather than returned because the declaring methods are chained.
    duplicate: Option<String>,
}

impl VaultBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the key provider.
    pub fn key_provider<P: KeyProvider + 'static>(mut self, provider: P) -> Self {
        self.provider = Some(Arc::new(provider));
        self
    }

    /// Sets the key provider from an existing handle, for sharing one provider
    /// between vaults.
    pub fn key_provider_arc(mut self, provider: Arc<dyn KeyProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Sets the default algorithm. Defaults to AES-256-GCM.
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Declares a field.
    ///
    /// Declaring the same name twice is an error, raised by [`Self::build`].
    /// Use [`Self::replace_field`] when overriding an earlier declaration is
    /// what you mean.
    pub fn field(mut self, config: FieldConfig) -> Self {
        self.declare(config);
        self
    }

    /// Declares several fields.
    ///
    /// Composing the configurations of several schemas is the expected use, and
    /// the reason a repeated name is refused: two schemas that disagree about
    /// one field would otherwise leave whichever was declared last in force.
    pub fn fields(mut self, configs: impl IntoIterator<Item = FieldConfig>) -> Self {
        for config in configs {
            self.declare(config);
        }
        self
    }

    /// Declares a field, replacing an earlier declaration of the same name.
    ///
    /// The escape hatch from [`Self::field`]'s strictness, for the case it
    /// would otherwise block: a configuration that mostly comes from
    /// `#[derive(Vaulted)]` but needs one field set up by hand, because an
    /// attribute cannot carry it. [`Normalization::Custom`] takes a function
    /// pointer, so it is the usual reason.
    ///
    /// ```
    /// # use vaulted_core::{FieldConfig, Normalization, Vault};
    /// # fn build(derived: Vec<FieldConfig>) -> vaulted_core::Result<()> {
    /// Vault::builder()
    /// #   .key_provider(vaulted_core::LocalKeyProvider::generate()?)
    ///     .fields(derived)
    ///     .replace_field(
    ///         FieldConfig::new("users.email")?
    ///             .with_normalization(Normalization::Custom(|value| value.trim().to_lowercase())),
    ///     )
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Replacing a name that was never declared simply declares it.
    pub fn replace_field(mut self, config: FieldConfig) -> Self {
        self.fields.insert(config);
        self
    }

    /// Records a field, and the first name to arrive twice.
    fn declare(&mut self, config: FieldConfig) {
        if self.duplicate.is_none() && self.fields.get(config.name()).is_some() {
            self.duplicate = Some(config.name().to_string());
        }
        self.fields.insert(config);
    }

    /// Validates the configuration and builds the vault.
    ///
    /// Algorithm availability is checked here, for the default and for every
    /// field override, so an unsupported build fails at startup rather than on
    /// the first write.
    pub fn build(self) -> Result<Vault> {
        if let Some(name) = self.duplicate {
            return Err(Error::DuplicateField { name });
        }
        let provider = self.provider.ok_or(Error::Configuration {
            reason: "a key provider is required",
        })?;
        let algorithm = self.algorithm.unwrap_or_default();
        if !algorithm.is_available() {
            return Err(Error::UnsupportedAlgorithm);
        }
        for config in self.fields.configs() {
            if let Some(algorithm) = config.algorithm() {
                if !algorithm.is_available() {
                    return Err(Error::UnsupportedAlgorithm);
                }
            }
        }
        // Resolving the primary key now turns a misconfigured provider into a
        // startup error instead of a runtime surprise.
        provider.primary_key_id()?;

        Ok(Vault {
            provider,
            algorithm,
            fields: self.fields,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BlindIndexConfig;
    use crate::provider::LocalKeyProvider;

    fn vault() -> Vault {
        Vault::builder()
            .key_provider(LocalKeyProvider::generate().unwrap())
            .field(
                FieldConfig::new("users.email")
                    .unwrap()
                    .with_normalization(Normalization::Email)
                    .with_blind_index(BlindIndexConfig::new()),
            )
            .field(FieldConfig::new("users.phone").unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn round_trip() {
        let vault = vault();
        let value = vault.encrypt("users.email", "user@example.com").unwrap();
        assert_eq!(
            &*vault.decrypt("users.email", &value).unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn the_stored_value_is_never_normalized() {
        // users.email normalizes for indexing; the plaintext must survive
        // untouched, spacing, casing and all.
        let vault = vault();
        let original = "  Alp@Example.COM  ";
        let value = vault.encrypt("users.email", original).unwrap();
        assert_eq!(&*vault.decrypt("users.email", &value).unwrap(), original);
    }

    #[test]
    fn encrypting_twice_produces_different_ciphertext() {
        let vault = vault();
        let a = vault.encrypt("users.email", "same").unwrap();
        let b = vault.encrypt("users.email", "same").unwrap();
        assert_ne!(a.to_string(), b.to_string());
        assert_ne!(a.nonce().unwrap().as_bytes(), b.nonce().unwrap().as_bytes());
        assert_eq!(
            &*vault.decrypt("users.email", &a).unwrap(),
            &*vault.decrypt("users.email", &b).unwrap()
        );
    }

    #[test]
    fn a_ciphertext_cannot_be_moved_to_another_field() {
        let vault = vault();
        let value = vault.encrypt("users.email", "user@example.com").unwrap();
        assert!(matches!(
            vault.decrypt("users.phone", &value),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn a_ciphertext_cannot_be_read_with_another_vaults_keys() {
        let value = vault().encrypt("users.email", "user@example.com").unwrap();
        let other = vault();
        // Same key identifier, different key material: the identifier is a
        // routing hint, not a credential.
        assert_eq!(value.key_id(), &other.primary_key_id().unwrap());
        assert!(matches!(
            other.decrypt("users.email", &value),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let vault = vault();
        let value = vault.encrypt("users.email", "user@example.com").unwrap();
        let mut payload = value.payload().to_vec();
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        let tampered =
            EncryptedValue::new(value.key_id().clone(), value.algorithm(), payload).unwrap();
        assert!(matches!(
            vault.decrypt("users.email", &tampered),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn rewriting_the_header_is_rejected() {
        // The header is authenticated, so relabelling a value as belonging to
        // another key cannot be used to smuggle it past validation.
        let vault = vault();
        let value = vault.encrypt("users.email", "user@example.com").unwrap();
        let relabelled = value.to_string().replace("aes256gcm", "xchacha20poly1305");
        assert!(vault.decrypt_str("users.email", &relabelled).is_err());
    }

    #[test]
    fn undeclared_fields_encrypt_but_do_not_index() {
        let vault = vault();
        let value = vault.encrypt("orders.note", "hello").unwrap();
        assert_eq!(&*vault.decrypt("orders.note", &value).unwrap(), "hello");
        assert!(matches!(
            vault.blind_index("orders.note", "hello"),
            Err(Error::BlindIndex {
                reason: BlindIndexError::NotConfigured
            })
        ));
    }

    #[test]
    fn blind_index_needs_to_be_declared() {
        let vault = vault();
        assert!(matches!(
            vault.blind_index("users.phone", "555"),
            Err(Error::BlindIndex {
                reason: BlindIndexError::NotConfigured
            })
        ));
    }

    #[test]
    fn blind_index_follows_the_fields_normalization() {
        let vault = vault();
        let a = vault
            .blind_index("users.email", "USER@Example.com")
            .unwrap();
        let b = vault
            .blind_index("users.email", " user@example.com ")
            .unwrap();
        assert_eq!(a, b);
        assert_ne!(
            a,
            vault
                .blind_index("users.email", "other@example.com")
                .unwrap()
        );
    }

    #[test]
    fn blind_index_bytes_requires_a_byte_safe_normalization() {
        let vault = Vault::builder()
            .key_provider(LocalKeyProvider::generate().unwrap())
            .field(
                FieldConfig::new("users.token")
                    .unwrap()
                    .with_blind_index(BlindIndexConfig::new()),
            )
            .field(
                FieldConfig::new("users.email")
                    .unwrap()
                    .with_normalization(Normalization::Email)
                    .with_blind_index(BlindIndexConfig::new()),
            )
            .build()
            .unwrap();

        assert!(vault
            .blind_index_bytes("users.token", &[0xff, 0x00])
            .is_ok());
        assert!(matches!(
            vault.blind_index_bytes("users.email", b"x"),
            Err(Error::BlindIndex {
                reason: BlindIndexError::RequiresText
            })
        ));
    }

    #[test]
    fn protect_produces_both_columns() {
        let vault = vault();
        let protected = vault.protect("users.email", "user@example.com").unwrap();
        assert!(protected.blind_index.is_some());
        assert_eq!(
            protected.blind_index.unwrap(),
            vault
                .blind_index("users.email", "user@example.com")
                .unwrap()
        );

        let unindexed = vault.protect("users.phone", "555").unwrap();
        assert!(unindexed.blind_index.is_none());
    }

    #[test]
    fn field_names_are_validated_on_every_entry_point() {
        let vault = vault();
        let value = vault.encrypt("users.email", "x").unwrap();
        for bad in ["", "users email", &"f".repeat(129)] {
            assert!(matches!(
                vault.encrypt(bad, "x"),
                Err(Error::InvalidFieldName)
            ));
            assert!(matches!(
                vault.decrypt(bad, &value),
                Err(Error::InvalidFieldName)
            ));
            assert!(matches!(
                vault.blind_index(bad, "x"),
                Err(Error::InvalidFieldName)
            ));
        }
    }

    #[test]
    fn builder_requires_a_provider() {
        assert!(matches!(
            Vault::builder().build(),
            Err(Error::Configuration { .. })
        ));
    }

    #[test]
    #[cfg(feature = "xchacha")]
    fn per_field_algorithm_override_is_used() {
        let vault = Vault::builder()
            .key_provider(LocalKeyProvider::generate().unwrap())
            .field(
                FieldConfig::new("users.email")
                    .unwrap()
                    .with_algorithm(Algorithm::XChaCha20Poly1305),
            )
            .build()
            .unwrap();

        let value = vault.encrypt("users.email", "user@example.com").unwrap();
        assert_eq!(value.algorithm(), Algorithm::XChaCha20Poly1305);
        assert_eq!(
            vault.encrypt("users.phone", "555").unwrap().algorithm(),
            Algorithm::Aes256Gcm
        );
        assert_eq!(
            &*vault.decrypt("users.email", &value).unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn non_utf8_values_round_trip_as_bytes() {
        let vault = vault();
        let value = vault
            .encrypt_bytes("users.avatar", &[0xff, 0xfe, 0x00])
            .unwrap();
        assert_eq!(
            vault
                .decrypt_bytes("users.avatar", &value)
                .unwrap()
                .as_slice(),
            &[0xff, 0xfe, 0x00]
        );
        assert!(matches!(
            vault.decrypt("users.avatar", &value),
            Err(Error::InvalidUtf8)
        ));
    }

    #[test]
    fn empty_values_are_supported() {
        let vault = vault();
        let value = vault.encrypt("users.email", "").unwrap();
        assert_eq!(value.plaintext_len(), 0);
        assert_eq!(&**vault.decrypt("users.email", &value).unwrap(), "");
    }
}
