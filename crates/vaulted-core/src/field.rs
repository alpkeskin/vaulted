//! Per-field policy: normalization, blind index settings, algorithm overrides.

use std::borrow::Cow;
use std::collections::HashMap;

use vaulted_crypto::{Algorithm, HMAC_SHA256_LEN};

use crate::error::{BlindIndexError, Error, Result};
use crate::key::KeyId;

/// Maximum length of a field name, in bytes.
pub const MAX_FIELD_NAME_LEN: usize = 128;

/// Shortest blind index output allowed, in bytes.
///
/// Below 64 bits, collisions stop being a theoretical concern and start being a
/// correctness problem for equality lookups.
pub const MIN_BLIND_INDEX_BYTES: usize = 8;

/// Longest blind index output, in bytes: the full HMAC-SHA256 tag.
pub const MAX_BLIND_INDEX_BYTES: usize = HMAC_SHA256_LEN;

/// Validates a field name.
///
/// Field names are part of the authenticated associated data, so they are part
/// of the on-disk contract: renaming a field makes existing values for it
/// undecryptable under the new name. Pick names like `users.email` and treat
/// them as permanent.
pub fn validate_field_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_FIELD_NAME_LEN {
        return Err(Error::InvalidFieldName);
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(Error::InvalidFieldName);
    }
    Ok(())
}

/// How a value is canonicalized before a blind index is computed.
///
/// # This never touches encrypted data
///
/// Normalization applies **only** to blind index input. The value that gets
/// encrypted is always the exact bytes the caller passed in, so `decrypt` gives
/// back what was stored, character for character. Normalizing before encryption
/// would silently rewrite user data — the one thing an encryption layer must
/// never do.
///
/// The trade-off is the usual one for case-insensitive search: `Alp@x.com` and
/// `alp@x.com` share a blind index, so a lookup finds both, and an attacker who
/// learns one plaintext learns it for every row with that index.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub enum Normalization {
    /// Use the input exactly as given. The default, and the only choice that
    /// cannot surprise anyone.
    #[default]
    None,
    /// Strip leading and trailing ASCII/Unicode whitespace.
    Trim,
    /// Lowercase, using Unicode's locale-independent mapping.
    Lowercase,
    /// Trim, then lowercase.
    TrimLowercase,
    /// Email addresses: trim, then lowercase the whole address.
    ///
    /// Strictly, RFC 5321 makes the local part case-sensitive; in practice
    /// mail providers do not, and applications treat addresses as
    /// case-insensitive. This matches that expectation. What matters most is
    /// that writes and queries agree, which is why the rule lives in the field
    /// configuration rather than at each call site.
    Email,
    /// Keep ASCII digits only.
    ///
    /// Intended for phone numbers, where `+90 555 111 22 33`,
    /// `905551112233` and `(0555) 111 22 33` should all match. Note that
    /// dropping `+` merges numbers that differ only by country prefix
    /// notation; if that matters, normalize to E.164 in your application and
    /// use [`Normalization::None`].
    DigitsOnly,
    /// An application-supplied rule.
    ///
    /// Must be pure and stable forever: changing it invalidates every blind
    /// index already written with it.
    Custom(fn(&str) -> String),
}

impl core::fmt::Debug for Normalization {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Trim => "Trim",
            Self::Lowercase => "Lowercase",
            Self::TrimLowercase => "TrimLowercase",
            Self::Email => "Email",
            Self::DigitsOnly => "DigitsOnly",
            Self::Custom(_) => "Custom",
        })
    }
}

impl Normalization {
    /// Applies the rule, borrowing when it changes nothing.
    pub fn apply<'a>(&self, value: &'a str) -> Cow<'a, str> {
        match self {
            Self::None => Cow::Borrowed(value),
            Self::Trim => Cow::Borrowed(value.trim()),
            Self::Lowercase => Cow::Owned(value.to_lowercase()),
            Self::TrimLowercase | Self::Email => Cow::Owned(value.trim().to_lowercase()),
            Self::DigitsOnly => Cow::Owned(value.chars().filter(char::is_ascii_digit).collect()),
            Self::Custom(f) => Cow::Owned(f(value)),
        }
    }

    /// Whether this rule needs text, rather than arbitrary bytes.
    pub fn requires_text(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Blind index settings for one field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindIndexConfig {
    key_id: Option<KeyId>,
    output_bytes: usize,
}

impl Default for BlindIndexConfig {
    fn default() -> Self {
        Self {
            key_id: None,
            output_bytes: MAX_BLIND_INDEX_BYTES,
        }
    }
}

impl BlindIndexConfig {
    /// Default settings: the provider's primary key, full-length output.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins the blind index to a specific key version.
    ///
    /// Worth doing. Blind index keys and encryption keys rotate on different
    /// schedules, because rotating an encryption key needs only the ciphertext,
    /// while rotating a blind index key needs the plaintext of every indexed
    /// row. Pinning here means routine encryption-key rotation does not
    /// invalidate your indexes. See `docs/KEY_MANAGEMENT.md`.
    pub fn with_key_id(mut self, key_id: KeyId) -> Self {
        self.key_id = Some(key_id);
        self
    }

    /// Truncates the index to `bytes` (8..=32).
    ///
    /// Shorter indexes take less space and make deliberate collisions more
    /// likely, which blurs equality slightly — at the cost of false positives
    /// that your query has to filter out after decrypting. The default is full
    /// length; treat truncation as a considered choice, not a size
    /// optimization.
    pub fn with_output_bytes(mut self, bytes: usize) -> Result<Self> {
        if !(MIN_BLIND_INDEX_BYTES..=MAX_BLIND_INDEX_BYTES).contains(&bytes) {
            return Err(BlindIndexError::InvalidOutputLength.into());
        }
        self.output_bytes = bytes;
        Ok(self)
    }

    /// The pinned key version, if any.
    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    /// The configured output length in bytes.
    pub fn output_bytes(&self) -> usize {
        self.output_bytes
    }
}

/// Policy for one encrypted field.
#[derive(Debug, Clone)]
pub struct FieldConfig {
    name: String,
    normalization: Normalization,
    blind_index: Option<BlindIndexConfig>,
    algorithm: Option<Algorithm>,
}

impl FieldConfig {
    /// Declares a field. The name is validated immediately.
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_field_name(&name)?;
        Ok(Self {
            name,
            normalization: Normalization::None,
            blind_index: None,
            algorithm: None,
        })
    }

    /// Sets the blind index normalization rule.
    pub fn with_normalization(mut self, normalization: Normalization) -> Self {
        self.normalization = normalization;
        self
    }

    /// Enables equality search for this field.
    ///
    /// Opt-in on purpose: a blind index publishes which rows share a value, and
    /// how often each value occurs. That is a real disclosure, and it should be
    /// a decision, not a default. See `docs/BLIND_INDEXES.md`.
    pub fn with_blind_index(mut self, config: BlindIndexConfig) -> Self {
        self.blind_index = Some(config);
        self
    }

    /// Overrides the vault's algorithm for this field.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// The field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The normalization rule.
    pub fn normalization(&self) -> Normalization {
        self.normalization
    }

    /// The blind index settings, if search is enabled.
    pub fn blind_index(&self) -> Option<&BlindIndexConfig> {
        self.blind_index.as_ref()
    }

    /// The algorithm override, if any.
    pub fn algorithm(&self) -> Option<Algorithm> {
        self.algorithm
    }
}

/// The set of declared fields.
///
/// Fields that were never declared still encrypt and decrypt, using the default
/// policy: no normalization, no blind index. Encryption of an unknown field is
/// safe, so refusing it would only push people toward turning validation off.
/// Blind indexing an unknown field is not safe by default, and is refused.
#[derive(Debug, Clone, Default)]
pub struct FieldRegistry {
    fields: HashMap<String, FieldConfig>,
}

impl FieldRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a field configuration.
    pub fn insert(&mut self, config: FieldConfig) {
        self.fields.insert(config.name.clone(), config);
    }

    /// Looks up a declared field.
    pub fn get(&self, name: &str) -> Option<&FieldConfig> {
        self.fields.get(name)
    }

    /// The number of declared fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether no field has been declared.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Declared field names, in no particular order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }

    /// Declared field configurations, in no particular order.
    pub fn configs(&self) -> impl Iterator<Item = &FieldConfig> {
        self.fields.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_are_validated() {
        for name in ["users.email", "a", "orders/line_items.note", "A-1"] {
            assert!(validate_field_name(name).is_ok(), "{name} should be valid");
        }
        for name in [
            "",
            "users email",
            "users\nemail",
            "kullanıcı.eposta",
            &"f".repeat(129),
        ] {
            assert!(
                matches!(validate_field_name(name), Err(Error::InvalidFieldName)),
                "{name:?} should be rejected"
            );
        }
    }

    #[test]
    fn normalization_rules_do_what_they_say() {
        assert_eq!(Normalization::None.apply("  Alp@X.com "), "  Alp@X.com ");
        assert_eq!(Normalization::Trim.apply("  Alp@X.com "), "Alp@X.com");
        assert_eq!(Normalization::Lowercase.apply(" Alp@X.com "), " alp@x.com ");
        assert_eq!(
            Normalization::Email.apply(" ALP@Example.COM "),
            "alp@example.com"
        );
        assert_eq!(
            Normalization::DigitsOnly.apply("+90 (555) 111 22 33"),
            "905551112233"
        );
        assert_eq!(
            Normalization::Custom(|s| s.replace('-', "")).apply("123-456"),
            "123456"
        );
    }

    #[test]
    fn none_normalization_borrows_instead_of_allocating() {
        assert!(matches!(
            Normalization::None.apply("value"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn blind_index_output_length_is_bounded() {
        assert!(BlindIndexConfig::new().with_output_bytes(8).is_ok());
        assert!(BlindIndexConfig::new().with_output_bytes(32).is_ok());
        assert!(BlindIndexConfig::new().with_output_bytes(7).is_err());
        assert!(BlindIndexConfig::new().with_output_bytes(33).is_err());
        assert!(BlindIndexConfig::new().with_output_bytes(0).is_err());
        assert_eq!(BlindIndexConfig::default().output_bytes(), 32);
    }

    #[test]
    fn blind_index_is_off_until_asked_for() {
        let field = FieldConfig::new("users.email").unwrap();
        assert!(field.blind_index().is_none());
        assert!(matches!(field.normalization(), Normalization::None));
        assert!(field
            .with_blind_index(BlindIndexConfig::new())
            .blind_index()
            .is_some());
    }

    #[test]
    fn registry_lookup() {
        let mut registry = FieldRegistry::new();
        assert!(registry.is_empty());
        registry.insert(FieldConfig::new("users.email").unwrap());
        assert_eq!(registry.len(), 1);
        assert!(registry.get("users.email").is_some());
        assert!(registry.get("users.phone").is_none());
    }
}
