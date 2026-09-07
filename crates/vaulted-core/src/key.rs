//! Key identifiers and key purposes.

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, Result};

/// Maximum length of a key identifier, in characters.
pub const MAX_KEY_ID_LEN: usize = 64;

/// A key identifier, as embedded in every ciphertext.
///
/// Identifiers are **not secret**: they travel in plain sight inside stored
/// values so that a ciphertext can always say which key it needs. They are
/// restricted to `A-Z a-z 0-9 . _ -` for two reasons: the format separator
/// (`:`) must never appear inside one, and a ciphertext parsed from a hostile
/// database dump must not be able to inject control characters into logs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(String);

impl KeyId {
    /// Validates and wraps a key identifier.
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > MAX_KEY_ID_LEN {
            return Err(Error::InvalidKeyId);
        }
        if !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(Error::InvalidKeyId);
        }
        Ok(Self(id))
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for KeyId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// What a key is used for.
///
/// A key version is a logical bundle; each purpose within it must resolve to
/// independent key material. Encrypting and blind-indexing with the same bytes
/// would mean that compromising the search index also compromises the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyPurpose {
    /// AEAD key used to encrypt and decrypt field values.
    Encryption,
    /// HMAC-SHA256 key used to compute blind indexes.
    BlindIndex,
}

impl KeyPurpose {
    /// A stable label, used as HKDF domain separation by providers that derive
    /// per-purpose keys from a single root secret. Never change these strings.
    pub const fn hkdf_info(self) -> &'static [u8] {
        match self {
            Self::Encryption => b"vaulted/v1/encryption",
            Self::BlindIndex => b"vaulted/v1/blind-index",
        }
    }

    /// A short name for diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encryption => "encryption",
            Self::BlindIndex => "blind-index",
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reasonable_identifiers() {
        for id in ["key-0001", "a", "kms.key_01", "A1", &"k".repeat(64)] {
            assert!(KeyId::new(id).is_ok(), "{id} should be valid");
        }
    }

    #[test]
    fn rejects_separators_and_control_characters() {
        for id in [
            "",
            "key:0001",
            "key 0001",
            "key\n0001",
            "key/0001",
            "kéy",
            "\u{0}",
            &"k".repeat(65),
        ] {
            assert!(
                matches!(KeyId::new(id), Err(Error::InvalidKeyId)),
                "{id:?} should be rejected"
            );
        }
    }

    #[test]
    fn purposes_have_distinct_stable_labels() {
        assert_eq!(KeyPurpose::Encryption.hkdf_info(), b"vaulted/v1/encryption");
        assert_eq!(
            KeyPurpose::BlindIndex.hkdf_info(),
            b"vaulted/v1/blind-index"
        );
        assert_ne!(
            KeyPurpose::Encryption.hkdf_info(),
            KeyPurpose::BlindIndex.hkdf_info()
        );
    }
}
