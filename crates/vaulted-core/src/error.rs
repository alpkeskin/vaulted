//! Errors.
//!
//! Two rules govern everything in this module:
//!
//! 1. No variant ever carries plaintext, key material, a nonce or a ciphertext.
//!    `Failed to decrypt "user@example.com"` is a data leak; `decryption
//!    failed` is an error message.
//! 2. Failures that an attacker could probe are collapsed into a single
//!    variant. A wrong key, a flipped ciphertext bit and a mismatched field
//!    name all surface as [`Error::AuthenticationFailed`], so the error channel
//!    cannot be used as an oracle.
//!
//! Structural problems that an attacker already knows about — a truncated
//! string, an unknown format version — stay distinct, because telling those
//! apart helps operators without helping anyone else.

use vaulted_crypto::CryptoError;

/// Result alias used across this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Everything that can go wrong in Vaulted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The serialized value is not a well-formed Vaulted ciphertext.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// The value uses a ciphertext format version this build does not know.
    #[error("unsupported ciphertext format version: {version}")]
    UnsupportedVersion {
        /// The version found in the value.
        version: u32,
    },

    /// The value names an algorithm this build cannot perform.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The payload was not valid unpadded URL-safe base64.
    #[error("invalid encoding")]
    InvalidEncoding,

    /// The embedded nonce is missing or the wrong size for the algorithm.
    #[error("invalid nonce")]
    InvalidNonce,

    /// Decryption failed.
    ///
    /// Wrong key, tampered ciphertext, tampered tag, or a ciphertext presented
    /// under a different field name than the one it was encrypted for. These
    /// are deliberately indistinguishable.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// The key referenced by a ciphertext is not available from the provider.
    #[error("unknown key: {key_id}")]
    UnknownKey {
        /// The key identifier that could not be resolved. Key *identifiers* are
        /// not secret — they are stored in plain sight inside every ciphertext.
        key_id: String,
    },

    /// A key identifier is malformed.
    ///
    /// Identifiers are limited to `A-Z a-z 0-9 . _ -`, 1 to 64 characters. The
    /// character set is restricted so an identifier can never contain the
    /// format separator, and so that a hostile ciphertext cannot smuggle
    /// control characters into logs.
    #[error("invalid key identifier")]
    InvalidKeyId,

    /// The key provider failed.
    #[error("key provider error")]
    KeyProvider(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A blind index could not be produced.
    #[error("blind index error: {reason}")]
    BlindIndex {
        /// What was wrong with the request. Never contains the value itself.
        reason: BlindIndexError,
    },

    /// A field name is malformed.
    ///
    /// Field names take part in the associated data, so they must be stable,
    /// printable and free of the format separator.
    #[error("invalid field name")]
    InvalidFieldName,

    /// The same field name was declared twice while building a vault.
    ///
    /// Only one of the two configurations could survive, and a field whose
    /// normalization or blind index settings are not the ones you wrote does
    /// not fail loudly — it writes indexes that later lookups do not match. So
    /// the second declaration is an error rather than an overwrite.
    #[error("field declared twice: {name}")]
    DuplicateField {
        /// The field name declared more than once. Field names are not secret;
        /// they travel in plain sight inside every ciphertext.
        name: String,
    },

    /// Decrypted bytes were requested as a string but are not valid UTF-8.
    #[error("decrypted value is not valid UTF-8")]
    InvalidUtf8,

    /// The operating system random number generator failed.
    #[error("secure random number generation failed")]
    Rng,

    /// A key or key file could not be read or written.
    #[error("keyring I/O error")]
    KeyringIo(#[source] std::io::Error),

    /// A keyring file is malformed.
    #[error("invalid keyring: {reason}")]
    InvalidKeyring {
        /// What was structurally wrong. Never contains key material.
        reason: &'static str,
    },

    /// The vault was configured in a way that cannot work.
    #[error("invalid configuration: {reason}")]
    Configuration {
        /// What is wrong with the configuration.
        reason: &'static str,
    },

    /// A keyring file is readable by users other than its owner.
    #[error("keyring file has insecure permissions (mode {mode:04o}); expected owner-only access")]
    InsecureKeyringPermissions {
        /// The permission bits found on the file.
        mode: u32,
    },
}

/// Why a blind index could not be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BlindIndexError {
    /// The field has no blind index configured.
    ///
    /// Blind indexes leak equality and frequency, so they are opt-in per field
    /// rather than on by default. See `docs/BLIND_INDEXES.md`.
    #[error("no blind index is configured for this field")]
    NotConfigured,

    /// Raw bytes were passed to a field whose normalization expects text.
    #[error("field normalization requires UTF-8 input")]
    RequiresText,

    /// The configured output length is outside the supported range.
    #[error("invalid output length")]
    InvalidOutputLength,

    /// The serialized blind index is malformed.
    #[error("malformed blind index")]
    Malformed,
}

impl From<CryptoError> for Error {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::AuthenticationFailed => Error::AuthenticationFailed,
            CryptoError::InvalidNonce => Error::InvalidNonce,
            CryptoError::MalformedCiphertext => Error::InvalidCiphertext,
            CryptoError::UnsupportedAlgorithm => Error::UnsupportedAlgorithm,
            CryptoError::Rng => Error::Rng,
            // A key of the wrong length can only come from a provider handing
            // out malformed material; it is not a property of the ciphertext.
            CryptoError::InvalidKeyLength => Error::KeyProvider(Box::new(err)),
            _ => Error::InvalidCiphertext,
        }
    }
}

impl From<BlindIndexError> for Error {
    fn from(reason: BlindIndexError) -> Self {
        Error::BlindIndex { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_never_mention_values() {
        // A crude but useful guard: rendering every error must not produce
        // anything that looks like user data.
        let errors = [
            Error::InvalidCiphertext,
            Error::UnsupportedVersion { version: 9 },
            Error::UnsupportedAlgorithm,
            Error::InvalidEncoding,
            Error::InvalidNonce,
            Error::AuthenticationFailed,
            Error::UnknownKey {
                key_id: "key-0001".into(),
            },
            Error::InvalidKeyId,
            Error::InvalidFieldName,
            Error::InvalidUtf8,
            Error::Rng,
            Error::BlindIndex {
                reason: BlindIndexError::NotConfigured,
            },
        ];
        for err in errors {
            let rendered = err.to_string();
            assert!(!rendered.contains('@'), "{rendered}");
            assert!(!rendered.to_lowercase().contains("secret"), "{rendered}");
        }
    }

    #[test]
    fn crypto_failures_collapse_to_authentication_failed() {
        assert!(matches!(
            Error::from(CryptoError::AuthenticationFailed),
            Error::AuthenticationFailed
        ));
    }
}
