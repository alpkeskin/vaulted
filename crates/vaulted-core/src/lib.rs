//! Field-level encryption for databases.
//!
//! Vaulted lets an application keep working with plaintext while the database
//! only ever holds ciphertext:
//!
//! ```text
//! application ──plaintext──► Vaulted ──ciphertext──► PostgreSQL
//! ```
//!
//! ```
//! use vaulted_core::{BlindIndexConfig, FieldConfig, LocalKeyProvider, Normalization, Vault};
//!
//! let vault = Vault::builder()
//!     .key_provider(LocalKeyProvider::generate()?)   // a KMS in production
//!     .field(
//!         FieldConfig::new("users.email")?
//!             .with_normalization(Normalization::Email)
//!             .with_blind_index(BlindIndexConfig::new()),
//!     )
//!     .build()?;
//!
//! let row = vault.protect("users.email", "user@example.com")?;
//! // INSERT INTO users (email_ciphertext, email_blind_index) VALUES ($1, $2)
//! let ciphertext = row.ciphertext.to_string();
//! let index = row.blind_index.unwrap().to_hex();
//!
//! // SELECT ... WHERE email_blind_index = $1
//! let lookup = vault.blind_index("users.email", "USER@Example.com")?.to_hex();
//! assert_eq!(lookup, index);
//!
//! assert_eq!(&*vault.decrypt_str("users.email", &ciphertext)?, "user@example.com");
//! # Ok::<(), vaulted_core::Error>(())
//! ```
//!
//! # What the design commits to
//!
//! - **Authenticated encryption, always.** AES-256-GCM by default,
//!   XChaCha20-Poly1305 optionally. There is no unauthenticated mode.
//! - **A random nonce per operation**, drawn from the OS CSPRNG. No API accepts
//!   a caller-supplied nonce.
//! - **Ciphertext carries its own routing information** — format version, key
//!   version, algorithm — so key rotation and format migration are ordinary
//!   operations rather than flag days. See [`format`].
//! - **Values are bound to their field** through the associated data, so a
//!   ciphertext copied from `users.email` to `users.phone` fails to decrypt.
//!   See [`aad`].
//! - **Search is opt-in.** A blind index reveals which rows share a value; that
//!   should be a decision. See [`blind_index`].
//! - **Encryption keys and blind index keys are separate material.** See
//!   [`provider`].
//! - **Plaintext never appears in an error, a `Debug` impl or a log line.**
//!
//! # What it does not do
//!
//! Encryption at the field level is not database confidentiality. An attacker
//! with a dump still sees value lengths, row counts, relationships, and — for
//! indexed columns — which rows share a value and how often each value occurs.
//! Read `docs/THREAT_MODEL.md` before deciding what to encrypt.

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod aad;
pub mod blind_index;
pub mod error;
pub mod field;
pub mod format;
mod hex;
pub mod key;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod provider;
pub mod schema;
#[cfg(any(feature = "sqlx-0_8", feature = "sqlx-0_9"))]
pub mod sqlx;
pub mod vault;

#[cfg(feature = "local-provider")]
pub mod keyfile;

pub use blind_index::BlindIndex;
pub use error::{BlindIndexError, Error, Result};
pub use field::{BlindIndexConfig, FieldConfig, FieldRegistry, Normalization};
pub use format::{EncryptedValue, FORMAT_PREFIX, FORMAT_VERSION};
pub use key::{KeyId, KeyPurpose};
pub use schema::{EncryptedField, VaultedSchema};

#[cfg(feature = "derive")]
pub use vaulted_derive::Vaulted;

// Generated code refers to `::vaulted_core`, which is not otherwise a name
// inside this crate. The alias lets the derive be used in our own tests and
// doc examples on the same footing as a dependent's.
#[cfg(feature = "derive")]
extern crate self as vaulted_core;
pub use provider::{KeyProvider, KeyVersion, Keyring, LocalKeyProvider};
pub use vault::{ProtectedValue, Rotated, Vault, VaultBuilder};

/// The AEAD algorithms Vaulted can use.
pub use vaulted_crypto::Algorithm;

/// A 256-bit symmetric key, as returned by a [`KeyProvider`].
pub use vaulted_crypto::SecretKey;

/// A buffer that wipes itself when dropped. Decrypted values come back in one.
pub use vaulted_crypto::Zeroizing;
