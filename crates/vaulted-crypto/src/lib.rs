//! Cryptographic primitives for Vaulted.
//!
//! This crate is the only place in the workspace that touches a cipher. It
//! wraps well-reviewed RustCrypto implementations behind a small surface that
//! is hard to misuse:
//!
//! - [`SecretKey`] holds 256-bit keys, zeroizes on drop and never prints itself.
//! - [`Nonce`] can only be built at the length its [`Algorithm`] requires, and
//!   the ordinary way to get one is [`Nonce::random`].
//! - [`seal`] and [`open`] always take associated data, so authenticating
//!   context is the default rather than an option.
//! - Every decryption failure returns the same error, so the API cannot be used
//!   as an oracle to distinguish a wrong key from tampered data.
//!
//! No cryptography is implemented here. Higher-level concerns — ciphertext
//! framing, key lookup, blind indexes, field policy — live in `vaulted-core`.
//!
//! ```
//! use vaulted_crypto::{open, seal, Algorithm, Nonce, SecretKey};
//!
//! let key = SecretKey::generate()?;
//! let nonce = Nonce::random(Algorithm::Aes256Gcm)?;
//! let sealed = seal(Algorithm::Aes256Gcm, &key, &nonce, b"users.email", b"user@example.com")?;
//! let opened = open(Algorithm::Aes256Gcm, &key, &nonce, b"users.email", &sealed)?;
//! assert_eq!(opened.as_slice(), b"user@example.com");
//! # Ok::<(), vaulted_crypto::CryptoError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod aead;
pub mod error;
pub mod kdf;
pub mod key;
pub mod mac;
pub mod rand;

pub use aead::{open, seal, Algorithm, Nonce, MAX_NONCE_LEN, TAG_LEN};
pub use error::{CryptoError, Result};
pub use kdf::derive_subkey;
pub use key::{SecretKey, KEY_LEN};
pub use mac::{constant_time_eq, hmac_sha256, HMAC_SHA256_LEN};
pub use rand::fill_random;

/// Re-exported so downstream crates can hold plaintext in buffers that are
/// wiped on drop without depending on `zeroize` directly.
pub use zeroize::Zeroizing;
