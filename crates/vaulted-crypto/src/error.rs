//! Error type for the primitive layer.
//!
//! Error messages are intentionally coarse: they never contain plaintext, key
//! material, nonces or any other value that could help an attacker.

/// Result alias used across this crate.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Failures that can occur inside the primitive layer.
///
/// The variants deliberately carry no data. Anything more specific than
/// "this operation failed" risks turning an error channel into an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// A key of the wrong length was supplied.
    #[error("invalid key length")]
    InvalidKeyLength,

    /// A nonce of the wrong length was supplied for the selected algorithm.
    #[error("invalid nonce")]
    InvalidNonce,

    /// The ciphertext is shorter than the authentication tag it must contain.
    #[error("ciphertext is malformed")]
    MalformedCiphertext,

    /// The authentication tag did not verify.
    ///
    /// This covers every failed-decryption case: wrong key, tampered
    /// ciphertext, tampered tag and mismatched associated data all produce
    /// exactly this error, and callers must not try to tell them apart.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// The operating system random number generator failed.
    #[error("secure random number generation failed")]
    Rng,

    /// The requested algorithm was not compiled into this build.
    #[error("algorithm not supported by this build")]
    UnsupportedAlgorithm,
}
