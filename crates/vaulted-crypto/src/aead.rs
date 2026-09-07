//! Authenticated encryption with associated data.
//!
//! Two algorithms are supported. Both are standard constructions from the
//! RustCrypto project; Vaulted implements no cryptography of its own here, it
//! only wires the pieces together in a way that is hard to misuse.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::key::SecretKey;
use crate::rand::fill_random;

/// The longest nonce any supported algorithm uses (XChaCha20-Poly1305).
pub const MAX_NONCE_LEN: usize = 24;

/// Length of the authentication tag, in bytes. Both algorithms use 128 bits.
pub const TAG_LEN: usize = 16;

/// An AEAD algorithm.
///
/// The wire names are part of the ciphertext format and must never change:
/// stored ciphertext refers to them forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Algorithm {
    /// AES-256-GCM with a 96-bit random nonce. The default.
    #[default]
    Aes256Gcm,
    /// XChaCha20-Poly1305 with a 192-bit random nonce.
    XChaCha20Poly1305,
}

impl Algorithm {
    /// The identifier written into the ciphertext format.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256gcm",
            Self::XChaCha20Poly1305 => "xchacha20poly1305",
        }
    }

    /// Parses a wire identifier.
    ///
    /// This recognises every algorithm the format defines, including ones that
    /// were not compiled into this build; those fail later, at use time, with
    /// [`CryptoError::UnsupportedAlgorithm`]. Keeping parsing and support
    /// separate means a build without a feature reports "not supported by this
    /// build" instead of "unknown algorithm".
    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "aes256gcm" => Some(Self::Aes256Gcm),
            "xchacha20poly1305" => Some(Self::XChaCha20Poly1305),
            _ => None,
        }
    }

    /// Nonce length in bytes.
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// Authentication tag length in bytes.
    pub const fn tag_len(self) -> usize {
        TAG_LEN
    }

    /// Whether this build can actually perform the algorithm.
    ///
    /// AES-256-GCM is always available; XChaCha20-Poly1305 depends on the
    /// `xchacha` feature.
    pub const fn is_available(self) -> bool {
        match self {
            Self::Aes256Gcm => true,
            Self::XChaCha20Poly1305 => cfg!(feature = "xchacha"),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

/// A nonce sized for a specific algorithm.
///
/// Backed by a fixed-size buffer so that encrypting does not allocate for it.
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce {
    buf: [u8; MAX_NONCE_LEN],
    len: usize,
}

impl Nonce {
    /// Draws a fresh random nonce of the length `algorithm` requires.
    ///
    /// Nonces are random rather than counter-based: Vaulted has no coordinated
    /// state between processes, so a counter could not be kept unique. For
    /// AES-256-GCM's 96-bit nonce, keep the number of encryptions under a
    /// single key well below 2^32 (see `docs/THREAT_MODEL.md`); rotate keys to
    /// stay there.
    pub fn random(algorithm: Algorithm) -> Result<Self> {
        let len = algorithm.nonce_len();
        let mut buf = [0u8; MAX_NONCE_LEN];
        fill_random(&mut buf[..len])?;
        Ok(Self { buf, len })
    }

    /// Wraps existing nonce bytes, checking the length against `algorithm`.
    pub fn from_slice(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != algorithm.nonce_len() {
            return Err(CryptoError::InvalidNonce);
        }
        let mut buf = [0u8; MAX_NONCE_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            buf,
            len: bytes.len(),
        })
    }

    /// The nonce bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The nonce length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the nonce is empty. Never true for a valid nonce.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A nonce is not secret, but printing it invites it into logs next to
        // the ciphertext it belongs to. Keep it out.
        write!(f, "Nonce({} bytes)", self.len)
    }
}

/// Borrows nonce bytes as the fixed-size array the AEAD traits take.
///
/// The length was already checked against the algorithm, so the conversion
/// only fails if that check was wrong.
fn nonce_array<N: aes_gcm::aead::array::ArraySize>(
    bytes: &[u8],
) -> Result<&aes_gcm::aead::array::Array<u8, N>> {
    bytes.try_into().map_err(|_| CryptoError::InvalidNonce)
}

/// Borrows tag bytes as the fixed-size array the AEAD traits take.
fn tag_array<N: aes_gcm::aead::array::ArraySize>(
    bytes: &[u8],
) -> Result<&aes_gcm::aead::array::Array<u8, N>> {
    bytes
        .try_into()
        .map_err(|_| CryptoError::MalformedCiphertext)
}

/// Encrypts `plaintext`, authenticating `aad` alongside it.
///
/// Returns `ciphertext || tag`. The nonce is *not* included; the caller owns
/// framing (see `vaulted_core::format`).
pub fn seal(
    algorithm: Algorithm,
    key: &SecretKey,
    nonce: &Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != algorithm.nonce_len() {
        return Err(CryptoError::InvalidNonce);
    }

    let mut buf = Vec::with_capacity(plaintext.len() + algorithm.tag_len());
    buf.extend_from_slice(plaintext);

    let tag = match algorithm {
        Algorithm::Aes256Gcm => {
            use aes_gcm::aead::{AeadInOut, KeyInit};
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key.expose_secret())
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            cipher
                .encrypt_inout_detached(
                    nonce_array(nonce.as_bytes())?,
                    aad,
                    buf.as_mut_slice().into(),
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?
                .to_vec()
        }
        #[cfg(feature = "xchacha")]
        Algorithm::XChaCha20Poly1305 => {
            use chacha20poly1305::aead::{AeadInOut, KeyInit};
            let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key.expose_secret())
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            cipher
                .encrypt_inout_detached(
                    nonce_array(nonce.as_bytes())?,
                    aad,
                    buf.as_mut_slice().into(),
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?
                .to_vec()
        }
        #[allow(unreachable_patterns)]
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    };

    debug_assert_eq!(tag.len(), algorithm.tag_len());
    buf.extend_from_slice(&tag);
    Ok(buf)
}

/// Decrypts `ciphertext_and_tag`, verifying it against `aad`.
///
/// Every failure mode — wrong key, flipped ciphertext bit, altered tag,
/// mismatched associated data — returns [`CryptoError::AuthenticationFailed`].
/// The returned plaintext is zeroized on drop.
pub fn open(
    algorithm: Algorithm,
    key: &SecretKey,
    nonce: &Nonce,
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != algorithm.nonce_len() {
        return Err(CryptoError::InvalidNonce);
    }
    let tag_len = algorithm.tag_len();
    if ciphertext_and_tag.len() < tag_len {
        return Err(CryptoError::MalformedCiphertext);
    }

    let split = ciphertext_and_tag.len() - tag_len;
    let (body, tag) = ciphertext_and_tag.split_at(split);
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(body.to_vec());

    match algorithm {
        Algorithm::Aes256Gcm => {
            use aes_gcm::aead::{AeadInOut, KeyInit};
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(key.expose_secret())
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            cipher
                .decrypt_inout_detached(
                    nonce_array(nonce.as_bytes())?,
                    aad,
                    buf.as_mut_slice().into(),
                    tag_array(tag)?,
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?;
        }
        #[cfg(feature = "xchacha")]
        Algorithm::XChaCha20Poly1305 => {
            use chacha20poly1305::aead::{AeadInOut, KeyInit};
            let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key.expose_secret())
                .map_err(|_| CryptoError::InvalidKeyLength)?;
            cipher
                .decrypt_inout_detached(
                    nonce_array(nonce.as_bytes())?,
                    aad,
                    buf.as_mut_slice().into(),
                    tag_array(tag)?,
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?;
        }
        #[allow(unreachable_patterns)]
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHMS: &[Algorithm] = &[Algorithm::Aes256Gcm, Algorithm::XChaCha20Poly1305];

    fn available() -> impl Iterator<Item = Algorithm> {
        ALGORITHMS.iter().copied().filter(|a| a.is_available())
    }

    #[test]
    fn round_trip() {
        for alg in available() {
            let key = SecretKey::generate().unwrap();
            let nonce = Nonce::random(alg).unwrap();
            let sealed = seal(alg, &key, &nonce, b"aad", b"attack at dawn").unwrap();
            let opened = open(alg, &key, &nonce, b"aad", &sealed).unwrap();
            assert_eq!(opened.as_slice(), b"attack at dawn");
        }
    }

    #[test]
    fn empty_plaintext_round_trips() {
        for alg in available() {
            let key = SecretKey::generate().unwrap();
            let nonce = Nonce::random(alg).unwrap();
            let sealed = seal(alg, &key, &nonce, b"", b"").unwrap();
            assert_eq!(sealed.len(), alg.tag_len());
            assert!(open(alg, &key, &nonce, b"", &sealed).unwrap().is_empty());
        }
    }

    #[test]
    fn tampering_with_ciphertext_fails() {
        for alg in available() {
            let key = SecretKey::generate().unwrap();
            let nonce = Nonce::random(alg).unwrap();
            let sealed = seal(alg, &key, &nonce, b"aad", b"secret").unwrap();

            for i in 0..sealed.len() {
                let mut broken = sealed.clone();
                broken[i] ^= 0x01;
                assert_eq!(
                    open(alg, &key, &nonce, b"aad", &broken).unwrap_err(),
                    CryptoError::AuthenticationFailed,
                    "byte {i} of {alg} ciphertext was not authenticated"
                );
            }
        }
    }

    #[test]
    fn wrong_key_nonce_or_aad_fails() {
        for alg in available() {
            let key = SecretKey::generate().unwrap();
            let nonce = Nonce::random(alg).unwrap();
            let sealed = seal(alg, &key, &nonce, b"users.email", b"secret").unwrap();

            let other_key = SecretKey::generate().unwrap();
            assert_eq!(
                open(alg, &other_key, &nonce, b"users.email", &sealed).unwrap_err(),
                CryptoError::AuthenticationFailed
            );

            let other_nonce = Nonce::random(alg).unwrap();
            assert_eq!(
                open(alg, &key, &other_nonce, b"users.email", &sealed).unwrap_err(),
                CryptoError::AuthenticationFailed
            );

            assert_eq!(
                open(alg, &key, &nonce, b"users.phone", &sealed).unwrap_err(),
                CryptoError::AuthenticationFailed
            );
        }
    }

    #[test]
    fn truncated_ciphertext_is_rejected_without_panicking() {
        for alg in available() {
            let key = SecretKey::generate().unwrap();
            let nonce = Nonce::random(alg).unwrap();
            let sealed = seal(alg, &key, &nonce, b"", b"secret").unwrap();
            for len in 0..alg.tag_len() {
                assert_eq!(
                    open(alg, &key, &nonce, b"", &sealed[..len]).unwrap_err(),
                    CryptoError::MalformedCiphertext
                );
            }
        }
    }

    #[test]
    fn nonce_length_is_enforced() {
        for alg in available() {
            let key = SecretKey::generate().unwrap();
            let wrong = Nonce {
                buf: [0u8; MAX_NONCE_LEN],
                len: alg.nonce_len() - 1,
            };
            assert_eq!(
                seal(alg, &key, &wrong, b"", b"x").unwrap_err(),
                CryptoError::InvalidNonce
            );
            assert!(Nonce::from_slice(alg, &[0u8; 3]).is_err());
            assert!(Nonce::from_slice(alg, &vec![0u8; alg.nonce_len()]).is_ok());
        }
    }

    #[test]
    fn wire_names_round_trip_and_are_stable() {
        for alg in ALGORITHMS {
            assert_eq!(Algorithm::from_wire_name(alg.wire_name()), Some(*alg));
        }
        assert_eq!(Algorithm::Aes256Gcm.wire_name(), "aes256gcm");
        assert_eq!(
            Algorithm::XChaCha20Poly1305.wire_name(),
            "xchacha20poly1305"
        );
        assert_eq!(Algorithm::from_wire_name("rot13"), None);
        assert_eq!(Algorithm::from_wire_name("AES256GCM"), None);
    }

    #[test]
    fn nonces_are_unique_across_calls() {
        for alg in ALGORITHMS {
            let a = Nonce::random(*alg).unwrap();
            let b = Nonce::random(*alg).unwrap();
            assert_ne!(a.as_bytes(), b.as_bytes());
            assert_eq!(a.len(), alg.nonce_len());
        }
    }
}
