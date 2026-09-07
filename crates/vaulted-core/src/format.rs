//! The versioned ciphertext format.
//!
//! ```text
//! vlt:v1:key-0001:aes256gcm:BASE64URL(nonce || ciphertext || tag)
//! ^   ^  ^        ^         ^
//! |   |  |        |         payload, unpadded URL-safe base64
//! |   |  |        AEAD algorithm
//! |   |  key identifier
//! |   format version
//! magic prefix
//! ```
//!
//! Everything a decryptor needs to route the value is in the clear header:
//! format version, key identifier and algorithm. Nothing in the header is
//! secret, and all of it is authenticated — the header is folded into the AAD
//! (see [`crate::aad`]), so an attacker cannot rewrite `aes256gcm` to something
//! else, or re-label a ciphertext as belonging to another key, without the
//! authentication tag failing.
//!
//! The full grammar and its stability guarantees are in
//! `docs/CIPHERTEXT_FORMAT.md`.
//!
//! Parsing treats its input as hostile: it comes from a database, which is
//! exactly the thing the threat model assumes an attacker controls.

use core::fmt;
use core::str::FromStr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use vaulted_crypto::{Algorithm, Nonce};

use crate::error::{Error, Result};
use crate::key::KeyId;

/// The magic prefix every serialized value starts with.
pub const FORMAT_PREFIX: &str = "vlt";

/// The format version this build writes.
pub const FORMAT_VERSION: u32 = 1;

/// Field separator in the serialized form.
pub const SEPARATOR: char = ':';

/// The number of `:`-separated segments in a serialized value.
const SEGMENTS: usize = 5;

/// An encrypted field value: header plus authenticated payload.
///
/// Construct one with [`crate::Vault::encrypt`], store it with
/// [`fmt::Display`], and read it back with [`str::parse`].
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedValue {
    version: u32,
    key_id: KeyId,
    algorithm: Algorithm,
    /// `nonce || ciphertext || tag`
    payload: Vec<u8>,
}

impl EncryptedValue {
    /// Assembles a value from its parts, checking the payload's shape.
    ///
    /// `payload` must be `nonce || ciphertext || tag` for `algorithm`.
    pub fn new(key_id: KeyId, algorithm: Algorithm, payload: Vec<u8>) -> Result<Self> {
        Self::with_version(FORMAT_VERSION, key_id, algorithm, payload)
    }

    fn with_version(
        version: u32,
        key_id: KeyId,
        algorithm: Algorithm,
        payload: Vec<u8>,
    ) -> Result<Self> {
        if payload.len() < algorithm.nonce_len() + algorithm.tag_len() {
            return Err(Error::InvalidCiphertext);
        }
        Ok(Self {
            version,
            key_id,
            algorithm,
            payload,
        })
    }

    /// The format version of this value.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The key this value was encrypted with.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The algorithm this value was encrypted with.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The nonce, borrowed from the payload.
    pub fn nonce(&self) -> Result<Nonce> {
        Nonce::from_slice(self.algorithm, &self.payload[..self.algorithm.nonce_len()])
            .map_err(Error::from)
    }

    /// The ciphertext and its authentication tag, without the nonce.
    pub fn ciphertext_with_tag(&self) -> &[u8] {
        &self.payload[self.algorithm.nonce_len()..]
    }

    /// The raw payload: `nonce || ciphertext || tag`.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The length of the encrypted plaintext, in bytes.
    ///
    /// This is not secret — an attacker holding the ciphertext can compute it
    /// just as easily. It is exposed so that callers can reason about the
    /// length leakage the format has by design.
    pub fn plaintext_len(&self) -> usize {
        self.payload.len() - self.algorithm.nonce_len() - self.algorithm.tag_len()
    }

    /// The clear-text header, exactly as it appears in the serialized form.
    ///
    /// This string is what gets authenticated as associated data.
    pub fn header(&self) -> String {
        format!(
            "{FORMAT_PREFIX}{SEPARATOR}v{}{SEPARATOR}{}{SEPARATOR}{}",
            self.version,
            self.key_id,
            self.algorithm.wire_name()
        )
    }

    /// Parses a serialized value.
    ///
    /// Strict by construction: exactly five segments, a known prefix, a numeric
    /// version, a validated key identifier, a known algorithm, canonical
    /// unpadded URL-safe base64, and a payload long enough to hold a nonce and
    /// a tag. Anything else is rejected before a key is ever fetched.
    pub fn parse(s: &str) -> Result<Self> {
        let mut segments = s.split(SEPARATOR);
        let mut next = || segments.next().ok_or(Error::InvalidCiphertext);

        let prefix = next()?;
        let version = next()?;
        let key_id = next()?;
        let algorithm = next()?;
        let payload = next()?;
        // A sixth segment means the value is not one of ours, or has been
        // tampered with. Either way, refuse it rather than guess.
        if segments.next().is_some() {
            return Err(Error::InvalidCiphertext);
        }
        debug_assert_eq!(SEGMENTS, 5);

        if prefix != FORMAT_PREFIX {
            return Err(Error::InvalidCiphertext);
        }

        let version = version
            .strip_prefix('v')
            .and_then(|digits| digits.parse::<u32>().ok())
            .ok_or(Error::InvalidCiphertext)?;
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion { version });
        }

        let key_id = KeyId::new(key_id)?;

        // Unknown names and known-but-not-compiled-in names are told apart, so
        // that a build without a feature reports the truth.
        let algorithm = Algorithm::from_wire_name(algorithm).ok_or(Error::UnsupportedAlgorithm)?;
        if !algorithm.is_available() {
            return Err(Error::UnsupportedAlgorithm);
        }

        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| Error::InvalidEncoding)?;

        Self::with_version(version, key_id, algorithm, payload)
    }
}

impl fmt::Display for EncryptedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{SEPARATOR}{}",
            self.header(),
            URL_SAFE_NO_PAD.encode(&self.payload)
        )
    }
}

impl fmt::Debug for EncryptedValue {
    /// Prints the header and payload size, never the payload.
    ///
    /// Ciphertext in a log is not a disclosure by itself, but logs get shipped
    /// to places databases do not, and a ciphertext next to its field name is a
    /// gift to an attacker with a key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedValue")
            .field("version", &self.version)
            .field("key_id", &self.key_id.as_str())
            .field("algorithm", &self.algorithm.wire_name())
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl FromStr for EncryptedValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for EncryptedValue {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for EncryptedValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EncryptedValue {
        // 12-byte nonce + 3-byte body + 16-byte tag.
        let payload = (0..31u8).collect::<Vec<_>>();
        EncryptedValue::new(
            KeyId::new("key-0001").unwrap(),
            Algorithm::Aes256Gcm,
            payload,
        )
        .unwrap()
    }

    #[test]
    fn display_matches_the_documented_shape() {
        let value = sample();
        let rendered = value.to_string();
        assert!(
            rendered.starts_with("vlt:v1:key-0001:aes256gcm:"),
            "{rendered}"
        );
        assert_eq!(rendered.split(':').count(), SEGMENTS);
        assert_eq!(value.header(), "vlt:v1:key-0001:aes256gcm");
    }

    #[test]
    fn round_trips_through_string() {
        let value = sample();
        let parsed: EncryptedValue = value.to_string().parse().unwrap();
        assert_eq!(parsed, value);
        assert_eq!(parsed.key_id().as_str(), "key-0001");
        assert_eq!(parsed.algorithm(), Algorithm::Aes256Gcm);
        assert_eq!(parsed.plaintext_len(), 3);
        assert_eq!(
            parsed.nonce().unwrap().as_bytes(),
            &(0..12u8).collect::<Vec<_>>()[..]
        );
    }

    #[test]
    fn debug_does_not_include_the_payload() {
        let rendered = format!("{:?}", sample());
        assert!(rendered.contains("payload_len"), "{rendered}");
        assert!(!rendered.contains("payload:"), "{rendered}");
        assert!(!rendered.contains('['), "{rendered}");
    }

    #[test]
    fn rejects_structurally_broken_values() {
        type Expectation = fn(&Error) -> bool;
        let cases: &[(&str, Expectation)] = &[
            ("", |e| matches!(e, Error::InvalidCiphertext)),
            ("vlt:v1:key-0001:aes256gcm", |e| {
                matches!(e, Error::InvalidCiphertext)
            }),
            ("vlt:v1:key-0001:aes256gcm:AAAA:extra", |e| {
                matches!(e, Error::InvalidCiphertext)
            }),
            ("xxx:v1:key-0001:aes256gcm:AAAA", |e| {
                matches!(e, Error::InvalidCiphertext)
            }),
            ("vlt:1:key-0001:aes256gcm:AAAA", |e| {
                matches!(e, Error::InvalidCiphertext)
            }),
            ("vlt:vx:key-0001:aes256gcm:AAAA", |e| {
                matches!(e, Error::InvalidCiphertext)
            }),
            ("vlt:v2:key-0001:aes256gcm:AAAA", |e| {
                matches!(e, Error::UnsupportedVersion { version: 2 })
            }),
            ("vlt:v1:key 0001:aes256gcm:AAAA", |e| {
                matches!(e, Error::InvalidKeyId)
            }),
            ("vlt:v1:key-0001:rot13:AAAA", |e| {
                matches!(e, Error::UnsupportedAlgorithm)
            }),
            ("vlt:v1:key-0001:aes256gcm:not base64!", |e| {
                matches!(e, Error::InvalidEncoding)
            }),
            // Valid base64, but too short to hold a nonce and a tag.
            ("vlt:v1:key-0001:aes256gcm:AAAA", |e| {
                matches!(e, Error::InvalidCiphertext)
            }),
        ];

        for (input, expected) in cases {
            let err = EncryptedValue::parse(input).unwrap_err();
            assert!(expected(&err), "{input:?} produced {err:?}");
        }
    }

    #[test]
    fn rejects_padded_base64() {
        // The format pins unpadded URL-safe base64 so that one plaintext has
        // exactly one serialization.
        let value = sample();
        let padded = format!("{}=", value);
        assert!(matches!(
            EncryptedValue::parse(&padded),
            Err(Error::InvalidEncoding)
        ));
    }

    #[test]
    fn minimum_length_is_enforced_per_algorithm() {
        let nonce_and_tag =
            vec![0u8; Algorithm::Aes256Gcm.nonce_len() + Algorithm::Aes256Gcm.tag_len()];
        assert!(EncryptedValue::new(
            KeyId::new("k").unwrap(),
            Algorithm::Aes256Gcm,
            nonce_and_tag.clone()
        )
        .is_ok());
        assert!(EncryptedValue::new(
            KeyId::new("k").unwrap(),
            Algorithm::Aes256Gcm,
            nonce_and_tag[1..].to_vec()
        )
        .is_err());
    }
}
