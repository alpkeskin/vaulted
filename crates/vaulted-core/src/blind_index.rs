//! Blind indexes: equality search over encrypted columns.
//!
//! An AEAD ciphertext is different every time, so `WHERE email = $1` cannot
//! work against it. A blind index is a second, deterministic column beside the
//! ciphertext:
//!
//! ```text
//! plaintext ──┬─► AES-256-GCM ──► email_ciphertext
//!             └─► HMAC-SHA256 ──► email_blind_index
//! ```
//!
//! The application computes the same HMAC at query time and looks the row up by
//! it. HMAC — not a bare hash — because a bare SHA-256 of an email address is
//! recovered instantly from a wordlist by anyone holding the dump. With a key
//! the attacker does not have, the index is opaque.
//!
//! # What it still leaks
//!
//! Equality and frequency. Two rows with the same value have the same index, so
//! a dump reveals how values are distributed even though it reveals no value.
//! For a low-entropy column (a country, a status flag) that distribution can be
//! matched against public statistics and effectively deanonymized. Blind
//! indexes are for high-entropy identifiers you must look rows up by — an email
//! address, a national ID — not for everything you might want to filter on.
//!
//! # Encoding
//!
//! ```text
//! message = "vaulted-blind-index-v1"
//!         || u32be(len(field)) || field
//!         || u32be(len(value)) || value      // after normalization
//!
//! index   = HMAC-SHA256(blind_index_key, message)[..output_bytes]
//! ```
//!
//! The field name is mixed in for the same reason it is mixed into the AAD:
//! the same value in two columns must not produce the same index, or the two
//! columns become joinable by anyone with the dump. Lengths are framed so the
//! encoding is unambiguous.
//!
//! Serialized form: `bi:v1:<key_id>:<lowercase hex>`.

use core::fmt;
use core::str::FromStr;

use vaulted_crypto::{constant_time_eq, hmac_sha256, SecretKey};

use crate::error::{BlindIndexError, Error, Result};
use crate::hex;
use crate::key::KeyId;

/// Domain separation label. Never change this string.
const DOMAIN: &[u8] = b"vaulted-blind-index-v1";

/// Prefix of the serialized form.
pub const BLIND_INDEX_PREFIX: &str = "bi";

/// Version of the serialized form and of the message encoding.
pub const BLIND_INDEX_VERSION: u32 = 1;

/// A searchable, deterministic tag derived from a plaintext value.
#[derive(Clone, Eq)]
pub struct BlindIndex {
    key_id: KeyId,
    bytes: Vec<u8>,
}

impl BlindIndex {
    /// Computes the index for an already-normalized value.
    pub(crate) fn compute(
        key: &SecretKey,
        key_id: &KeyId,
        field: &str,
        normalized_value: &[u8],
        output_bytes: usize,
    ) -> Result<Self> {
        use crate::field::{MAX_BLIND_INDEX_BYTES, MIN_BLIND_INDEX_BYTES};
        if !(MIN_BLIND_INDEX_BYTES..=MAX_BLIND_INDEX_BYTES).contains(&output_bytes) {
            return Err(BlindIndexError::InvalidOutputLength.into());
        }

        let mut message =
            Vec::with_capacity(DOMAIN.len() + 8 + field.len() + normalized_value.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&(field.len() as u32).to_be_bytes());
        message.extend_from_slice(field.as_bytes());
        message.extend_from_slice(&(normalized_value.len() as u32).to_be_bytes());
        message.extend_from_slice(normalized_value);

        let tag = hmac_sha256(key, &message);
        Ok(Self {
            key_id: key_id.clone(),
            bytes: tag[..output_bytes].to_vec(),
        })
    }

    /// The key version this index was computed with.
    ///
    /// Part of the value and of its serialized form, not of the column you
    /// store: [`matches`](Self::matches) compares it along with the bytes, so
    /// two indexes computed under different keys can never compare equal.
    ///
    /// Rotating an index key needs the plaintext of every row regardless, so
    /// keeping the identifier in the table would buy nothing. See
    /// `docs/KEY_MANAGEMENT.md` for the dual-write window that does it.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The raw index bytes, for storage in a `bytea` column.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The index as lowercase hex, for storage in a `text` column.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Compares two indexes in constant time.
    pub fn matches(&self, other: &BlindIndex) -> bool {
        self.key_id == other.key_id && constant_time_eq(&self.bytes, &other.bytes)
    }

    /// Parses the serialized form `bi:v1:<key_id>:<hex>`.
    pub fn parse(s: &str) -> Result<Self> {
        let mut segments = s.split(':');
        let mut next = || {
            segments
                .next()
                .ok_or(Error::from(BlindIndexError::Malformed))
        };

        let prefix = next()?;
        let version = next()?;
        let key_id = next()?;
        let digits = next()?;
        if segments.next().is_some() || prefix != BLIND_INDEX_PREFIX {
            return Err(BlindIndexError::Malformed.into());
        }

        let version = version
            .strip_prefix('v')
            .and_then(|d| d.parse::<u32>().ok())
            .ok_or(Error::from(BlindIndexError::Malformed))?;
        if version != BLIND_INDEX_VERSION {
            return Err(Error::UnsupportedVersion { version });
        }

        let key_id = KeyId::new(key_id)?;
        let bytes = hex::decode(digits)?;

        use crate::field::{MAX_BLIND_INDEX_BYTES, MIN_BLIND_INDEX_BYTES};
        if !(MIN_BLIND_INDEX_BYTES..=MAX_BLIND_INDEX_BYTES).contains(&bytes.len()) {
            return Err(BlindIndexError::InvalidOutputLength.into());
        }

        Ok(Self { key_id, bytes })
    }
}

impl fmt::Display for BlindIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{BLIND_INDEX_PREFIX}:v{BLIND_INDEX_VERSION}:{}:{}",
            self.key_id,
            self.to_hex()
        )
    }
}

impl fmt::Debug for BlindIndex {
    /// Deliberately does not print the index itself.
    ///
    /// The index is a stable fingerprint of a plaintext. It belongs in the
    /// database and in query parameters, not in a log line that outlives both.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindIndex")
            .field("key_id", &self.key_id.as_str())
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl PartialEq for BlindIndex {
    /// Constant-time, so that comparing indexes cannot be timed to recover one.
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl FromStr for BlindIndex {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for BlindIndex {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for BlindIndex {
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

    fn key() -> SecretKey {
        SecretKey::from_bytes([9u8; 32])
    }

    fn key_id() -> KeyId {
        KeyId::new("key-0001").unwrap()
    }

    fn index_of(field: &str, value: &str) -> BlindIndex {
        BlindIndex::compute(&key(), &key_id(), field, value.as_bytes(), 32).unwrap()
    }

    #[test]
    fn equal_values_produce_equal_indexes() {
        assert_eq!(
            index_of("users.email", "foo"),
            index_of("users.email", "foo")
        );
    }

    #[test]
    fn different_values_produce_different_indexes() {
        assert_ne!(
            index_of("users.email", "foo"),
            index_of("users.email", "bar")
        );
    }

    #[test]
    fn the_field_name_separates_columns() {
        // The same value in two columns must not be joinable.
        assert_ne!(
            index_of("users.email", "foo"),
            index_of("users.phone", "foo")
        );
    }

    #[test]
    fn length_framing_prevents_boundary_collisions() {
        assert_ne!(index_of("ab", "c"), index_of("a", "bc"));
    }

    #[test]
    fn different_keys_produce_different_indexes() {
        let other = SecretKey::from_bytes([1u8; 32]);
        let a = index_of("users.email", "foo");
        let b = BlindIndex::compute(&other, &key_id(), "users.email", b"foo", 32).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn truncation_is_a_prefix_of_the_full_tag() {
        let full = index_of("users.email", "foo");
        let short = BlindIndex::compute(&key(), &key_id(), "users.email", b"foo", 8).unwrap();
        assert_eq!(short.as_bytes(), &full.as_bytes()[..8]);
        assert_eq!(short.to_hex().len(), 16);
    }

    #[test]
    fn output_length_is_validated() {
        for bad in [0, 7, 33, 64] {
            assert!(BlindIndex::compute(&key(), &key_id(), "f", b"v", bad).is_err());
        }
    }

    #[test]
    fn serialized_form_round_trips() {
        let index = index_of("users.email", "foo");
        let rendered = index.to_string();
        assert!(rendered.starts_with("bi:v1:key-0001:"));
        assert_eq!(rendered.len(), "bi:v1:key-0001:".len() + 64);
        let parsed: BlindIndex = rendered.parse().unwrap();
        assert_eq!(parsed, index);
        assert_eq!(parsed.key_id(), &key_id());
    }

    #[test]
    fn parsing_rejects_malformed_input() {
        let cases = [
            "",
            "bi:v1:key-0001",
            "bi:v1:key-0001:abcd:extra",
            "xx:v1:key-0001:00112233445566778899aabbccddeeff",
            "bi:1:key-0001:00112233445566778899aabbccddeeff",
            "bi:v1:key 0001:00112233445566778899aabbccddeeff",
            "bi:v1:key-0001:zz112233445566778899aabbccddeeff",
            "bi:v1:key-0001:0011",            // too short
            "bi:v1:key-0001:001122334455667", // odd length
        ];
        for case in cases {
            assert!(
                BlindIndex::parse(case).is_err(),
                "{case:?} should be rejected"
            );
        }
        assert!(matches!(
            BlindIndex::parse("bi:v9:key-0001:00112233445566778899aabbccddeeff"),
            Err(Error::UnsupportedVersion { version: 9 })
        ));
    }

    #[test]
    fn debug_does_not_reveal_the_index() {
        let rendered = format!("{:?}", index_of("users.email", "foo"));
        assert!(rendered.contains("key-0001"));
        assert!(!rendered.contains(&index_of("users.email", "foo").to_hex()));
    }

    #[test]
    fn indexes_from_different_key_versions_never_match() {
        let a = index_of("users.email", "foo");
        let b = BlindIndex::compute(
            &key(),
            &KeyId::new("key-0002").unwrap(),
            "users.email",
            b"foo",
            32,
        )
        .unwrap();
        assert_ne!(a, b);
    }
}
