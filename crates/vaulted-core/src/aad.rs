//! Associated data construction.
//!
//! Every encryption authenticates a context string that is *not* stored inside
//! the payload. Two things go into it:
//!
//! - the ciphertext header (`vlt:v1:<key_id>:<algorithm>`), so the parts of the
//!   value that travel in the clear cannot be rewritten; and
//! - the field name (`users.email`), so a ciphertext is bound to the column it
//!   belongs to.
//!
//! The second binding is the interesting one. Without it, an attacker with
//! write access to the database could copy the ciphertext of
//! `users.email` into `users.phone`, and the application would happily decrypt
//! it — a valid value in the wrong place. With it, decryption under the wrong
//! field name fails authentication, indistinguishably from any other tampering.
//!
//! # Encoding
//!
//! ```text
//! AAD = "vaulted-aad-v1"
//!     || u32be(len(header)) || header
//!     || u32be(len(field))  || field
//! ```
//!
//! Lengths are explicit so the encoding is unambiguous: without them,
//! `header="a", field="bc"` and `header="ab", field="c"` would produce the same
//! bytes, and a value could be moved between fields whose names happen to line
//! up. The domain label pins this construction to Vaulted, so the same key used
//! by some other protocol cannot produce a colliding AAD.
//!
//! This encoding is part of the on-disk contract: changing it makes every
//! existing ciphertext undecryptable.

use vaulted_crypto::Algorithm;

use crate::format::{FORMAT_PREFIX, SEPARATOR};
use crate::key::KeyId;

/// Domain separation label. Never change this string.
const DOMAIN: &[u8] = b"vaulted-aad-v1";

/// Builds the associated data for a value.
pub(crate) fn build(version: u32, key_id: &KeyId, algorithm: Algorithm, field: &str) -> Vec<u8> {
    let header = format!(
        "{FORMAT_PREFIX}{SEPARATOR}v{version}{SEPARATOR}{key_id}{SEPARATOR}{}",
        algorithm.wire_name()
    );
    build_from_header(&header, field)
}

fn build_from_header(header: &str, field: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN.len() + 8 + header.len() + field.len());
    aad.extend_from_slice(DOMAIN);
    push_framed(&mut aad, header.as_bytes());
    push_framed(&mut aad, field.as_bytes());
    aad
}

fn push_framed(out: &mut Vec<u8>, bytes: &[u8]) {
    // Field names and headers are bounded well below 4 GiB by validation, so
    // the cast cannot lose information.
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str) -> KeyId {
        KeyId::new(id).unwrap()
    }

    #[test]
    fn encodes_the_documented_layout() {
        let aad = build(1, &key("key-0001"), Algorithm::Aes256Gcm, "users.email");
        let header = b"vlt:v1:key-0001:aes256gcm";
        let mut expected = Vec::new();
        expected.extend_from_slice(b"vaulted-aad-v1");
        expected.extend_from_slice(&(header.len() as u32).to_be_bytes());
        expected.extend_from_slice(header);
        expected.extend_from_slice(&11u32.to_be_bytes());
        expected.extend_from_slice(b"users.email");
        assert_eq!(aad, expected);
    }

    #[test]
    fn every_component_changes_the_result() {
        let base = build(1, &key("key-0001"), Algorithm::Aes256Gcm, "users.email");
        assert_ne!(
            base,
            build(2, &key("key-0001"), Algorithm::Aes256Gcm, "users.email")
        );
        assert_ne!(
            base,
            build(1, &key("key-0002"), Algorithm::Aes256Gcm, "users.email")
        );
        assert_ne!(
            base,
            build(
                1,
                &key("key-0001"),
                Algorithm::XChaCha20Poly1305,
                "users.email"
            )
        );
        assert_ne!(
            base,
            build(1, &key("key-0001"), Algorithm::Aes256Gcm, "users.phone")
        );
    }

    #[test]
    fn length_framing_prevents_boundary_collisions() {
        // Without length prefixes these two would serialize identically.
        assert_ne!(build_from_header("a", "bc"), build_from_header("ab", "c"));
        assert_ne!(build_from_header("", "ab"), build_from_header("a", "b"));
    }

    #[test]
    fn is_deterministic() {
        let a = build(1, &key("key-0001"), Algorithm::Aes256Gcm, "users.email");
        let b = build(1, &key("key-0001"), Algorithm::Aes256Gcm, "users.email");
        assert_eq!(a, b);
    }
}
