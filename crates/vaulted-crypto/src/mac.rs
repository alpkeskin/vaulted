//! Message authentication, used by blind indexes.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::key::SecretKey;

/// Output length of HMAC-SHA256, in bytes.
pub const HMAC_SHA256_LEN: usize = 32;

/// Computes `HMAC-SHA256(key, message)`.
///
/// The output is not secret in the sense that it is stored in the database, but
/// it is derived from a plaintext, so the buffer is zeroized on drop to avoid
/// leaving copies behind in memory the caller did not ask for.
pub fn hmac_sha256(key: &SecretKey, message: &[u8]) -> Zeroizing<[u8; HMAC_SHA256_LEN]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.expose_secret())
        .expect("HMAC accepts keys of any length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Compares two byte slices in constant time.
///
/// Use this instead of `==` whenever the comparison involves a value derived
/// from a secret, such as a blind index.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc4231_test_case_2() {
        // RFC 4231, test case 2: key = "Jefe", data = "what do ya want for
        // nothing?". Our keys are fixed at 32 bytes, so the RFC key is padded
        // with zeros -- which HMAC does internally anyway for short keys.
        let mut key_bytes = [0u8; 32];
        key_bytes[..4].copy_from_slice(b"Jefe");
        let key = SecretKey::from_bytes(key_bytes);
        let out = hmac_sha256(&key, b"what do ya want for nothing?");
        assert_eq!(
            hex_lower(&*out),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn deterministic_for_same_input() {
        let key = SecretKey::generate().unwrap();
        assert_eq!(*hmac_sha256(&key, b"foo"), *hmac_sha256(&key, b"foo"));
        assert_ne!(*hmac_sha256(&key, b"foo"), *hmac_sha256(&key, b"bar"));
    }

    #[test]
    fn differs_per_key() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        assert_ne!(*hmac_sha256(&a, b"foo"), *hmac_sha256(&b, b"foo"));
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
