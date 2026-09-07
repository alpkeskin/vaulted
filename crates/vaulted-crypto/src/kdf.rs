//! Key derivation.
//!
//! Used by key providers that hold a single root secret per key version and
//! need distinct subkeys per purpose. Providers backed by a KMS or by
//! independently generated keys do not need this.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{CryptoError, Result};
use crate::key::{SecretKey, KEY_LEN};

/// Derives a 256-bit subkey from `root` using HKDF-SHA256.
///
/// `info` is a domain separation label: two different labels derived from the
/// same root are computationally independent, so a blind index key cannot be
/// used to decrypt, or vice versa. Labels must be stable forever — changing one
/// changes every key derived with it.
pub fn derive_subkey(root: &SecretKey, salt: &[u8], info: &[u8]) -> Result<SecretKey> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), root.expose_secret());
    let mut okm = [0u8; KEY_LEN];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(SecretKey::from_bytes(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_info_yields_independent_keys() {
        let root = SecretKey::generate().unwrap();
        let a = derive_subkey(&root, b"salt", b"vaulted/v1/encryption").unwrap();
        let b = derive_subkey(&root, b"salt", b"vaulted/v1/blind-index").unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_ne!(a.expose_secret(), root.expose_secret());
    }

    #[test]
    fn derivation_is_deterministic() {
        let root = SecretKey::from_bytes([7u8; KEY_LEN]);
        let a = derive_subkey(&root, b"salt", b"info").unwrap();
        let b = derive_subkey(&root, b"salt", b"info").unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn salt_is_part_of_the_derivation() {
        let root = SecretKey::from_bytes([7u8; KEY_LEN]);
        let a = derive_subkey(&root, b"salt-a", b"info").unwrap();
        let b = derive_subkey(&root, b"salt-b", b"info").unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }
}
