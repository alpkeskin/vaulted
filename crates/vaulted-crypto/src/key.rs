//! Symmetric key material.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};
use crate::rand::fill_random;

/// Length of every symmetric key used by Vaulted, in bytes.
///
/// Both supported AEADs take 256-bit keys, and HMAC-SHA256 blind index keys
/// use the same size so that key material is uniform across purposes.
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key.
///
/// The bytes are zeroized when the value is dropped, and neither [`fmt::Debug`]
/// nor [`fmt::Display`] will ever reveal them.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; KEY_LEN],
}

impl SecretKey {
    /// Wraps an existing 256-bit key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Wraps a key from a slice, which must be exactly [`KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self { bytes })
    }

    /// Generates a fresh key from the operating system CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        fill_random(&mut bytes)?;
        Ok(Self { bytes })
    }

    /// Borrows the raw key bytes.
    ///
    /// The name is deliberately loud: every call site is a place where key
    /// material escapes this type, and should be reviewed as such.
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_key_material() {
        let key = SecretKey::from_bytes([0xAB; KEY_LEN]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "SecretKey(<redacted>)");
        assert!(!rendered.contains("171") && !rendered.to_lowercase().contains("ab"));
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert_eq!(
            SecretKey::from_slice(&[0u8; KEY_LEN - 1]).unwrap_err(),
            CryptoError::InvalidKeyLength
        );
        assert_eq!(
            SecretKey::from_slice(&[0u8; KEY_LEN + 1]).unwrap_err(),
            CryptoError::InvalidKeyLength
        );
        assert!(SecretKey::from_slice(&[0u8; KEY_LEN]).is_ok());
    }

    #[test]
    fn generated_keys_differ() {
        let a = SecretKey::generate().unwrap();
        let b = SecretKey::generate().unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_ne!(a.expose_secret(), &[0u8; KEY_LEN]);
    }
}
