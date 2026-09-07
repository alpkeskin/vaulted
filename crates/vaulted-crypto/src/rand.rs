//! Secure randomness.
//!
//! Every random byte in Vaulted comes from the operating system CSPRNG through
//! this module. There is no userspace PRNG, and no seeding knob to get wrong.

use crate::error::{CryptoError, Result};

/// Fills `buf` with cryptographically secure random bytes.
///
/// Returns [`CryptoError::Rng`] if the OS entropy source is unavailable. That
/// failure is never swallowed: a caller that cannot get randomness must abort
/// the operation rather than continue with a predictable nonce or key.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| CryptoError::Rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_different_output_each_call() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn empty_buffer_is_fine() {
        fill_random(&mut []).unwrap();
    }
}
