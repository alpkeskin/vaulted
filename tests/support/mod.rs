//! Shared helpers for the integration tests.

#![allow(dead_code)]

use vaulted_core::{BlindIndexConfig, FieldConfig, LocalKeyProvider, Normalization, Vault};

/// A vault with the field layout the tests use throughout:
///
/// | field         | normalization | blind index |
/// |---------------|---------------|-------------|
/// | `users.email` | email         | yes         |
/// | `users.phone` | digits only   | yes         |
/// | `users.note`  | none          | no          |
pub fn test_vault(provider: LocalKeyProvider) -> Vault {
    Vault::builder()
        .key_provider(provider)
        .field(
            FieldConfig::new("users.email")
                .unwrap()
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .field(
            FieldConfig::new("users.phone")
                .unwrap()
                .with_normalization(Normalization::DigitsOnly)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .field(FieldConfig::new("users.note").unwrap())
        .build()
        .unwrap()
}

/// A small deterministic PRNG.
///
/// Deterministic on purpose: a randomized test that cannot be replayed is a
/// test that reports failures nobody can reproduce. Seeds are fixed constants,
/// so a failure here always reproduces exactly.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Any non-zero state works for xorshift64*.
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// Random bytes, with a random length below `bound`.
    pub fn bytes_below(&mut self, bound: usize) -> Vec<u8> {
        let len = self.below(bound);
        self.bytes(len)
    }
}
