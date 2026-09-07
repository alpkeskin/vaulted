//! Benchmarks for the operations an application performs per row.
//!
//! Run with `cargo bench -p vaulted-core`.
//!
//! On aarch64, add `RUSTFLAGS="--cfg aes_armv8"` to let the `aes` crate use the
//! ARMv8 crypto extensions — worth about a 2× difference on AES-256-GCM, and
//! without it XChaCha20-Poly1305 will look misleadingly faster. On x86-64,
//! AES-NI is detected at runtime and no flag is needed.
//!
//! What to watch for is shape, not absolute numbers: encryption should scale
//! with plaintext size, while parsing and blind indexing should stay flat for
//! the value sizes a database column actually holds.

// criterion's macros generate undocumented items; the crate-wide missing_docs
// lint does not apply usefully to a benchmark harness.
#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use vaulted_core::{
    Algorithm, BlindIndexConfig, FieldConfig, LocalKeyProvider, Normalization, Vault,
};

const FIELD: &str = "users.email";
const SAMPLE: &str = "user@example.com";

fn build_vault(algorithm: Algorithm) -> Vault {
    Vault::builder()
        .key_provider(LocalKeyProvider::generate().expect("key generation"))
        .algorithm(algorithm)
        .field(
            FieldConfig::new(FIELD)
                .expect("valid field name")
                .with_normalization(Normalization::Email)
                .with_blind_index(BlindIndexConfig::new()),
        )
        .build()
        .expect("vault")
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");
    for size in [16usize, 256, 4096] {
        let plaintext = "x".repeat(size);
        group.throughput(Throughput::Bytes(size as u64));
        for (label, algorithm) in [
            ("aes256gcm", Algorithm::Aes256Gcm),
            ("xchacha20poly1305", Algorithm::XChaCha20Poly1305),
        ] {
            if !algorithm.is_available() {
                continue;
            }
            let vault = build_vault(algorithm);
            group.bench_with_input(BenchmarkId::new(label, size), &plaintext, |b, value| {
                b.iter(|| vault.encrypt(black_box(FIELD), black_box(value)).unwrap());
            });
        }
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");
    for size in [16usize, 256, 4096] {
        let plaintext = "x".repeat(size);
        group.throughput(Throughput::Bytes(size as u64));
        for (label, algorithm) in [
            ("aes256gcm", Algorithm::Aes256Gcm),
            ("xchacha20poly1305", Algorithm::XChaCha20Poly1305),
        ] {
            if !algorithm.is_available() {
                continue;
            }
            let vault = build_vault(algorithm);
            let value = vault.encrypt(FIELD, &plaintext).unwrap();
            group.bench_with_input(BenchmarkId::new(label, size), &value, |b, value| {
                b.iter(|| vault.decrypt(black_box(FIELD), black_box(value)).unwrap());
            });
        }
    }
    group.finish();
}

fn bench_blind_index(c: &mut Criterion) {
    let vault = build_vault(Algorithm::Aes256Gcm);
    c.bench_function("blind_index", |b| {
        b.iter(|| {
            vault
                .blind_index(black_box(FIELD), black_box(SAMPLE))
                .unwrap()
        });
    });
}

fn bench_serialization(c: &mut Criterion) {
    let vault = build_vault(Algorithm::Aes256Gcm);
    let value = vault.encrypt(FIELD, SAMPLE).unwrap();
    let serialized = value.to_string();

    c.bench_function("serialize", |b| {
        b.iter(|| black_box(&value).to_string());
    });
    c.bench_function("deserialize", |b| {
        b.iter(|| {
            black_box(&serialized)
                .parse::<vaulted_core::EncryptedValue>()
                .unwrap()
        });
    });
}

fn bench_protect(c: &mut Criterion) {
    // The full write path: encrypt plus blind index, as an INSERT would do it.
    let vault = build_vault(Algorithm::Aes256Gcm);
    c.bench_function("protect", |b| {
        b.iter(|| vault.protect(black_box(FIELD), black_box(SAMPLE)).unwrap());
    });
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_blind_index,
    bench_serialization,
    bench_protect
);
criterion_main!(benches);
