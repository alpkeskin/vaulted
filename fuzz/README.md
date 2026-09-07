# Fuzzing Vaulted

Every input Vaulted parses comes from the database, and the threat model says
the attacker controls the database. These targets exist to keep that surface
panic-free.

This directory is excluded from the workspace: it needs a nightly toolchain and
`cargo-fuzz`, and nothing else in the repository does.

## Setup

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running

```sh
cargo +nightly fuzz run parse_ciphertext
cargo +nightly fuzz run decrypt
cargo +nightly fuzz run parse_blind_index
cargo +nightly fuzz run parse_keyring
```

Time-boxed, as in CI:

```sh
cargo +nightly fuzz run parse_ciphertext -- -max_total_time=300
```

## The targets

| Target              | Entry point                    | What it must never do |
|---------------------|--------------------------------|-----------------------|
| `parse_ciphertext`  | `EncryptedValue::parse`        | panic; accept a value that does not round trip |
| `decrypt`           | `Vault::decrypt_str`           | panic; return plaintext for a value it did not produce |
| `parse_blind_index` | `BlindIndex::parse`            | panic; accept an out-of-range length |
| `parse_keyring`     | `LocalKeyProvider::from_json`  | panic; accept malformed key material |

## Seeds

Give the fuzzer something structured to mutate, or it spends its first hours
rediscovering the `vlt:` prefix:

```sh
mkdir -p corpus/parse_ciphertext
cargo run -q -p vaulted-examples --example basic \
  | awk '/^ciphertext/ {print $2}' > corpus/parse_ciphertext/seed
```

## When something is found

`cargo fuzz` writes the input to `artifacts/<target>/`. Add it verbatim to the
fixed cases in `tests/hostile_input.rs` before fixing the bug, so the case is
covered by `cargo test` from then on.
