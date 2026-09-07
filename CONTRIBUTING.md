# Contributing to Vaulted

Thanks for taking the time. Vaulted is a cryptography library, so the bar for
changes is a little higher than usual — this page says where that bar is.

> **Found a vulnerability?** Do not open an issue. Follow [SECURITY.md](SECURITY.md).

## Ways to help

| | |
|---|---|
| 🐛 **Report a bug** | [Open a bug report](https://github.com/alpkeskin/vaulted/issues/new?template=bug_report.yml) with a minimal reproduction. |
| 💡 **Propose a feature** | [Open a feature request](https://github.com/alpkeskin/vaulted/issues/new?template=feature_request.yml). Check [ROADMAP.md](docs/ROADMAP.md) first — some things are deliberately not planned. |
| 📖 **Improve the docs** | Small doc fixes need no issue; send the PR. |
| 🧑‍💻 **Write code** | For anything beyond a small fix, open an issue first so the design is agreed before you spend time. |

## Getting set up

```sh
git clone https://github.com/alpkeskin/vaulted
cd vaulted
cargo test --workspace
```

Rust 1.85 or newer (see [Compatibility](README.md#compatibility)). Fuzzing needs
a nightly toolchain and `cargo-fuzz`.

## Before you open a PR

Run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features   # warnings are errors in CI
cargo test --workspace --all-targets
cargo test --workspace --doc
```

If you touched parsing or any hostile-input path, also give the fuzzers a minute:

```sh
cd fuzz && cargo +nightly fuzz run parse_ciphertext -- -max_total_time=60
```

## What reviewers look for

- **No new cryptography.** Vaulted composes [RustCrypto](https://github.com/RustCrypto)
  primitives and implements none of its own. A PR that hand-rolls a primitive
  will be declined.
- **No plaintext or key material** in errors, `Debug` output, logs or panics.
- **No unauthenticated mode**, and no API that accepts a caller-supplied nonce.
- **Format changes are versioned.** The ciphertext format is a compatibility
  contract; see [CIPHERTEXT_FORMAT.md](docs/CIPHERTEXT_FORMAT.md).
- **Tests that fail without the change.** For parsing and validation, prefer a
  property test or a fuzz target over a handful of examples.
- **Dependencies stay few and boring.** A new dependency needs a reason in the
  PR description.
- **Compile-time and run-time validation stay in sync.** The derive mirrors the
  core's rules, and a test pins the two together — update both.

## Commits and PRs

- One logical change per PR; keep unrelated refactors out.
- Write commit messages in the imperative mood ("add blind index truncation").
- Describe *why* in the PR body, not just what. Link the issue it closes.
- Draft PRs are welcome for early feedback.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
