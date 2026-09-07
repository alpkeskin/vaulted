## What and why

<!-- What does this change, and what problem does it solve? Link the issue. -->

Closes #

## Checklist

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features` is clean
- [ ] `cargo test --workspace --all-targets` and `--doc` pass
- [ ] Tests added that fail without this change
- [ ] Docs updated (`README.md` / `docs/`) if behavior or API changed

## Security review

- [ ] No new cryptographic primitive is implemented here
- [ ] No plaintext or key material can reach errors, `Debug`, logs or panics
- [ ] The ciphertext format is unchanged, or the change is versioned and
      documented in [`docs/CIPHERTEXT_FORMAT.md`](../blob/main/docs/CIPHERTEXT_FORMAT.md)
- [ ] Compile-time (derive) and run-time (core) validation stay in sync
