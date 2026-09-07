# vaulted-crypto

Cryptographic primitives for [Vaulted](https://github.com/alpkeskin/vaulted),
field-level encryption for databases.

This is the only crate in the workspace that touches a cipher. It implements no
cryptography of its own: it wraps [RustCrypto](https://github.com/RustCrypto)
implementations behind a surface that is hard to misuse.

- `SecretKey` holds 256-bit keys, zeroizes on drop and never prints itself.
- `Nonce` can only be built at the length its `Algorithm` requires, and the
  ordinary way to get one is `Nonce::random`.
- `seal` and `open` always take associated data, so authenticating context is
  the default rather than an option.
- Every decryption failure returns the same error, so the API cannot be used as
  an oracle to distinguish a wrong key from tampered data.

```rust
use vaulted_crypto::{open, seal, Algorithm, Nonce, SecretKey};

let key = SecretKey::generate()?;
let nonce = Nonce::random(Algorithm::Aes256Gcm)?;
let sealed = seal(Algorithm::Aes256Gcm, &key, &nonce, b"users.email", b"user@example.com")?;
let opened = open(Algorithm::Aes256Gcm, &key, &nonce, b"users.email", &sealed)?;
assert_eq!(opened.as_slice(), b"user@example.com");
```

AES-256-GCM is always available. XChaCha20-Poly1305 is behind the default
`xchacha` feature.

**Most applications want [`vaulted-core`](https://crates.io/crates/vaulted-core)
instead**, which owns ciphertext framing, key lookup, blind indexes and field
policy. Reach for this crate directly only if you are building on the
primitives.

Licensed under the MIT license.
