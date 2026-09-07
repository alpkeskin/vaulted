# Architecture

## Layers

```text
  vaulted-cli   vaulted-postgres    keyring and rotation; SQL for
       │              │              encrypted columns
       │              │
       │              │   vaulted-derive   #[derive(Vaulted)], compile time only
       │              │        │
       ▼              ▼        ▼
        vaulted-core         ciphertext format, AAD, blind indexes,
             │               key providers, field policy, the Vault API
             ▼
       vaulted-crypto        AEAD, HMAC, HKDF, secure randomness
             │
             ▼
        RustCrypto           aes-gcm, chacha20poly1305, hmac, sha2, hkdf
```

Dependencies point one way only. `vaulted-crypto` knows nothing about fields,
keyrings or storage; `vaulted-core` knows nothing about PostgreSQL. That is what
keeps a future database integration from leaking into the crypto layer, and what
makes the core reusable from SDKs in other languages later.

## vaulted-crypto

The only crate that touches a cipher. It exists to make the primitives hard to
misuse rather than to add capability:

- `SecretKey` — 256-bit, zeroized on drop, redacted in `Debug`.
- `Nonce` — constructible only at the length its algorithm requires; the
  ordinary constructor is `Nonce::random`.
- `seal` / `open` — always take associated data, so authenticated context is the
  default rather than an option.
- Every decryption failure returns one error, so the API cannot be probed as an
  oracle.
- `hmac_sha256`, `derive_subkey`, `constant_time_eq`, `fill_random`.

No cryptography is implemented here.

## vaulted-core

| Module | Responsibility |
|--------|----------------|
| `format` | `EncryptedValue`: the versioned wire format, and a parser that treats its input as hostile |
| `aad` | Deterministic associated data binding version, key id, algorithm and field |
| `blind_index` | `BlindIndex`: HMAC-SHA256 equality tags, with key version attached |
| `field` | `FieldConfig`, `Normalization`, per-field policy |
| `key` | `KeyId`, `KeyPurpose` |
| `provider` | `KeyProvider` trait, `Keyring`, `LocalKeyProvider` |
| `keyfile` | JSON keyring documents, permission-checked file I/O |
| `vault` | `Vault`: the four operations an application uses |
| `error` | Errors that never carry plaintext, and collapse probeable failures |

### The Vault API

```rust
vault.encrypt(field, plaintext)   -> EncryptedValue
vault.decrypt(field, &value)      -> Zeroizing<String>
vault.blind_index(field, value)   -> BlindIndex
vault.protect(field, value)       -> ProtectedValue   // both columns, for INSERT
vault.rotate(field, &value)       -> Rotated          // re-encrypt + reindex
```

Nonces, tags, serialization, key lookup and algorithm selection stay inside.
The only thing a caller must get right is the field name — and getting it wrong
fails loudly, because the name is authenticated.

### Write and read paths

```text
encrypt(field, plaintext)
  ├─ validate field name
  ├─ resolve algorithm      (field override, else vault default)
  ├─ provider.primary_key_id()
  ├─ provider.key(key_id, Encryption)
  ├─ Nonce::random(algorithm)                    ← fresh, from the OS CSPRNG
  ├─ aad = build(version, key_id, algorithm, field)
  ├─ seal(...)
  └─ EncryptedValue { key_id, algorithm, nonce || ciphertext || tag }

decrypt(field, value)
  ├─ validate field name
  ├─ provider.key(value.key_id, Encryption)      ← routed by the value itself
  ├─ aad = build(value.version, value.key_id, value.algorithm, field)
  └─ open(...)                                   ← one error for every failure
```

The read path takes its version, key and algorithm from the value, which is what
makes rotation and format migration ordinary operations instead of flag days.

## vaulted-derive

A proc-macro crate holding `#[derive(Vaulted)]`, re-exported from `vaulted-core`
under the `derive` feature. It generates an impl of `VaultedSchema`: the
`FieldConfig` set, the field-name constants used at call sites, and the column
names. `syn` and `quote` are build-time dependencies, so nothing from them
reaches a dependent's binary and the core's runtime dependency list is unchanged.

The macro emits data and no logic. Everything that could be a method on
`EncryptedField` — column definitions, lookups — lives in `vaulted_core::schema`
where it can be unit tested, rather than being generated afresh into every
dependent crate.

What it validates at expansion time is the point of it: field names and their
character set, the name length limit, key identifiers, blind index lengths,
duplicate names, duplicate columns, and constants that would collide. Those
rules are mirrored from the core, since a proc-macro crate cannot depend on the
crate it generates code for; the core validates them again at run time, so a
drift costs a later error rather than a wrong one, and `tests/derive.rs` pins
the mirrored limits against the core's constants. A field name is authenticated associated data, so a typo in
one of the places it used to be repeated did not fail loudly — it wrote a column
nothing could decrypt. Deriving the three uses from one declaration makes that
typo a compile error.

## vaulted-postgres

Driver glue so encrypted values bind as ordinary query parameters, and DDL
generated from a `VaultedSchema`: the columns a field set needs, the three-step
migration that adds them to a populated table, the indexes for the blind index
columns, and the `WHERE` fragment that looks a row up by one. The DDL is the
same whichever driver you use; the `postgres-types`, `sqlx-0_8` and `sqlx-0_9`
features pick which glue is compiled, and any combination may be on at once.

The trait impls are not in this crate. Rust's orphan rule puts them in
`vaulted_core::postgres` and `vaulted_core::sqlx`, since both the trait and the
type would otherwise be foreign; the alternative is a newtype at every bind
site, which is worse to use and no more honest about the coupling. Neither
brings a driver or a runtime: `postgres-types` is the trait crate
`tokio-postgres` and the synchronous `postgres` both re-export, and `sqlx` is
taken with no runtime, no TLS and no macros. What stays out of the core is SQL
itself: `bytea` is not a type every database has.

Two sqlx lines are carried rather than one. A trait impl applies only to the
crate version that defined the trait, so linking a single sqlx would leave every
application on the other with a feature that compiles and does nothing — the
quietest kind of wrong. The impl bodies turned out identical across 0.8 and 0.9,
so one macro writes both; if a future version changes a signature, that macro
splits into two modules.

Both carry an MSRV above the workspace's 1.85 — 1.88 for 0.8, which reaches
`url` -> `idna` -> `icu_*`, and 1.94 for 0.9, which declares it — so neither is
a default feature and the MSRV job builds every feature but those.

It opens no connection and builds no statement beyond a single predicate.
Rewriting SQL is the proxy problem, and it is not being solved here by halves.

## vaulted-cli

`vaulted init`, `key create|list|rotate`, `status`, `inspect`, `blind-index`,
`encrypt`, `decrypt`, `rotate`. No command connects to a database: schema
migration needs to know your tables, and a tool that guessed at them would be
worse than no tool. `rotate` reads values from stdin and writes them to stdout,
so it composes with whatever does know your schema.

## Publishing

The crates go to crates.io bottom-up, because each depends on the published
version of the one below it and a version number on crates.io cannot be reused:

```text
vaulted-crypto  ──►  vaulted-derive  ──►  vaulted-core  ──►  vaulted-postgres
                                                        └──►  vaulted-cli
```

`vaulted-derive` comes before `vaulted-core` rather than after it: the core
carries the derive as an optional dependency so that `#[derive(Vaulted)]` can be
re-exported from one place. `vaulted-derive` itself depends on nothing in this
workspace, so it can go at any point before the core.

## Design decisions worth knowing

**Blind indexes are opt-in per field.** They publish equality and frequency.
That should be a decision, not a default.

**Encryption of undeclared fields is allowed.** Encrypting is always safe;
refusing unknown fields would only push people toward disabling validation.
Blind-indexing an undeclared field is refused.

**Normalization never touches stored data.** It applies to index input only.
An encryption layer that silently rewrites values is worse than no encryption
layer.

**Rotation returns rather than writes.** Non-destructive by construction, which
is what makes a backfill resumable and a zero-downtime rotation possible.

**Errors are coarse where it matters.** Wrong key, tampered ciphertext and wrong
field all produce `AuthenticationFailed`. Structural problems an attacker
already knows about — bad version, malformed encoding — stay distinct, because
telling those apart helps operators without helping anyone else.

## Testing

| Location | Covers |
|----------|--------|
| `crates/*/src/**` unit tests | Each module's contract, including negative cases |
| `tests/vertical_slice.rs` | The full application path against a simulated table |
| `tests/derive.rs` | The generated schema, and that a derived vault matches a hand-built one |
| `crates/vaulted-core/src/postgres.rs` | The wire format round-trip, without a database |
| `crates/vaulted-postgres/src/ddl.rs` | The generated SQL, statement by statement |
| `tests/rotation.rs` | Two-key windows, backfill, pinned index keys, retirement |
| `tests/properties.rs` | Round-trips, nonce uniqueness, cross-field isolation over generated inputs |
| `tests/hostile_input.rs` | Mutated and random input; the parser must never panic |
| `fuzz/` | Coverage-guided fuzzing of the same surfaces |
| `crates/vaulted-core/benches/` | encrypt, decrypt, blind_index, serialize, deserialize |

Generated inputs use a fixed-seed PRNG so every failure reproduces exactly.

## Not in the MVP

PostgreSQL proxy, SQL rewriting, driver replacement, KMS providers, range
queries, a dashboard. `vaulted-postgres` generates DDL and binds parameters; it
does not run them, and it does not know what a connection is. The core has to be stable and boring
first. See [ROADMAP.md](ROADMAP.md).
