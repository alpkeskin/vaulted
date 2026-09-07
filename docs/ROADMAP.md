# Roadmap

The order matters more than the dates. Nothing below starts until the layer
under it is stable, because a field-encryption core that changes shape after
people have written data is not infrastructure anyone can trust.

## v0.1 — the core (this release)

- [x] Rust workspace: `vaulted-crypto`, `vaulted-core`, `vaulted-cli`,
      `vaulted-derive`, `vaulted-postgres`
- [x] AES-256-GCM with random per-operation nonces
- [x] XChaCha20-Poly1305 as an optional algorithm
- [x] Versioned ciphertext format, with the header authenticated
- [x] Field-bound associated data
- [x] Blind indexes over HMAC-SHA256, opt-in per field
- [x] `KeyProvider` abstraction with separate encryption / blind index material
- [x] Local keyring provider: file and environment
- [x] Key versioning and non-destructive rotation primitives
- [x] CLI: `init`, `key create|list|rotate`, `status`, `inspect`, `encrypt`,
      `decrypt`, `blind-index`, `rotate`
- [x] Unit, integration, property and hostile-input tests; fuzz targets
- [x] Benchmarks
- [x] Threat model, format specification, key management guide
- [x] `#[derive(Vaulted)]`: one declaration produces the field configuration,
      the call-site name constants and the column names

## Next: production key management

KMS-backed providers, in roughly this order:

1. AWS KMS (envelope encryption, wrapped data keys, cached with a TTL)
2. HashiCorp Vault Transit
3. GCP KMS
4. Azure Key Vault

The `KeyProvider` trait already has the shape these need — see
`examples/custom_key_provider.rs`. Adding them should not change any public API
above the provider layer, and if it does, the trait was wrong.

Also wanted here: a provider decorator with a bounded, TTL'd key cache, so that
every implementation does not reinvent one.

## Then: making it pleasant in an application

The derive covers the declaration; what remains is the database itself.

- [x] A `vaulted-postgres` crate with `ToSql`/`FromSql` glue for encrypted
      columns, driven by the `VaultedSchema` the derive already produces
- [x] Schema helpers: column fragments, the three-step migration for a
      populated table, and indexes for the blind index columns. Deliberately
      fragments and not a whole `CREATE TABLE`: the rest of the table is not
      this crate's business, and a statement that looked complete while
      omitting it would be worse than none
- [x] `sqlx` support, as a second set of `Type`/`Encode`/`Decode` impls behind
      a feature, sharing the same DDL. Both live sqlx lines are carried —
      `sqlx-0_8` and `sqlx-0_9` — because an impl only applies to the version
      that defined the trait. Drop `sqlx-0_8` once the ecosystem has moved
- A field configuration file the CLI can read, so `vaulted status` can report
  the real inventory of encrypted fields and blind indexes
- `vaulted migrate`: batched backfill against a live database, resumable, with
  progress and rate limiting

## Then: SDKs

Go first — it is the main target. The intended surface:

```go
encrypted, err := vaulted.Encrypt("users.email", email)
plaintext, err := vaulted.Decrypt("users.email", encrypted)
index, err     := vaulted.BlindIndex("users.email", email)
```

and, once that is solid, `database/sql` integration through `Scanner`/`Valuer`
so a struct tag is enough:

```go
type User struct {
    ID    int64
    Email string `vaulted:"encrypted"`
}
```

The rule for that work: **never hide a security failure**. Transparent
integration must fail loudly on a decryption error, never return an empty
string, and never silently skip encryption for a field it did not recognize.

Node.js and Python follow, sharing the same core.

## Later, maybe

A PostgreSQL proxy that rewrites SQL so applications need no changes at all:

```text
application ──SQL──► Vaulted proxy ──SQL──► PostgreSQL
                          ├─ encrypt INSERT/UPDATE
                          ├─ decrypt SELECT
                          └─ rewrite equality predicates to blind indexes
```

This is genuinely hard — parsing, prepared statements, type inference, `RETURNING`,
joins on encrypted columns — and a half-working version would be worse than
none. It is listed to say that the architecture leaves room for it, not to
promise it.

## Explicitly not planned

- Order-preserving or order-revealing encryption. Range queries over encrypted
  columns leak enough to reconstruct much of the data.
- Automatic normalization of stored values.
- Silent fallbacks of any kind: no unauthenticated mode, no plaintext
  passthrough, no "encryption optional" configuration flag.
