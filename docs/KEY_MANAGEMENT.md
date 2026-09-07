# Key management and rotation

## The one rule

> Keys never live in the database they protect, and never in a backup taken
> alongside it.

Everything else here follows from that.

## Key versions and purposes

A *key version* is a labelled bundle of key material — `key-0001`,
`kms.dek-2026-08` — holding two independent keys:

| Purpose | Used for | Rotating it needs |
|---------|----------|-------------------|
| `Encryption` | AES-256-GCM / XChaCha20-Poly1305 | ciphertext only |
| `BlindIndex` | HMAC-SHA256 | **plaintext of every indexed row** |

They are separate material, not two uses of one key, so compromising a search
index does not hand over the data. `LocalKeyProvider` generates them
independently; `KeyVersion::from_root` derives them from a single root with
HKDF-SHA256 and distinct labels, for providers that only get one secret per
version.

The asymmetry in the last column is the single most important operational fact
about rotation, and it is why blind index keys can be pinned per field.

## The provider trait

```rust
pub trait KeyProvider: Debug + Send + Sync {
    fn primary_key_id(&self) -> Result<KeyId>;
    fn key(&self, key_id: &KeyId, purpose: KeyPurpose) -> Result<SecretKey>;
    fn key_ids(&self) -> Result<Vec<KeyId>> { Ok(Vec::new()) }
}
```

`primary_key_id` says what new writes use. `key` resolves the version named
inside an existing value. Everything else in Vaulted goes through these two
calls, which is what lets a KMS drop in without anything above changing.

### Envelope encryption

The trait is already shaped for it:

```text
   KMS master key  (never leaves the KMS)
         │  Decrypt(wrapped_dek)
         ▼
   data encryption key ──► KeyProvider::key(key_id, purpose) ──► Vault
```

A provider stores wrapped DEKs in configuration, unwraps on first use, and
caches. `examples/custom_key_provider.rs` is a complete sketch, cache included.
Cache with a TTL: the point of a KMS is that access can be revoked, and an
unbounded cache quietly opts out of that.

## The local provider

`LocalKeyProvider` keeps a keyring in process memory, loaded from a JSON file or
an environment variable. It is right for development, tests, and single-node
deployments where something outside the database manages the file.

```sh
vaulted init                    # writes ./vaulted.keys.json, mode 0600
vaulted key list
vaulted status
```

```rust
let provider = LocalKeyProvider::load_file("/etc/vaulted/keys.json")?;
let provider = LocalKeyProvider::from_env("VAULTED_KEYRING")?;
```

Loading refuses a file that group or other can read; pass
`load_file_ignoring_permissions` if you have a reason. The env-var path is
convenient in containers and comes with the usual costs: the value is visible to
anything that can read the process environment, and it tends to end up in
orchestrator manifests and crash dumps.

What it does not have: access control, audit trail, hardware protection,
revocation. Those are the reasons to use a KMS in production.

## Rotating an encryption key

Cheap, because it needs only the ciphertext.

### 1. Add a key and promote it

```sh
vaulted key rotate            # generates the next version, makes it primary
```

New writes use it immediately. Existing values keep naming the key they were
written with, and keep decrypting. **Nothing is broken during this window** — a
deployment can sit here for as long as the backfill takes.

### 2. Backfill

```rust
for row in batch {
    let value: EncryptedValue = row.email_ciphertext.parse()?;
    if !vault.needs_rotation("users.email", &value)? {
        continue;                       // already current, skip cheaply
    }
    let rotated = vault.rotate("users.email", &value)?;
    // UPDATE users SET email_ciphertext = $1, email_blind_index = $2 WHERE id = $3
}
```

`rotate` is non-destructive: it returns the new value and leaves persisting it
to you. A crashed job resumes by running again, because `needs_rotation` makes
already-migrated rows free to skip.

From the shell, for values piped one per line:

```sh
vaulted rotate -f users.email < old-values.txt > new-values.txt
```

Run it in batches sized for your write throughput, not in one transaction across
the whole table.

### 3. Verify, then retire

Confirm no row still names the old version, then remove it from the keyring.
**Not before.** A value naming a key that no longer exists is unreadable
forever; `Error::UnknownKey` names the missing version so you can put it back,
but only if you still have it.

That verification works because every ciphertext names the key version that
produced it. A blind index does not — the column holds the index bytes and
nothing else, [by design](BLIND_INDEXES.md) — so an index key is not retired by
inspecting rows. It is retired by finishing the dual-write window below:
dropping the old index column, and only then removing the key.

The CLI will not delete a key version for you. That is deliberate.

## Rotating a blind index key

Expensive, because computing an index requires the plaintext. There is no way
around this: that is what makes the index blind.

Two consequences:

1. **Pin the blind index key per field** so ordinary encryption-key rotation
   does not drag your indexes along:

   ```rust
   FieldConfig::new("users.email")?
       .with_normalization(Normalization::Email)
       .with_blind_index(BlindIndexConfig::new().with_key_id(KeyId::new("bi-0001")?))
   ```

   Without pinning, the index follows the primary key, and every
   encryption-key rotation forces a full reindex.

2. **When you must rotate it**, run a dual-write window: add a second index
   column, backfill it with the new key while queries still use the old one,
   switch reads over, then drop the old column. `Vault::rotate` returns the
   recomputed index precisely because that is the moment the plaintext is in
   hand anyway.

## When a key is compromised

Rotating stops *future* exposure. It does nothing for a dump the attacker
already has: those values were encrypted with the leaked key and stay readable
to whoever holds it. Rotation is damage limitation, not repair. Plan on the
assumption that data exposed under a leaked key is exposed.

## Checklist

- [ ] Keys are not in the database, and not in its backups
- [ ] The keyring is not in version control (`.gitignore` covers the obvious
      patterns; check anyway)
- [ ] Key files are `0600` and owned by the service user
- [ ] Blind index keys are pinned per field
- [ ] A rotation runbook exists and someone has rehearsed it
- [ ] Encryption key versions are retired only after verifying no ciphertext
      still names them
- [ ] Blind index key versions are retired only after the column computed under
      them is dropped — no row records which key built an index
- [ ] Production uses a KMS, not a keyfile
