# Threat model

## The attacker

> The attacker obtains a complete dump of the database.

A stolen backup, a compromised replica, an over-broad `SELECT` from a service
that should not have had access, a decommissioned disk. They have every table,
every row, every column, and as much time as they want.

They do **not** have the keys, because the keys are never stored in the database
and never travel with its backups.

## What Vaulted defends

A field-encrypted column yields no plaintext to an attacker in that position.
Every value is authenticated, so tampering is detected rather than silently
decrypted into something else.

## What the attacker still learns

This is the part worth reading twice. Encrypting fields is not the same as
encrypting a database.

| Visible in the dump | Why |
|---------------------|-----|
| Value lengths, to the byte | AEAD ciphertext is the length of its plaintext |
| Row counts, table structure, foreign keys | Nothing about the schema is encrypted |
| Which columns are encrypted, with which key version and algorithm | The ciphertext header is in the clear, by design |
| Timestamps, sequence numbers, `id` ordering | Unencrypted columns stay unencrypted |
| **For indexed columns: which rows share a value** | A blind index is deterministic |
| **For indexed columns: how often each value occurs** | Same |

The last two are the ones that surprise people. A blind index on a column with
few distinct values — a country, a subscription tier, a yes/no answer — is close
to publishing the column. The distribution of index values can be matched
against public statistics, and once one row's plaintext is learned by any other
means, every row sharing that index is learned with it.

Blind indexes are for high-entropy identifiers you must look rows up by. See
[BLIND_INDEXES.md](BLIND_INDEXES.md).

## What Vaulted does not defend against

**A compromised application process.** Vaulted decrypts in your process, so an
attacker with code execution there, or a debugger attached to it, sees
plaintext. So does anyone who can read the process's memory or a core dump.
Nothing at this layer changes that.

**A compromised key store.** Keys plus dump equals plaintext. This is why the
`KeyProvider` abstraction exists and why a KMS is the production answer: it adds
access control, an audit trail, and the ability to revoke.

**An attacker who can query your application.** If your application decrypts a
row and shows it, an attacker who can make it do that gets the plaintext. Field
encryption protects data at rest, not authorization mistakes.

**Traffic analysis and timing.** Vaulted compares blind indexes in constant time
and returns one indistinguishable error for every decryption failure, so it does
not add an oracle of its own. It cannot do anything about what your query
patterns reveal to someone watching the database.

**Range queries, sorting, prefix search.** Not supported, and deliberately so.
Order-preserving and order-revealing encryption leak enough to reconstruct much
of a column; if you need `WHERE age > 30` on encrypted data, this is not the
tool.

**Backups of the key file.** A keyring backed up into the same S3 bucket as the
database dump has undone the entire exercise. Keep them in separate trust
domains, with separate access control.

## Cryptographic assumptions

- AES-256-GCM and XChaCha20-Poly1305 are secure AEADs, as implemented by the
  RustCrypto crates. Vaulted implements no cryptography itself.
- HMAC-SHA256 is a secure PRF, so a blind index reveals nothing about its input
  without the key.
- The operating system CSPRNG produces unpredictable bytes. If `getrandom`
  fails, the operation fails; Vaulted never falls back to a weaker source.

### Nonce budget

Nonces are random, not counters, because Vaulted has no coordinated state across
processes. For AES-256-GCM's 96-bit nonce, the collision probability after *q*
encryptions under one key is about *q²/2⁹⁷*. At 2³² encryptions (~4 billion) it
is around 2⁻³³ — small, and the standard guidance is to stay under that. Rotate
the encryption key before a single version encrypts on the order of a billion
values.

XChaCha20-Poly1305's 192-bit nonce makes this a non-issue; it is available as a
per-field algorithm override for workloads that write enormously.

## Residual risks to accept explicitly

1. **Correlation across columns is prevented, correlation within one is not.**
   The field name is mixed into both the AAD and the blind index, so the same
   value in `users.email` and `users.phone` produces unrelated ciphertext and
   unrelated indexes. Within one column, equality is visible whenever that
   column is indexed.

2. **Deleting a key version deletes data.** No recovery, no support ticket, no
   exception. `Vault::rotate` is non-destructive and the CLI will not remove a
   key for you, but an operator with the keyring file can still do it.

3. **The local key provider is for development.** It has no access control, no
   audit trail and no hardware protection. Production means a KMS behind the
   `KeyProvider` trait.

4. **Normalization decisions are permanent.** Changing a field's normalization
   rule changes its blind indexes, which means reindexing every row — which
   means decrypting every row.

## Reporting a problem

See [../SECURITY.md](../SECURITY.md).
