# Blind indexes

## The problem

AEAD ciphertext is randomized: encrypting the same address twice gives two
different values. That is what stops a dump from revealing which rows are equal
— and it is also what stops this from working:

```sql
SELECT * FROM users WHERE email_ciphertext = $1;   -- never matches
```

## The solution, and its price

Store a second, deterministic column beside the ciphertext:

```text
plaintext ──┬─► AES-256-GCM ──► email_ciphertext     (different every write)
            └─► HMAC-SHA256 ──► email_blind_index    (same every write)
```

```sql
SELECT * FROM users WHERE email_blind_index = $1;
```

The price is that the index is the same every write. Rows sharing a value share
an index, so a dump shows the equality structure and the frequency distribution
of the column. That is a real disclosure, which is why blind indexes are
**opt-in per field** in Vaulted rather than automatic.

Use them for high-entropy values you must look rows up by: email addresses,
national IDs, usernames, phone numbers. Do not use them for low-entropy columns
— country, plan tier, a boolean — where the frequency distribution alone
effectively reveals the column.

## Why HMAC and not SHA-256

A bare `SHA-256(email)` is recovered from a wordlist in seconds; the whole
input space of email addresses is enumerable. HMAC with a key the attacker does
not have makes the index opaque: with only the dump, they cannot test a guess.

The blind index key is separate material from the encryption key
(`KeyPurpose::BlindIndex`), so a leak of one does not automatically hand over
the other. See [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).

## What gets hashed

```text
message = "vaulted-blind-index-v1"
        || u32be(len(field)) || field           ; "users.email"
        || u32be(len(value)) || value           ; after normalization

index   = HMAC-SHA256(blind_index_key, message)[..output_bytes]
```

The field name is mixed in so that the same value in two columns produces two
unrelated indexes. Without it, a phone number that is also a username would make
the two columns joinable by anyone holding the dump. Lengths are framed so the
encoding is unambiguous.

Serialized form: `bi:v1:<key_id>:<lowercase hex>`. That is the transport form —
what the CLI prints, and what to pass between systems.

What goes in the database is the index alone: `BlindIndex::as_bytes()` in a
`bytea` column, or `to_hex()` in `text`. The key identifier deliberately stays
out of the column. Keeping it there would cost a column on every searchable
field to answer a question no query needs to ask, because rotating an index key
requires the plaintext of every row anyway — a full pass, not a lookup of stale
rows. The dual-write window in [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md) is how
that rotation is actually done.

The identifier still earns its place in the value. `BlindIndex::matches`
compares it along with the bytes, so two indexes computed under different keys
can never compare equal, collision or not.

## Normalization

Queries only find rows if the query computes the same index the write did. That
requires a canonical form, and canonicalization is exactly where a data-mangling
bug would live — so Vaulted draws a hard line:

> **Normalization applies to the blind index only. The encrypted value is always
> the exact bytes you passed in.**

`decrypt` gives back what was stored, spacing and casing intact. There is no
configuration that changes this.

| Rule | Effect | For |
|------|--------|-----|
| `None` | none (default) | opaque identifiers, values normalized upstream |
| `Trim` | strips surrounding whitespace | pasted values |
| `Lowercase` | Unicode lowercase | case-insensitive identifiers |
| `TrimLowercase` | both | general text |
| `Email` | trim, then lowercase the whole address | email addresses |
| `DigitsOnly` | keeps ASCII digits | phone numbers |
| `Custom(fn)` | yours | anything else |

Two caveats worth knowing before you pick one:

**`Email` lowercases the local part.** RFC 5321 says the local part is
case-sensitive; virtually no mail provider treats it that way, and virtually
every application treats addresses as case-insensitive. This rule matches the
application, not the RFC. If you need RFC behaviour, use `Trim` and lowercase
only the domain in your own `Custom` rule.

**`DigitsOnly` drops the `+`.** `+90 555 111 22 33` and `90-555-111-22-33` match;
`0555 111 22 33` does not, because those are different digits. If you need real
phone semantics, normalize to E.164 in your application and index with `None`.

Whatever you pick, it becomes part of the on-disk contract: changing a field's
rule invalidates every index already written for it, and recomputing them means
decrypting every row.

## Truncation

The default output is the full 32-byte HMAC. `with_output_bytes(n)` truncates to
between 8 and 32 bytes.

Truncation is not a space optimization to reach for casually. Shorter indexes
collide deliberately, which blurs equality a little — and gives your query false
positives that you must filter out after decrypting the candidate rows. Treat it
as a considered trade, and if you make it, make sure the query path actually
does the post-filter.

## Practical schema

```sql
CREATE TABLE users (
    id                 bigserial PRIMARY KEY,
    email_ciphertext   text  NOT NULL,
    email_blind_index  bytea NOT NULL
);

CREATE INDEX users_email_blind_index_idx ON users (email_blind_index);
```

A `UNIQUE` constraint on the blind index enforces uniqueness of the underlying
value — useful, and also worth thinking about: a failing insert tells the caller
that some row already holds that value, which is a small oracle you are choosing
to expose.

Never index the ciphertext column. It is different for every write, so the index
would be pure overhead.

## Compare in constant time

`BlindIndex::matches` and `PartialEq` use a constant-time comparison. When you
compare indexes in your own code — outside the database — use those rather than
`==` on the hex strings.
