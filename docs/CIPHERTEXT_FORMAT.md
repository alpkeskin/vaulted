# Ciphertext format v1

A stored value is a single ASCII string:

```text
vlt:v1:key-0001:aes256gcm:BASE64URL_NOPAD(nonce || ciphertext || tag)
└┬┘ └┬┘ └──┬───┘ └───┬───┘ └──────────────────┬──────────────────────┘
 │   │     │         │                        payload
 │   │     │         AEAD algorithm
 │   │     key version
 │   format version
 magic prefix
```

Example:

```text
vlt:v1:key-0001:aes256gcm:G_--PFtn4OT052Cj8Q9TS3_F4oU5DjL5kePSvCyHv9FChRZ4kns2rnhtfg
```

## Grammar

```text
value      = prefix ":" version ":" key-id ":" algorithm ":" payload
prefix     = "vlt"
version    = "v" 1*DIGIT                  ; currently always "v1"
key-id     = 1*64( ALPHA / DIGIT / "." / "_" / "-" )
algorithm  = "aes256gcm" / "xchacha20poly1305"
payload    = 1*( base64url character )    ; unpadded, RFC 4648 §5
```

Exactly five segments. No segment may contain `:`, which is why the key
identifier character set is restricted.

## Payload

| Part       | AES-256-GCM | XChaCha20-Poly1305 |
|------------|-------------|--------------------|
| nonce      | 12 bytes    | 24 bytes           |
| ciphertext | *n* bytes   | *n* bytes          |
| tag        | 16 bytes    | 16 bytes           |

The nonce is drawn from the OS CSPRNG for every operation. No API accepts a
caller-supplied nonce.

Encoding is unpadded URL-safe base64, and the decoder rejects padding, standard
(`+/`) alphabet characters and non-canonical trailing bits. One plaintext under
one nonce therefore has exactly one serialization, so a stored value can be
compared byte-for-byte with a freshly serialized one.

## Associated data

The header is not merely a hint — it is authenticated. Each encryption
authenticates:

```text
AAD = "vaulted-aad-v1"
    || u32be(len(header)) || header       ; "vlt:v1:key-0001:aes256gcm"
    || u32be(len(field))  || field        ; "users.email"
```

Consequences worth stating plainly:

- Rewriting `aes256gcm` to `xchacha20poly1305` in a stored value breaks
  authentication rather than causing a confused decryption.
- Relabelling a value as belonging to another key version breaks authentication.
- A ciphertext copied from one column to another fails to decrypt, because the
  field name is part of the AAD but not part of the stored value.

Lengths are framed explicitly so that `header="a", field="bc"` and
`header="ab", field="c"` cannot produce the same associated data.

**This encoding is part of the on-disk contract.** Changing the domain label,
the framing, or the header string makes every existing ciphertext undecryptable.

## What the format reveals

Anyone holding a stored value learns:

- that it is a Vaulted value (the prefix),
- which key version and algorithm it needs,
- the plaintext length, to the byte.

Length is inherent to a stream cipher construction. If lengths matter for your
data — a field with few possible values whose lengths differ — pad before
encrypting; the library does not pad for you, because a padding scheme that is
invisible to the caller is a padding scheme that silently changes the data.

## Sizing a column

For a plaintext of *n* bytes with AES-256-GCM:

```text
header  = 26 + len(key_id)          bytes   ("vlt:v1:" + key-id + ":aes256gcm:")
payload = ceil((n + 28) / 3) * 4    bytes   (base64 of nonce + ciphertext + tag)
```

A 16-byte email address under `key-0001` is 84 characters. `text` is the natural
column type; `bytea` works if you prefer to store `EncryptedValue::payload()`
plus your own framing, but then you own the header and lose the format
versioning that makes migration possible.

## Versioning and migration

The version segment exists so that the format can change without a flag day:

| Version | Status  | Notes |
|---------|---------|-------|
| `v1`    | current | AES-256-GCM and XChaCha20-Poly1305 |

A reader that meets an unknown version returns `Error::UnsupportedVersion`
rather than guessing. When `v2` arrives, deployments will run both for as long
as the backfill takes — exactly the way key rotation already works, and using
the same `Vault::rotate` primitive.

Note that the algorithm is a separate segment from the version, so switching a
field from AES-256-GCM to XChaCha20-Poly1305 is not a format change: values
written before the switch keep decrypting because each one names its own
algorithm.

## Parsing rules

The parser treats its input as hostile, because the database is the one place
the threat model assumes an attacker can write. It:

- requires exactly five segments and a known prefix;
- validates the key identifier before any key lookup happens;
- distinguishes "unknown algorithm" from "algorithm not compiled into this
  build", so a misconfigured deployment reports the truth;
- rejects non-canonical base64;
- checks the payload is long enough to hold a nonce and a tag before indexing
  into it;
- allocates nothing proportional to a length field an attacker controls.

`tests/hostile_input.rs` and `fuzz/` keep it honest.
