# vaulted-derive

`#[derive(Vaulted)]` for [`vaulted-core`](https://crates.io/crates/vaulted-core),
part of [Vaulted](https://github.com/alpkeskin/vaulted).

A struct declares which of its fields are encrypted, and the macro derives the
three things that would otherwise be written out three times and drift apart:
the vault's field configuration, the field-name constants used at every call
site, and the database columns the values occupy.

```rust
#[derive(Vaulted)]
#[vaulted(table = "users")]
struct User {
    id: i64,
    name: String,

    #[vaulted(encrypt, blind_index, normalize = "email")]
    email: String,

    #[vaulted(encrypt)]
    national_id: Option<String>,
}

let vault = Vault::builder()
    .key_provider(provider)
    .fields(User::field_configs()?)
    .build()?;

let row = vault.protect(User::EMAIL_FIELD, &email)?;
```

`encrypt` is spelled out per field rather than inferred from the other options,
because a field that is silently *not* encrypted is the failure this crate
exists to prevent.

You do not normally depend on this crate directly: enable the `derive` feature
of `vaulted-core` or `vaulted-postgres`, which re-export it. The full attribute
reference is in the [API documentation](https://docs.rs/vaulted-derive).

Licensed under the MIT license.
