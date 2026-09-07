# vaulted-postgres

PostgreSQL glue for [`vaulted-core`](https://crates.io/crates/vaulted-core),
part of [Vaulted](https://github.com/alpkeskin/vaulted).

Two things, and nothing else:

- **Driver glue** for `EncryptedValue` and `BlindIndex`, so encrypted values
  bind as query parameters like any other type. `ToSql`/`FromSql` under the
  `postgres-types` feature, `Type`/`Encode`/`Decode` under `sqlx-0_8` and
  `sqlx-0_9`. Pick the one your application already uses, or several.
- **DDL** generated from a `VaultedSchema`: the columns a set of encrypted
  fields needs, the migration that adds them to a populated table, and the
  indexes that make blind index lookups fast.

It builds no queries beyond a single `WHERE` fragment, and it does not talk to a
database. Rewriting SQL is a much larger problem than this crate is trying to
solve, and a half-working version of it would be worse than none.

```rust
use vaulted_postgres::{ddl, Vaulted, VaultedSchema};

#[derive(Vaulted)]
#[vaulted(table = "users")]
struct User {
    id: i64,
    #[vaulted(encrypt, blind_index, normalize = "email")]
    email: String,
}

for statement in ddl::add_column_statements::<User>(User::TABLE) {
    client.execute(&statement, &[]).await?;
}
```

## Features

| Feature | Default | What it turns on |
|---|:-:|---|
| `derive` | ✅ | Re-exports `#[derive(Vaulted)]`, so this crate is the only dependency you need |
| `postgres-types` | ✅ | `ToSql`/`FromSql`, what both `tokio-postgres` and the synchronous `postgres` re-export. No runtime of its own |
| `sqlx-0_8` | | `Type`/`Encode`/`Decode` against sqlx 0.8 |
| `sqlx-0_9` | | The same against sqlx 0.9. Raises the minimum supported Rust version to 1.94 |

The sqlx features name a version because a trait impl applies only to the sqlx
that defined it: built against the wrong one, the feature compiles and then does
nothing. Enabling both is supported and gives two independent sets of impls.

Licensed under the MIT license.
