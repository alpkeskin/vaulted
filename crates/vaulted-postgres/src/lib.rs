//! PostgreSQL glue for [`vaulted-core`](https://docs.rs/vaulted-core).
//!
//! Two things, and nothing else:
//!
//! - Driver glue for [`EncryptedValue`](vaulted_core::EncryptedValue) and
//!   [`BlindIndex`](vaulted_core::BlindIndex), so encrypted values bind as
//!   query parameters like any other type: `ToSql`/`FromSql` under the
//!   `postgres-types` feature, `Type`/`Encode`/`Decode` under `sqlx-0_8` and
//!   `sqlx-0_9`. Pick the one your application already uses, or several. Rust's
//!   orphan rule keeps the impls themselves in `vaulted_core::postgres` and
//!   `vaulted_core::sqlx`; these features turn them on.
//! - DDL generated from a [`VaultedSchema`](vaulted_core::VaultedSchema): the
//!   columns a set of encrypted fields needs, the migration that adds them to a
//!   populated table, and the indexes that make blind index lookups fast. See
//!   [`ddl`].
//!
//! It builds no queries beyond a single `WHERE` fragment, and it does not talk
//! to a database. Rewriting SQL is a much larger problem than this crate is
//! trying to solve, and a half-working version of it would be worse than none.
//!
//! `postgres-types`, the default, is what both `tokio-postgres` and the
//! synchronous `postgres` re-export, so this works with either and pulls in no
//! runtime of its own. The sqlx features take `sqlx` with no runtime, no TLS
//! and no macros. They name a version because a trait impl applies only to the
//! sqlx that defined the trait: built against the wrong one, the feature
//! compiles and then does nothing. `sqlx-0_9` raises the minimum supported
//! Rust version to 1.94 — see the crate README.
//!
//! ```ignore
//! use vaulted_postgres::{ddl, Vaulted, VaultedSchema};
//!
//! #[derive(Vaulted)]
//! #[vaulted(table = "users")]
//! struct User {
//!     id: i64,
//!     #[vaulted(encrypt, blind_index, normalize = "email")]
//!     email: String,
//! }
//!
//! for statement in ddl::add_column_statements::<User>(User::TABLE) {
//!     client.execute(&statement, &[]).await?;
//! }
//!
//! let row = vault.protect(User::EMAIL_FIELD, &email)?;
//! client
//!     .execute(
//!         "INSERT INTO users (email_ciphertext, email_blind_index) VALUES ($1, $2)",
//!         &[&row.ciphertext, &row.blind_index],
//!     )
//!     .await?;
//!
//! let predicate = ddl::blind_index_predicate::<User>("email", 1).expect("searchable");
//! let sql = format!("SELECT id, email_ciphertext FROM users WHERE {predicate}");
//! let found = client.query(&sql, &[&vault.blind_index(User::EMAIL_FIELD, &email)?]).await?;
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

pub mod ddl;

/// The core crate, re-exported so that depending on this one is enough.
///
/// `#[derive(Vaulted)]` writes paths into your crate, and by default they point
/// at `::vaulted_core` — which resolves only if you depend on it directly. If
/// this crate is your only dependency, point the derive here:
///
/// ```ignore
/// #[derive(Vaulted)]
/// #[vaulted(table = "users", crate = "vaulted_postgres::vaulted_core")]
/// struct User { /* ... */ }
/// ```
pub use vaulted_core;

pub use vaulted_core::{EncryptedField, VaultedSchema};

#[cfg(feature = "derive")]
pub use vaulted_core::Vaulted;
