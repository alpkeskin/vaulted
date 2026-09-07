//! `#[derive(Vaulted)]` for [`vaulted-core`](https://docs.rs/vaulted-core).
//!
//! A struct declares which of its fields are encrypted, and the macro derives
//! the three things that would otherwise be written out three times and drift:
//! the vault's field configuration, the field-name constants used at every call
//! site, and the database columns the values occupy.
//!
//! ```ignore
//! #[derive(Vaulted)]
//! #[vaulted(table = "users")]
//! struct User {
//!     id: i64,
//!     name: String,
//!
//!     #[vaulted(encrypt, blind_index, normalize = "email")]
//!     email: String,
//!
//!     #[vaulted(encrypt)]
//!     national_id: Option<String>,
//! }
//!
//! let vault = Vault::builder()
//!     .key_provider(provider)
//!     .fields(User::field_configs()?)
//!     .build()?;
//!
//! let row = vault.protect(User::EMAIL_FIELD, &email)?;
//! ```
//!
//! # Options
//!
//! On the struct:
//!
//! - `table = "users"` — required. Field names become `users.<field>`.
//! - `crate = "..."` — where the generated code reaches `vaulted-core`.
//!   Defaults to `::vaulted_core`, which resolves only if your crate depends on
//!   it directly. If you depend on `vaulted-postgres` alone, or renamed the
//!   dependency, name the path here — for example
//!   `crate = "vaulted_postgres::vaulted_core"`.
//!
//! On a field:
//!
//! - `encrypt` — required for the field to be part of the schema. Spelled out
//!   rather than inferred from the other options, because a field that is
//!   silently not encrypted is the failure this crate exists to prevent.
//! - `blind_index` — give the field a searchable index.
//! - `normalize = "..."` — `none`, `trim`, `lowercase`, `trim_lowercase`,
//!   `email`, `digits_only`. Affects blind index input only; the encrypted
//!   value is always the exact bytes given.
//! - `rename = "..."` — the field name segment, if it should not be the Rust
//!   field's name. The name is authenticated associated data, so changing it
//!   later orphans existing values. The default column names follow it.
//! - `ciphertext_column`, `blind_index_column` — default to
//!   `<name>_ciphertext` and `<name>_blind_index`, where `<name>` is the
//!   `rename` if there is one and the Rust field's name otherwise, with `-`,
//!   `.` and `/` written as `_` so the column reads like a column. Set them
//!   explicitly for a table whose columns were named before any of this.
//! - `nullable = true` / `nullable = false` — whether the columns accept NULL.
//!   Defaults to whether the Rust field is spelled `Option<_>`, which is a
//!   textual check: an alias for `Option` reads as non-optional, and a column
//!   may have to accept NULL for rows written before the field existed. This is
//!   the override for both.
//! - `blind_index_bytes = 16` — truncate the index. 8..=32.
//! - `blind_index_key = "..."` — pin the index to a key version.
//!
//! # What is checked at compile time
//!
//! Field names and their character set, the field name length limit, key
//! identifiers and their character set, the blind index length range, duplicate
//! field names, duplicate columns, colliding generated constants, blind index
//! options on a field with no blind index, and `normalize` on a field with no
//! blind index — where it would quietly do nothing.
//!
//! Those rules are mirrored from `vaulted-core`, because a macro cannot call
//! into the crate it generates code for. The core validates them again at
//! run time, so a drift between the two costs a later error rather than a wrong
//! one, and `tests/derive.rs` pins the limits against the core's constants.

#![forbid(unsafe_code)]

mod expand;
mod parse;

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

/// Derives [`VaultedSchema`](https://docs.rs/vaulted-core) for a struct.
///
/// See the [crate documentation](crate) for the available options.
#[proc_macro_derive(Vaulted, attributes(vaulted))]
pub fn derive_vaulted(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match parse::parse(&input) {
        Ok(model) => expand::expand(&model, &input.vis).into(),
        Err(error) => error.to_compile_error().into(),
    }
}
