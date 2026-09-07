//! Compile-time schema for structs that carry encrypted fields.
//!
//! [`VaultedSchema`] is what `#[derive(Vaulted)]` implements. It exists so a
//! struct definition can be the single source of truth for three things that
//! otherwise drift apart: the [`FieldConfig`] set the vault is built with, the
//! field names passed to [`Vault::protect`](crate::Vault::protect), and the
//! database columns the values are written to.
//!
//! Drift between those is the failure this module is here to prevent. A field
//! name is authenticated associated data, so a typo in one of the three places
//! does not produce a wrong answer — it produces an undecryptable column, found
//! in production. Deriving all three from one declaration makes that typo a
//! compile error instead.
//!
//! The derive is behind the `derive` feature. Implementing the trait by hand is
//! supported and unremarkable; the macro only writes what you would have.
//!
//! What is deliberately absent here is SQL. Column *names* are a property of
//! the declaration; column *types* are a property of a database, and `bytea` is
//! not a type every database has. DDL generation lives in `vaulted-postgres`,
//! so that this crate keeps knowing nothing about any particular one.

use crate::error::Result;
use crate::field::FieldConfig;

/// One encrypted field, as declared on a struct.
///
/// Constructed by the derive macro in a `const` context; the accessors are the
/// stable surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedField {
    struct_field: &'static str,
    name: &'static str,
    ciphertext_column: &'static str,
    blind_index_column: Option<&'static str>,
    optional: bool,
}

impl EncryptedField {
    /// Declares a field. Called by generated code; the arguments are already
    /// validated at macro expansion time.
    pub const fn new(
        struct_field: &'static str,
        name: &'static str,
        ciphertext_column: &'static str,
        blind_index_column: Option<&'static str>,
        optional: bool,
    ) -> Self {
        Self {
            struct_field,
            name,
            ciphertext_column,
            blind_index_column,
            optional,
        }
    }

    /// The Rust field name, for example `email`.
    pub const fn struct_field(&self) -> &'static str {
        self.struct_field
    }

    /// The vault field name, for example `users.email`.
    ///
    /// This is the string that goes into the associated data, so it is part of
    /// the on-disk contract. Renaming it orphans every value already written.
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The column holding the serialized ciphertext.
    pub const fn ciphertext_column(&self) -> &'static str {
        self.ciphertext_column
    }

    /// The column holding the blind index, if the field is searchable.
    pub const fn blind_index_column(&self) -> Option<&'static str> {
        self.blind_index_column
    }

    /// Whether the Rust field is an `Option`, and so the columns are nullable.
    pub const fn is_optional(&self) -> bool {
        self.optional
    }

    /// Whether the field has a blind index.
    pub const fn is_searchable(&self) -> bool {
        self.blind_index_column.is_some()
    }

    /// Every column this field occupies, ciphertext and index alike.
    pub fn columns(&self) -> Vec<&'static str> {
        let mut out = vec![self.ciphertext_column];
        out.extend(self.blind_index_column);
        out
    }
}

/// A struct whose encrypted fields are declared once, at compile time.
///
/// Derive it rather than writing it:
///
/// ```ignore
/// #[derive(Vaulted)]
/// #[vaulted(table = "users")]
/// struct User {
///     id: i64,
///     name: String,
///     #[vaulted(encrypt, blind_index, normalize = "email")]
///     email: String,
/// }
/// ```
pub trait VaultedSchema {
    /// The table these fields live on; the prefix of every field name.
    const TABLE: &'static str;

    /// Every encrypted field on the struct, in declaration order.
    const ENCRYPTED_FIELDS: &'static [EncryptedField];

    /// The [`FieldConfig`] set to build the vault with.
    ///
    /// Pass it straight to [`VaultBuilder::fields`](crate::vault::VaultBuilder::fields).
    /// The names are validated at macro expansion time, so this only fails if
    /// the trait was implemented by hand with an invalid one.
    fn field_configs() -> Result<Vec<FieldConfig>>;

    /// Looks up a field by its Rust field name.
    fn encrypted_field(struct_field: &str) -> Option<&'static EncryptedField> {
        Self::ENCRYPTED_FIELDS
            .iter()
            .find(|f| f.struct_field() == struct_field)
    }

    /// Every column the encrypted fields occupy, ciphertext and index alike.
    fn columns() -> Vec<&'static str> {
        Self::ENCRYPTED_FIELDS
            .iter()
            .flat_map(EncryptedField::columns)
            .collect()
    }
}
