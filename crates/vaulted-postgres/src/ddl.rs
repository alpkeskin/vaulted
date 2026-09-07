//! Generating the DDL an encrypted schema needs.
//!
//! Every function here takes the table name explicitly rather than reading
//! [`VaultedSchema::TABLE`]. That constant is the prefix of the *vault* field
//! names, which is part of the on-disk crypto contract; a SQL table can be
//! renamed freely and the two are only conventionally the same string. Passing
//! it in keeps the assumption from being silent — usually you pass `T::TABLE`.
//!
//! Identifiers are always double-quoted. That preserves the case and the
//! punctuation a field attribute may have asked for, at the cost of DDL that
//! looks more formal than hand-written SQL would.

use vaulted_core::{EncryptedField, VaultedSchema};

/// The column type a serialized ciphertext is stored as: the format is ASCII.
pub const CIPHERTEXT_SQL_TYPE: &str = "text";

/// The column type a blind index is stored as: raw bytes, at whatever length
/// the field's configuration asked for.
pub const BLIND_INDEX_SQL_TYPE: &str = "bytea";

/// Quotes an identifier for use in a statement.
fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// The type and nullability of each column a field occupies.
fn columns_of(field: &EncryptedField) -> Vec<(&'static str, &'static str)> {
    let mut out = vec![(field.ciphertext_column(), CIPHERTEXT_SQL_TYPE)];
    if let Some(index) = field.blind_index_column() {
        out.push((index, BLIND_INDEX_SQL_TYPE));
    }
    out
}

/// Column definitions for a `CREATE TABLE`, one fragment per column.
///
/// Fragments and not a whole statement: the rest of the table is not this
/// crate's business, and a statement that looked complete while silently
/// omitting your own columns would be worse than none.
///
/// ```ignore
/// CREATE TABLE users (
///     id bigserial PRIMARY KEY,
///     name text NOT NULL,
///     -- everything below from column_definitions::<User>()
///     "email_ciphertext" text NOT NULL,
///     "email_blind_index" bytea NOT NULL
/// );
/// ```
pub fn column_definitions<T: VaultedSchema>() -> Vec<String> {
    let mut out = Vec::new();
    for field in T::ENCRYPTED_FIELDS {
        let null = if field.is_optional() { "" } else { " NOT NULL" };
        for (column, sql_type) in columns_of(field) {
            out.push(format!("{} {sql_type}{null}", quote(column)));
        }
    }
    out
}

/// `ALTER TABLE ... ADD COLUMN` for encrypting a table that already has rows.
///
/// The columns are added **nullable**, whatever the Rust field says, because a
/// `NOT NULL` column cannot be added to a populated table without a default —
/// and a default for a ciphertext column is a plaintext value in your schema.
/// The migration is three steps, in this order:
///
/// 1. [`add_column_statements`] — the columns appear, empty.
/// 2. Backfill: read each row's plaintext, write the ciphertext and index.
/// 3. [`set_not_null_statements`] — the constraint goes on once it can hold.
pub fn add_column_statements<T: VaultedSchema>(table: &str) -> Vec<String> {
    let table = quote(table);
    T::ENCRYPTED_FIELDS
        .iter()
        .flat_map(columns_of)
        .map(|(column, sql_type)| {
            format!(
                "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {} {sql_type};",
                quote(column)
            )
        })
        .collect()
}

/// `SET NOT NULL` for the columns whose Rust field is not an `Option`.
///
/// Run after the backfill. Postgres validates the constraint against every
/// existing row, so this is where a backfill that missed rows is caught.
pub fn set_not_null_statements<T: VaultedSchema>(table: &str) -> Vec<String> {
    let table = quote(table);
    T::ENCRYPTED_FIELDS
        .iter()
        .filter(|field| !field.is_optional())
        .flat_map(columns_of)
        .map(|(column, _)| {
            format!(
                "ALTER TABLE {table} ALTER COLUMN {} SET NOT NULL;",
                quote(column)
            )
        })
        .collect()
}

/// `CREATE INDEX` for every blind index column, and only those.
///
/// The ciphertext columns are deliberately absent: a fresh nonce per write
/// makes them different every time, so an index on one is pure overhead that
/// can never serve a query.
///
/// The index is named `<table>_<column>_idx`. PostgreSQL truncates identifiers
/// at 63 bytes, so a long table and column together can produce two statements
/// that name the same index — and because of the `IF NOT EXISTS`, the second
/// would quietly do nothing and leave that column unindexed. Check the names if
/// your identifiers are long; the statements are strings, and editing one
/// before running it is expected.
pub fn create_index_statements<T: VaultedSchema>(table: &str) -> Vec<String> {
    let quoted = quote(table);
    T::ENCRYPTED_FIELDS
        .iter()
        .filter_map(EncryptedField::blind_index_column)
        .map(|column| {
            format!(
                "CREATE INDEX IF NOT EXISTS {} ON {quoted} ({});",
                quote(&format!("{table}_{column}_idx")),
                quote(column)
            )
        })
        .collect()
}

/// The `WHERE` fragment that looks a row up by one field's blind index.
///
/// `parameter` is the placeholder number, so the fragment composes with
/// whatever else the query already binds:
///
/// ```ignore
/// let predicate = blind_index_predicate::<User>("email", 1).unwrap();
/// let sql = format!("SELECT id, email_ciphertext FROM users WHERE {predicate}");
/// // SELECT id, email_ciphertext FROM users WHERE "email_blind_index" = $1
/// let rows = client.query(&sql, &[&vault.blind_index(User::EMAIL_FIELD, input)?]).await?;
/// ```
///
/// Returns `None` if the field has no blind index, which is the only honest
/// answer: there is no equality query for a column that was deliberately left
/// unsearchable.
///
/// # Panics
///
/// If `parameter` is zero. PostgreSQL placeholders start at `$1`, so `$0` is a
/// syntax error the database would only report once the query ran — long after
/// the mistake was made.
pub fn blind_index_predicate<T: VaultedSchema>(
    struct_field: &str,
    parameter: usize,
) -> Option<String> {
    assert!(
        parameter >= 1,
        "PostgreSQL parameters are numbered from $1; got ${parameter}"
    );
    let column = T::encrypted_field(struct_field)?.blind_index_column()?;
    Some(format!("{} = ${parameter}", quote(column)))
}

#[cfg(all(test, feature = "derive"))]
mod tests {
    use super::*;
    use crate::Vaulted;

    #[derive(Vaulted)]
    #[vaulted(table = "users")]
    #[allow(dead_code)]
    struct User {
        id: i64,
        name: String,

        #[vaulted(encrypt, blind_index, normalize = "email")]
        email: String,

        #[vaulted(encrypt, blind_index, normalize = "digits_only")]
        phone: Option<String>,

        #[vaulted(encrypt, rename = "tckn")]
        national_id: String,
    }

    #[test]
    fn create_table_fragments_follow_the_rust_types() {
        assert_eq!(
            column_definitions::<User>(),
            [
                "\"email_ciphertext\" text NOT NULL",
                "\"email_blind_index\" bytea NOT NULL",
                // `phone` is an Option, so both of its columns are nullable.
                "\"phone_ciphertext\" text",
                "\"phone_blind_index\" bytea",
                "\"tckn_ciphertext\" text NOT NULL",
            ]
        );
    }

    #[test]
    fn columns_are_added_nullable_and_constrained_afterwards() {
        let added = add_column_statements::<User>("users");
        assert_eq!(added.len(), 5);
        assert!(
            added
                .iter()
                .all(|statement| !statement.contains("NOT NULL")),
            "a NOT NULL column cannot be added to a populated table: {added:?}"
        );
        assert_eq!(
            added[0],
            "ALTER TABLE \"users\" ADD COLUMN IF NOT EXISTS \"email_ciphertext\" text;"
        );

        let constrained = set_not_null_statements::<User>("users");
        assert_eq!(
            constrained,
            [
                "ALTER TABLE \"users\" ALTER COLUMN \"email_ciphertext\" SET NOT NULL;",
                "ALTER TABLE \"users\" ALTER COLUMN \"email_blind_index\" SET NOT NULL;",
                "ALTER TABLE \"users\" ALTER COLUMN \"tckn_ciphertext\" SET NOT NULL;",
            ],
            "the optional field is left out"
        );
    }

    #[test]
    fn only_blind_index_columns_are_indexed() {
        assert_eq!(
            create_index_statements::<User>("users"),
            [
                "CREATE INDEX IF NOT EXISTS \"users_email_blind_index_idx\" \
                 ON \"users\" (\"email_blind_index\");",
                "CREATE INDEX IF NOT EXISTS \"users_phone_blind_index_idx\" \
                 ON \"users\" (\"phone_blind_index\");",
            ],
            "a ciphertext column differs on every write; indexing one is overhead"
        );
    }

    #[test]
    fn a_predicate_exists_only_for_a_searchable_field() {
        assert_eq!(
            blind_index_predicate::<User>("email", 1).as_deref(),
            Some("\"email_blind_index\" = $1")
        );
        assert_eq!(
            blind_index_predicate::<User>("phone", 3).as_deref(),
            Some("\"phone_blind_index\" = $3")
        );
        assert_eq!(blind_index_predicate::<User>("national_id", 1), None);
        assert_eq!(blind_index_predicate::<User>("name", 1), None);
        assert_eq!(blind_index_predicate::<User>("nonexistent", 1), None);
    }

    #[test]
    #[should_panic(expected = "numbered from $1")]
    fn a_zero_parameter_is_a_mistake_not_a_query() {
        // `$0` is a syntax error, and a database would only say so at run time.
        let _ = blind_index_predicate::<User>("email", 0);
    }

    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote("Mixed Case"), "\"Mixed Case\"");
        assert_eq!(quote("with\"quote"), "\"with\"\"quote\"");
    }
}
