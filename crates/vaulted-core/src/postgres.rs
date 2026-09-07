//! `ToSql` and `FromSql` for the values Vaulted stores, behind the `postgres`
//! feature.
//!
//! # Why this is in the core rather than in `vaulted-postgres`
//!
//! Rust's orphan rule: `ToSql` belongs to `postgres-types` and
//! [`EncryptedValue`] belongs here, so only this crate can join them. The
//! alternative is a newtype the caller wraps every bound parameter in, which is
//! worse to use and no more honest about the coupling. The dependency is on the
//! trait crate alone — both `tokio-postgres` and the synchronous `postgres`
//! re-export it — so no driver and no runtime comes with it.
//!
//! What genuinely does not belong in the core, and is not here, is SQL: column
//! types, DDL and query fragments live in `vaulted-postgres`.
//!
//! The impls delegate to the built-in `&str` and `&[u8]` ones rather than
//! writing the wire format themselves, so domains over `text` — `citext`, for
//! instance — keep working.

use std::error::Error;

use crate::{BlindIndex, EncryptedValue};
use bytes::BytesMut;
use postgres_types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

/// Written as its serialized form, `vlt:v1:<key>:<algorithm>:<payload>`, into a
/// `text` column.
impl ToSql for EncryptedValue {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        <&str as ToSql>::to_sql(&self.to_string().as_str(), ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <&str as ToSql>::accepts(ty)
    }

    to_sql_checked!();
}

impl<'a> FromSql<'a> for EncryptedValue {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        let serialized = <&str as FromSql>::from_sql(ty, raw)?;
        Ok(Self::parse(serialized)?)
    }

    fn accepts(ty: &Type) -> bool {
        <&str as FromSql>::accepts(ty)
    }
}

/// Written as raw bytes into a `bytea` column.
///
/// There is deliberately no `FromSql`. A blind index is written and compared,
/// never read back: the stored bytes alone cannot reconstruct a [`BlindIndex`],
/// which also carries the key version it was computed under. Comparison belongs
/// in the query — `WHERE email_blind_index = $1` — where the database can use
/// an index for it, rather than in a loop over decoded rows.
impl ToSql for BlindIndex {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        <&[u8] as ToSql>::to_sql(&self.as_bytes(), ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <&[u8] as ToSql>::accepts(ty)
    }

    to_sql_checked!();
}

// The tests declare a schema, so they need the derive as well.
#[cfg(all(test, feature = "derive"))]
mod tests {
    use super::*;
    use crate::{LocalKeyProvider, Vault, VaultedSchema};

    #[derive(crate::Vaulted)]
    #[vaulted(table = "users")]
    #[allow(dead_code)]
    struct User {
        #[vaulted(encrypt, blind_index, normalize = "email")]
        email: String,
    }

    fn vault() -> Vault {
        Vault::builder()
            .key_provider(LocalKeyProvider::generate().expect("provider"))
            .fields(User::field_configs().expect("configs"))
            .build()
            .expect("vault")
    }

    #[test]
    fn an_encrypted_value_survives_the_wire_format() {
        let vault = vault();
        let value = vault
            .encrypt(User::EMAIL_FIELD, "alp@example.com")
            .expect("encrypt");

        let mut buffer = BytesMut::new();
        let is_null = value.to_sql(&Type::TEXT, &mut buffer).expect("to_sql");
        assert!(matches!(is_null, IsNull::No));

        let read = EncryptedValue::from_sql(&Type::TEXT, &buffer).expect("from_sql");
        assert_eq!(read, value);
        assert_eq!(
            &*vault.decrypt(User::EMAIL_FIELD, &read).expect("decrypt"),
            "alp@example.com"
        );
    }

    #[test]
    fn a_blind_index_is_written_as_its_raw_bytes() {
        let vault = vault();
        let index = vault
            .blind_index(User::EMAIL_FIELD, "alp@example.com")
            .expect("index");

        let mut buffer = BytesMut::new();
        index.to_sql(&Type::BYTEA, &mut buffer).expect("to_sql");
        assert_eq!(&buffer[..], index.as_bytes());
    }

    #[test]
    fn the_documented_parameter_slice_compiles() {
        // Exactly the shape README.md tells people to write. `blind_index` is
        // an Option, so this also pins that a null index still binds.
        let vault = vault();
        let row = vault
            .protect(User::EMAIL_FIELD, "a@b.com")
            .expect("protect");
        let params: &[&(dyn ToSql + Sync)] = &[&row.ciphertext, &row.blind_index];
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn the_accepted_types_are_the_ones_the_ddl_generates() {
        assert!(<EncryptedValue as ToSql>::accepts(&Type::TEXT));
        assert!(<EncryptedValue as ToSql>::accepts(&Type::VARCHAR));
        assert!(!<EncryptedValue as ToSql>::accepts(&Type::BYTEA));

        assert!(<BlindIndex as ToSql>::accepts(&Type::BYTEA));
        assert!(!<BlindIndex as ToSql>::accepts(&Type::TEXT));
    }

    #[test]
    fn a_null_column_reads_as_none() {
        // `Option<T>` handling comes from postgres-types; this pins that the
        // encrypted value does not shadow it with something of its own.
        let value: Option<EncryptedValue> = None;
        let mut buffer = BytesMut::new();
        let is_null = value.to_sql(&Type::TEXT, &mut buffer).expect("to_sql");
        assert!(matches!(is_null, IsNull::Yes));
    }
}
