//! `Type`, `Encode` and `Decode` for the values Vaulted stores, behind the
//! `sqlx-0_8` and `sqlx-0_9` features.
//!
//! The counterpart of [`postgres`](crate::postgres), for applications on `sqlx`
//! rather than on `tokio-postgres`. Both are here for the same reason: the
//! orphan rule lets only this crate join a foreign trait to a type it owns.
//! Neither pulls in a driver — `sqlx` is taken with no runtime, no TLS and no
//! macros — and enabling one does not affect the other.
//!
//! # Why the features name a version
//!
//! A trait impl applies only to the exact crate version that defines the trait.
//! `sqlx 0.8::Encode` and `sqlx 0.9::Encode` are different traits, so an impl
//! written against one is invisible to an application on the other — the
//! feature would compile and then do nothing, which is the quietest kind of
//! wrong. Naming the version makes the coupling explicit, and lets both lines be
//! supported at once: enable either, or both, and you get one independent set of
//! impls per version.
//!
//! Each raises the minimum Rust version for the build that enables it: 1.88 for
//! 0.8, which reaches `url` -> `idna` -> `icu_*`, and 1.94 for 0.9, which
//! declares it. Neither is on by default, so the crate's own floor stays at
//! 1.85.
//!
//! The impls delegate to the built-in `&str` and `&[u8]` ones, so a column of a
//! domain over `text` keeps working.

/// Writes one version's worth of impls.
///
/// The bodies are identical across the supported sqlx lines; only the crate
/// they name differs. Should a future version change one of these signatures,
/// this splits into two modules and the macro goes away.
macro_rules! sqlx_impls {
    ($sqlx:ident) => {
        use $sqlx::encode::IsNull;
        use $sqlx::error::BoxDynError;
        use $sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};
        use $sqlx::{Decode, Encode, Postgres, Type};

        use $crate::{BlindIndex, EncryptedValue};

        /// Bound and read as its serialized form, from a `text` column.
        impl Type<Postgres> for EncryptedValue {
            fn type_info() -> PgTypeInfo {
                <&str as Type<Postgres>>::type_info()
            }

            fn compatible(ty: &PgTypeInfo) -> bool {
                <&str as Type<Postgres>>::compatible(ty)
            }
        }

        impl Encode<'_, Postgres> for EncryptedValue {
            fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
                let serialized = self.to_string();
                <&str as Encode<Postgres>>::encode_by_ref(&serialized.as_str(), buf)
            }
        }

        impl<'r> Decode<'r, Postgres> for EncryptedValue {
            fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
                let serialized = <&str as Decode<Postgres>>::decode(value)?;
                Ok(Self::parse(serialized)?)
            }
        }

        /// Bound as raw bytes, into a `bytea` column.
        ///
        /// There is deliberately no `Decode`, for the reason given in
        /// [`postgres`](crate::postgres): a blind index is written and
        /// compared, never read back, and the stored bytes alone cannot
        /// reconstruct one.
        impl Type<Postgres> for BlindIndex {
            fn type_info() -> PgTypeInfo {
                <&[u8] as Type<Postgres>>::type_info()
            }

            fn compatible(ty: &PgTypeInfo) -> bool {
                <&[u8] as Type<Postgres>>::compatible(ty)
            }
        }

        impl Encode<'_, Postgres> for BlindIndex {
            fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
                <&[u8] as Encode<Postgres>>::encode_by_ref(&self.as_bytes(), buf)
            }
        }

        // The tests declare a schema, so they need the derive as well.
        #[cfg(all(test, feature = "derive"))]
        mod tests {
            use super::*;
            use $crate::{LocalKeyProvider, Vault, VaultedSchema};

            #[derive($crate::Vaulted)]
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

                let mut buffer = PgArgumentBuffer::default();
                let is_null = value.encode_by_ref(&mut buffer).expect("encode");
                assert!(matches!(is_null, IsNull::No));

                // What sqlx hands back on read is the same buffer, as text.
                let serialized = std::str::from_utf8(&buffer).expect("utf-8");
                let read = EncryptedValue::parse(serialized).expect("parse");
                assert_eq!(read, value);
                assert_eq!(
                    &*vault.decrypt(User::EMAIL_FIELD, &read).expect("decrypt"),
                    "alp@example.com"
                );
            }

            #[test]
            fn a_blind_index_is_bound_as_its_raw_bytes() {
                let vault = vault();
                let index = vault
                    .blind_index(User::EMAIL_FIELD, "alp@example.com")
                    .expect("index");

                let mut buffer = PgArgumentBuffer::default();
                let is_null = index.encode_by_ref(&mut buffer).expect("encode");
                assert!(matches!(is_null, IsNull::No));
                assert_eq!(&buffer[..], index.as_bytes());
            }

            #[test]
            fn the_documented_binding_compiles() {
                // Exactly the shape README.md tells people to write.
                // `blind_index` is an Option, so this also pins that a null
                // index still binds.
                let vault = vault();
                let row = vault
                    .protect(User::EMAIL_FIELD, "a@b.com")
                    .expect("protect");
                let _query = $sqlx::query(
                    "INSERT INTO users (email_ciphertext, email_blind_index) VALUES ($1, $2)",
                )
                .bind(&row.ciphertext)
                .bind(&row.blind_index);
                let _ = _query;
            }

            #[test]
            fn the_column_types_are_the_ones_the_ddl_generates() {
                assert_eq!(
                    <EncryptedValue as Type<Postgres>>::type_info(),
                    PgTypeInfo::with_name("text")
                );
                assert_eq!(
                    <BlindIndex as Type<Postgres>>::type_info(),
                    PgTypeInfo::with_name("bytea")
                );
                assert!(!<EncryptedValue as Type<Postgres>>::compatible(
                    &PgTypeInfo::with_name("bytea")
                ));
            }
        }
    };
}

#[cfg(feature = "sqlx-0_8")]
mod v0_8 {
    sqlx_impls!(sqlx_0_8);
}

#[cfg(feature = "sqlx-0_9")]
mod v0_9 {
    sqlx_impls!(sqlx_0_9);
}
