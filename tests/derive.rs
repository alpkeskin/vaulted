//! `#[derive(Vaulted)]`: the schema it generates, and that a vault built from
//! it behaves exactly like one configured by hand.
//!
//! The structs here are declarations, never instances: the derive reads their
//! shape, so nothing reads their fields.
#![allow(dead_code)]

use vaulted_core::{LocalKeyProvider, Vault, Vaulted, VaultedSchema};

#[derive(Vaulted)]
#[vaulted(table = "users")]
struct User {
    id: i64,
    name: String,

    #[vaulted(encrypt, blind_index, normalize = "email")]
    email: String,

    #[vaulted(
        encrypt,
        blind_index,
        normalize = "digits_only",
        blind_index_bytes = 16
    )]
    phone: Option<String>,

    #[vaulted(encrypt, rename = "tckn")]
    national_id: String,
}

fn vault() -> Vault {
    Vault::builder()
        .key_provider(LocalKeyProvider::generate().expect("provider"))
        .fields(User::field_configs().expect("configs"))
        .build()
        .expect("vault")
}

#[test]
fn field_names_are_prefixed_with_the_table() {
    assert_eq!(User::TABLE, "users");
    assert_eq!(User::EMAIL_FIELD, "users.email");
    assert_eq!(User::PHONE_FIELD, "users.phone");
    // `rename` replaces the segment, not the prefix.
    assert_eq!(User::NATIONAL_ID_FIELD, "users.tckn");
}

#[test]
fn only_annotated_fields_are_in_the_schema() {
    let names: Vec<_> = User::ENCRYPTED_FIELDS
        .iter()
        .map(|field| field.struct_field())
        .collect();
    assert_eq!(names, ["email", "phone", "national_id"]);
    assert_eq!(User::field_configs().expect("configs").len(), 3);
}

#[test]
fn columns_default_from_the_field_name_and_can_be_overridden() {
    let email = User::encrypted_field("email").expect("email");
    assert_eq!(email.ciphertext_column(), "email_ciphertext");
    assert_eq!(email.blind_index_column(), Some("email_blind_index"));

    // The column follows `rename`, not the Rust identifier: one value, one
    // name, everywhere it appears.
    let national_id = User::encrypted_field("national_id").expect("national_id");
    assert_eq!(national_id.ciphertext_column(), "tckn_ciphertext");
    assert_eq!(national_id.blind_index_column(), None);
    assert!(!national_id.is_searchable());

    assert_eq!(
        User::columns(),
        [
            "email_ciphertext",
            "email_blind_index",
            "phone_ciphertext",
            "phone_blind_index",
            "tckn_ciphertext",
        ]
    );
}

#[test]
fn an_option_field_is_marked_optional() {
    // What that means for a column is `vaulted-postgres`'s business; the schema
    // only records the shape it read.
    let phone = User::encrypted_field("phone").expect("phone");
    assert!(phone.is_optional());
    assert_eq!(phone.columns(), ["phone_ciphertext", "phone_blind_index"]);

    let email = User::encrypted_field("email").expect("email");
    assert!(!email.is_optional());

    let national_id = User::encrypted_field("national_id").expect("national_id");
    assert!(!national_id.is_optional());
    assert_eq!(national_id.columns(), ["tckn_ciphertext"]);
}

#[test]
fn a_derived_vault_round_trips() {
    let vault = vault();
    let protected = vault
        .protect(User::EMAIL_FIELD, "Alp@Example.com")
        .expect("protect");
    let ciphertext = protected.ciphertext.to_string();

    assert_eq!(
        &*vault
            .decrypt_str(User::EMAIL_FIELD, &ciphertext)
            .expect("decrypt"),
        "Alp@Example.com",
        "decryption returns the exact input, normalization notwithstanding"
    );
}

#[test]
fn normalize_reaches_the_blind_index() {
    let vault = vault();

    let stored = vault
        .protect(User::EMAIL_FIELD, "Alp@Example.com")
        .expect("protect");
    let lookup = vault
        .blind_index(User::EMAIL_FIELD, "  alp@EXAMPLE.com ")
        .expect("index");
    assert!(stored.blind_index.expect("index").matches(&lookup));

    let stored = vault
        .protect(User::PHONE_FIELD, "+90 555 111 22 33")
        .expect("protect");
    let lookup = vault
        .blind_index(User::PHONE_FIELD, "905551112233")
        .expect("index");
    assert!(stored.blind_index.expect("index").matches(&lookup));
}

#[test]
fn blind_index_bytes_truncates() {
    let vault = vault();
    let email = vault
        .blind_index(User::EMAIL_FIELD, "a@b.com")
        .expect("index");
    let phone = vault
        .blind_index(User::PHONE_FIELD, "5551112233")
        .expect("index");

    assert_eq!(email.as_bytes().len(), 32, "the default is the full tag");
    assert_eq!(phone.as_bytes().len(), 16, "blind_index_bytes = 16");
}

#[test]
fn a_field_without_blind_index_is_not_searchable() {
    let vault = vault();
    assert!(vault.is_searchable(User::EMAIL_FIELD));
    assert!(!vault.is_searchable(User::NATIONAL_ID_FIELD));

    let protected = vault
        .protect(User::NATIONAL_ID_FIELD, "11111111111")
        .expect("protect");
    assert!(protected.blind_index.is_none());
}

#[test]
fn derived_names_still_bind_a_value_to_its_field() {
    let vault = vault();
    let email = vault
        .encrypt(User::EMAIL_FIELD, "alp@example.com")
        .expect("encrypt");

    assert!(
        vault.decrypt(User::NATIONAL_ID_FIELD, &email).is_err(),
        "a ciphertext moved between columns must not decrypt"
    );
}

/// A struct whose Rust field names have nothing to do with its column names.
#[derive(Vaulted)]
#[vaulted(table = "legacy/records")]
struct Legacy {
    #[vaulted(
        encrypt,
        blind_index,
        rename = "ssn-v2",
        ciphertext_column = "SSN_ENC",
        blind_index_column = "SSN_IDX",
        normalize = "trim_lowercase"
    )]
    social_security_number: String,
}

/// Two fields renamed for the vault, with nothing said about their columns.
#[derive(Vaulted)]
#[vaulted(table = "patients")]
struct Renamed {
    #[vaulted(encrypt, blind_index, rename = "national_id")]
    tckn: String,

    /// A field name using separators the vault allows but SQL does not like.
    #[vaulted(encrypt, blind_index, rename = "insurance-no/v2")]
    insurance: String,
}

#[test]
fn columns_follow_the_rename() {
    assert_eq!(Renamed::TCKN_FIELD, "patients.national_id");
    let tckn = Renamed::encrypted_field("tckn").expect("tckn");
    assert_eq!(
        tckn.columns(),
        ["national_id_ciphertext", "national_id_blind_index"],
        "the Rust identifier `tckn` names nothing in the schema"
    );
}

#[test]
fn column_names_use_underscores_for_separators() {
    // The field name keeps every character it was given — it is authenticated
    // associated data, and rewriting it would orphan values.
    assert_eq!(
        Renamed::INSURANCE_FIELD,
        "patients.insurance-no/v2",
        "the crypto contract is untouched"
    );
    // The default column name is not part of any contract, so it reads the way
    // a column normally does.
    let insurance = Renamed::encrypted_field("insurance").expect("insurance");
    assert_eq!(
        insurance.columns(),
        ["insurance_no_v2_ciphertext", "insurance_no_v2_blind_index"]
    );
}

/// A second schema on the same table, disagreeing about one field.
#[derive(Vaulted)]
#[vaulted(table = "users")]
struct UserSummary {
    // No normalization, unlike `User::email`.
    #[vaulted(encrypt, blind_index)]
    email: String,
}

#[test]
fn composing_schemas_that_disagree_is_refused() {
    // Composing several schemas into one vault is the expected use of the
    // derive, which is exactly why a repeated field name must not be an
    // overwrite: the loser's normalization would silently stop applying, and
    // lookups would return nothing rather than fail.
    let error = Vault::builder()
        .key_provider(LocalKeyProvider::generate().expect("provider"))
        .fields(User::field_configs().expect("configs"))
        .fields(UserSummary::field_configs().expect("configs"))
        .build()
        .expect_err("users.email is declared by both");

    assert!(
        matches!(&error, vaulted_core::Error::DuplicateField { name } if name == "users.email"),
        "expected a duplicate field error, got {error:?}"
    );
}

#[test]
fn one_derived_field_can_be_replaced_by_hand() {
    // `Normalization::Custom` takes a function pointer, which no attribute can
    // carry, so the derive covers the rest of the struct and this one field is
    // built here. The override has to be explicit — `fields` would refuse it.
    let vault = Vault::builder()
        .key_provider(LocalKeyProvider::generate().expect("provider"))
        .fields(User::field_configs().expect("configs"))
        .replace_field(
            vaulted_core::FieldConfig::new(User::EMAIL_FIELD)
                .expect("field")
                .with_normalization(vaulted_core::Normalization::Custom(|value| {
                    value.replace('.', "").to_lowercase()
                }))
                .with_blind_index(vaulted_core::BlindIndexConfig::new()),
        )
        .build()
        .expect("vault");

    // Gmail-style dot folding, which no built-in rule offers.
    let stored = vault
        .protect(User::EMAIL_FIELD, "A.L.P@example.com")
        .expect("protect");
    let lookup = vault
        .blind_index(User::EMAIL_FIELD, "alp@example.com")
        .expect("index");
    assert!(stored.blind_index.expect("index").matches(&lookup));
}

#[test]
fn an_explicit_column_wins_over_the_name() {
    assert_eq!(Legacy::TABLE, "legacy/records");
    assert_eq!(
        Legacy::SOCIAL_SECURITY_NUMBER_FIELD,
        "legacy/records.ssn-v2"
    );
    // Without the overrides these would be `ssn_v2_ciphertext` and
    // `ssn_v2_blind_index`, following the rename.
    assert_eq!(Legacy::columns(), ["SSN_ENC", "SSN_IDX"]);

    let vault = Vault::builder()
        .key_provider(LocalKeyProvider::generate().expect("provider"))
        .fields(Legacy::field_configs().expect("configs"))
        .build()
        .expect("vault");
    let stored = vault
        .protect(Legacy::SOCIAL_SECURITY_NUMBER_FIELD, " ABC ")
        .expect("protect");
    let lookup = vault
        .blind_index(Legacy::SOCIAL_SECURITY_NUMBER_FIELD, "abc")
        .expect("index");
    assert!(stored.blind_index.expect("index").matches(&lookup));
}

/// The generated code names `::vaulted_core` unless told otherwise, which
/// resolves only for a crate that depends on it directly. A crate whose only
/// dependency is `vaulted-postgres` has to point the derive at the re-export —
/// this pins that the option exists and that the path it takes is a real one.
#[derive(Vaulted)]
#[vaulted(table = "orders", crate = "vaulted_core")]
struct Reexported {
    #[vaulted(encrypt, blind_index)]
    reference: String,
}

#[test]
fn the_crate_path_can_be_redirected() {
    assert_eq!(Reexported::REFERENCE_FIELD, "orders.reference");
    assert_eq!(
        Reexported::columns(),
        ["reference_ciphertext", "reference_blind_index"]
    );

    let vault = Vault::builder()
        .key_provider(LocalKeyProvider::generate().expect("provider"))
        .fields(Reexported::field_configs().expect("configs"))
        .build()
        .expect("vault");
    let stored = vault
        .protect(Reexported::REFERENCE_FIELD, "ABC-123")
        .expect("protect");
    assert_eq!(
        &*vault
            .decrypt(Reexported::REFERENCE_FIELD, &stored.ciphertext)
            .expect("decrypt"),
        "ABC-123"
    );
}

/// The derive mirrors these limits, because a proc-macro crate cannot depend on
/// the crate it generates code for. Nothing makes the two agree, so this test
/// does: if one of these constants moves, update the matching `const` at the
/// top of `crates/vaulted-derive/src/parse.rs`.
#[test]
fn the_derive_mirrors_the_core_limits() {
    assert_eq!(vaulted_core::field::MAX_FIELD_NAME_LEN, 128);
    assert_eq!(vaulted_core::field::MIN_BLIND_INDEX_BYTES, 8);
    assert_eq!(vaulted_core::field::MAX_BLIND_INDEX_BYTES, 32);
    assert_eq!(vaulted_core::key::MAX_KEY_ID_LEN, 64);
}

/// Nullability the Rust type does not say.
#[derive(Vaulted)]
#[vaulted(table = "invoices")]
struct Nullability {
    /// Not an `Option`, but the column predates the field: existing rows have
    /// no value for it, and never will.
    #[vaulted(encrypt, nullable = true)]
    legacy_note: String,

    /// An `Option` in Rust for the application's convenience, while the column
    /// itself is written on every insert.
    #[vaulted(encrypt, blind_index, nullable = false)]
    reference: Option<String>,
}

#[test]
fn nullable_overrides_what_the_type_says() {
    let note = Nullability::encrypted_field("legacy_note").expect("legacy_note");
    assert!(note.is_optional(), "a String forced to accept NULL");

    let reference = Nullability::encrypted_field("reference").expect("reference");
    assert!(!reference.is_optional(), "an Option forced to NOT NULL");

    // And the DDL follows the schema, not the Rust type.
    assert_eq!(
        vaulted_postgres::ddl::column_definitions::<Nullability>(),
        [
            "\"legacy_note_ciphertext\" text",
            "\"reference_ciphertext\" text NOT NULL",
            "\"reference_blind_index\" bytea NOT NULL",
        ]
    );
}
