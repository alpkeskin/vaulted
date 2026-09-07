//! Parsing `#[vaulted(...)]` into a validated model.
//!
//! Everything that can be checked without running the program is checked here,
//! so that a mistake in a field declaration is a compile error rather than an
//! undecryptable column discovered later.

use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields, Ident, LitBool, LitInt, LitStr, Type};

/// Mirrors `vaulted_core::field::MAX_FIELD_NAME_LEN`.
///
/// Duplicated on purpose: this crate must not depend on the core to expand a
/// macro. `FieldConfig::new` re-validates at runtime, so a drift between the
/// two is caught there rather than being let through.
const MAX_FIELD_NAME_LEN: usize = 128;

/// Mirrors `vaulted_core::field::MIN_BLIND_INDEX_BYTES`.
const MIN_BLIND_INDEX_BYTES: usize = 8;

/// Mirrors `vaulted_core::field::MAX_BLIND_INDEX_BYTES`.
const MAX_BLIND_INDEX_BYTES: usize = 32;

/// Mirrors `vaulted_core::key::MAX_KEY_ID_LEN`.
const MAX_KEY_ID_LEN: usize = 64;

const NORMALIZATIONS: &[(&str, &str)] = &[
    ("none", "None"),
    ("trim", "Trim"),
    ("lowercase", "Lowercase"),
    ("trim_lowercase", "TrimLowercase"),
    ("email", "Email"),
    ("digits_only", "DigitsOnly"),
];

/// A struct that carries encrypted fields.
pub struct Model {
    pub ident: Ident,
    pub table: String,
    /// The path the generated code reaches `vaulted-core` through.
    pub krate: syn::Path,
    pub fields: Vec<Field>,
}

/// One encrypted field on that struct.
pub struct Field {
    pub ident: Ident,
    /// The vault field name: `table.field`.
    pub name: String,
    /// The `Normalization` variant to emit, already resolved.
    pub normalization: &'static str,
    /// The name of the generated `<FIELD>_FIELD` constant. Computed here rather
    /// than at expansion so that a collision between two fields is caught with
    /// a message that names them.
    pub const_ident: String,
    pub blind_index: Option<BlindIndex>,
    pub ciphertext_column: String,
    pub blind_index_column: Option<String>,
    pub optional: bool,
}

/// Blind index settings, if the field is searchable.
pub struct BlindIndex {
    pub bytes: Option<usize>,
    pub key_id: Option<String>,
}

/// Collects several errors so one compile reports all of them.
#[derive(Default)]
struct Errors(Option<syn::Error>);

impl Errors {
    fn push(&mut self, error: syn::Error) {
        match &mut self.0 {
            Some(existing) => existing.combine(error),
            None => self.0 = Some(error),
        }
    }

    fn finish(self) -> syn::Result<()> {
        match self.0 {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// Validates one segment of a field name against the core's character rules.
fn check_name_segment(segment: &str, span: proc_macro2::Span, what: &str) -> syn::Result<()> {
    if segment.is_empty() {
        return Err(syn::Error::new(span, format!("{what} must not be empty")));
    }
    if let Some(bad) = segment
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '-' | '/'))
    {
        return Err(syn::Error::new(
            span,
            format!(
                "{what} contains `{bad}`; vault field names allow only ASCII \
                 alphanumerics and `.`, `_`, `-`, `/`"
            ),
        ));
    }
    Ok(())
}

/// Validates a key identifier against the same rules as `KeyId::new`.
///
/// Mirrored here for the same reason as the field name rules: a macro cannot
/// call into the crate it is generating code for. `KeyId::new` still runs at
/// vault construction, so a drift between the two costs a later error rather
/// than a wrong one.
fn check_key_id(id: &str, span: proc_macro2::Span) -> syn::Result<()> {
    if id.is_empty() || id.len() > MAX_KEY_ID_LEN {
        return Err(syn::Error::new(
            span,
            format!(
                "a key identifier is 1 to {MAX_KEY_ID_LEN} characters; this is {}",
                id.len()
            ),
        ));
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '-'))
    {
        return Err(syn::Error::new(
            span,
            format!(
                "a key identifier contains `{bad}`; only ASCII alphanumerics \
                 and `.`, `_`, `-` are allowed, so that one can never carry the \
                 ciphertext format separator"
            ),
        ));
    }
    Ok(())
}

/// Turns a field name into the stem of a column name.
///
/// Vault field names allow `-`, `.` and `/`; SQL identifiers conventionally do
/// not, and while the generated DDL quotes everything, a column called
/// `"ssn-v2_ciphertext"` is a column every hand-written query has to quote too.
/// So the separators become underscores.
///
/// This touches the default column name only. The field name — the one that is
/// authenticated associated data — is never rewritten, and an explicit
/// `ciphertext_column` or `blind_index_column` skips this entirely. Two fields
/// whose names differ only by separator therefore collide on one column, which
/// `check_uniqueness` reports.
fn column_stem(name: &str) -> String {
    name.replace(['-', '.', '/'], "_")
}

/// `r#type` names a field just as well as `type` does; the string forms of it
/// must not carry the escape.
fn unraw(ident: &Ident) -> String {
    let text = ident.to_string();
    text.strip_prefix("r#").unwrap_or(&text).to_string()
}

/// Whether a type is spelled `Option<_>`.
///
/// A textual check, which is all a macro can do. `type Maybe<T> = Option<T>;`
/// reads as non-optional here; the consequence is a `NOT NULL` in a generated
/// DDL fragment, not a wrong ciphertext.
fn is_option(ty: &Type) -> bool {
    let Type::Path(path) = ty else { return false };
    path.qself.is_none()
        && path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Option")
}

pub fn parse(input: &DeriveInput) -> syn::Result<Model> {
    let mut errors = Errors::default();

    if !input.generics.params.is_empty() {
        errors.push(syn::Error::new(
            input.generics.span(),
            "#[derive(Vaulted)] does not support generic parameters: a schema \
             describes one concrete table",
        ));
    }

    let (table, krate) = match parse_container(input) {
        Ok(parsed) => parsed,
        Err(error) => {
            errors.push(error);
            (String::new(), default_crate_path())
        }
    };

    let named = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => named.named.iter().collect::<Vec<_>>(),
            other => {
                errors.push(syn::Error::new(
                    other.span(),
                    "#[derive(Vaulted)] requires a struct with named fields",
                ));
                Vec::new()
            }
        },
        Data::Enum(_) | Data::Union(_) => {
            errors.push(syn::Error::new(
                input.ident.span(),
                "#[derive(Vaulted)] can only be applied to a struct",
            ));
            Vec::new()
        }
    };

    let mut fields = Vec::new();
    for field in named {
        match parse_field(field, &table) {
            Ok(Some(parsed)) => fields.push(parsed),
            Ok(None) => {}
            Err(error) => errors.push(error),
        }
    }

    check_uniqueness(&fields, &mut errors);

    if fields.is_empty() && errors.0.is_none() {
        errors.push(syn::Error::new(
            input.ident.span(),
            "#[derive(Vaulted)] found no encrypted fields; mark at least one \
             with #[vaulted(encrypt)]",
        ));
    }

    errors.finish()?;

    Ok(Model {
        ident: input.ident.clone(),
        table,
        krate,
        fields,
    })
}

/// Where the generated code looks for `vaulted-core` unless told otherwise.
fn default_crate_path() -> syn::Path {
    syn::parse_quote!(::vaulted_core)
}

fn parse_container(input: &DeriveInput) -> syn::Result<(String, syn::Path)> {
    let mut table: Option<LitStr> = None;
    let mut krate: Option<syn::Path> = None;

    for attr in &input.attrs {
        if !attr.path().is_ident("vaulted") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("table") {
                if table.is_some() {
                    return Err(meta.error("`table` is set twice"));
                }
                table = Some(meta.value()?.parse()?);
                Ok(())
            } else if meta.path.is_ident("crate") {
                if krate.is_some() {
                    return Err(meta.error("`crate` is set twice"));
                }
                let value: LitStr = meta.value()?.parse()?;
                krate = Some(value.parse_with(syn::Path::parse_mod_style)?);
                Ok(())
            } else {
                Err(meta.error(
                    "unknown option; the struct accepts `table = \"...\"` and \
                     `crate = \"...\"`",
                ))
            }
        })?;
    }

    let Some(table) = table else {
        return Err(syn::Error::new(
            input.ident.span(),
            "missing #[vaulted(table = \"...\")]: field names are prefixed with \
             it and are part of the on-disk contract",
        ));
    };

    let value = table.value();
    check_name_segment(&value, table.span(), "the table name")?;
    Ok((value, krate.unwrap_or_else(default_crate_path)))
}

fn parse_field(field: &syn::Field, table: &str) -> syn::Result<Option<Field>> {
    let ident = field
        .ident
        .clone()
        .expect("named fields are checked by the caller");

    let attrs: Vec<_> = field
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("vaulted"))
        .collect();
    if attrs.is_empty() {
        return Ok(None);
    }

    let mut encrypt = false;
    let mut blind_index = false;
    let mut normalization: Option<(String, proc_macro2::Span)> = None;
    let mut rename: Option<LitStr> = None;
    let mut ciphertext_column: Option<LitStr> = None;
    let mut blind_index_column: Option<LitStr> = None;
    let mut blind_index_bytes: Option<LitInt> = None;
    let mut blind_index_key: Option<LitStr> = None;
    let mut nullable: Option<LitBool> = None;

    for attr in attrs {
        attr.parse_nested_meta(|meta| {
            let path = &meta.path;
            if path.is_ident("encrypt") {
                encrypt = true;
            } else if path.is_ident("blind_index") {
                blind_index = true;
            } else if path.is_ident("normalize") {
                let value: LitStr = meta.value()?.parse()?;
                normalization = Some((value.value(), value.span()));
            } else if path.is_ident("rename") {
                rename = Some(meta.value()?.parse()?);
            } else if path.is_ident("ciphertext_column") {
                ciphertext_column = Some(meta.value()?.parse()?);
            } else if path.is_ident("blind_index_column") {
                blind_index_column = Some(meta.value()?.parse()?);
            } else if path.is_ident("blind_index_bytes") {
                blind_index_bytes = Some(meta.value()?.parse()?);
            } else if path.is_ident("blind_index_key") {
                blind_index_key = Some(meta.value()?.parse()?);
            } else if path.is_ident("nullable") {
                nullable = Some(meta.value()?.parse()?);
            } else {
                return Err(meta.error(
                    "unknown option; a field accepts `encrypt`, `blind_index`, \
                     `normalize`, `rename`, `nullable`, `ciphertext_column`, \
                     `blind_index_column`, `blind_index_bytes`, `blind_index_key`",
                ));
            }
            Ok(())
        })?;
    }

    if !encrypt {
        return Err(syn::Error::new(
            ident.span(),
            "this field has #[vaulted(...)] but not `encrypt`; every vaulted \
             field is encrypted, and the intent is spelled out rather than \
             inferred",
        ));
    }

    let normalization = match &normalization {
        None => "None",
        Some((value, span)) => match NORMALIZATIONS.iter().find(|(name, _)| name == value) {
            Some((_, variant)) => *variant,
            None if value == "custom" => {
                return Err(syn::Error::new(
                    *span,
                    "`custom` normalization takes a function pointer, which an \
                     attribute cannot carry. Drop `normalize` here, and hand \
                     the built configuration to \
                     `VaultBuilder::replace_field` with the rule attached",
                ));
            }
            None => {
                let known: Vec<_> = NORMALIZATIONS.iter().map(|(name, _)| *name).collect();
                return Err(syn::Error::new(
                    *span,
                    format!(
                        "unknown normalization; expected one of {}",
                        known.join(", ")
                    ),
                ));
            }
        },
    };

    if !blind_index {
        for (value, option) in [
            (
                blind_index_bytes.as_ref().map(Spanned::span),
                "blind_index_bytes",
            ),
            (
                blind_index_column.as_ref().map(Spanned::span),
                "blind_index_column",
            ),
            (
                blind_index_key.as_ref().map(Spanned::span),
                "blind_index_key",
            ),
        ] {
            if let Some(span) = value {
                return Err(syn::Error::new(
                    span,
                    format!("`{option}` needs `blind_index` on the same field"),
                ));
            }
        }
        if !matches!(normalization, "None") {
            return Err(syn::Error::new(
                ident.span(),
                "`normalize` only affects blind index input, so it does nothing \
                 without `blind_index`; encrypted values are always stored \
                 exactly as given",
            ));
        }
    }

    let short_name = match &rename {
        Some(rename) => {
            let value = rename.value();
            check_name_segment(&value, rename.span(), "the renamed field")?;
            value
        }
        None => unraw(&ident),
    };
    let name = format!("{table}.{short_name}");
    if name.len() > MAX_FIELD_NAME_LEN {
        return Err(syn::Error::new(
            ident.span(),
            format!(
                "the field name `{name}` is {} bytes; the limit is {MAX_FIELD_NAME_LEN}",
                name.len()
            ),
        ));
    }
    check_name_segment(&name, ident.span(), "the field name")?;

    let bytes = match &blind_index_bytes {
        None => None,
        Some(literal) => {
            let bytes: usize = literal.base10_parse()?;
            if !(MIN_BLIND_INDEX_BYTES..=MAX_BLIND_INDEX_BYTES).contains(&bytes) {
                return Err(syn::Error::new(
                    literal.span(),
                    format!(
                        "blind index output must be {MIN_BLIND_INDEX_BYTES}..={MAX_BLIND_INDEX_BYTES} bytes"
                    ),
                ));
            }
            Some(bytes)
        }
    };

    // Columns follow the field's name, which is `rename` when one is given.
    // A field renamed for the vault has been renamed for the schema too; having
    // the column keep the old Rust identifier would put the two names that
    // describe one value out of step, which is the whole thing the derive
    // exists to prevent. An explicit column still wins, for a table whose
    // shape was decided before any of this.
    if let Some(key_id) = &blind_index_key {
        check_key_id(&key_id.value(), key_id.span())?;
    }

    let stem = column_stem(&short_name);
    let ciphertext_column = match &ciphertext_column {
        Some(column) => column.value(),
        None => format!("{stem}_ciphertext"),
    };
    let blind_index_column = if blind_index {
        Some(match &blind_index_column {
            Some(column) => column.value(),
            None => format!("{stem}_blind_index"),
        })
    } else {
        None
    };

    Ok(Some(Field {
        // The type is the default answer; `nullable` is the override, for the
        // cases the textual `Option` check cannot see — an alias, or a column
        // that has to accept NULL for rows written before the field existed.
        optional: match &nullable {
            Some(nullable) => nullable.value(),
            None => is_option(&field.ty),
        },
        const_ident: format!("{}_FIELD", unraw(&ident).to_uppercase()),
        ident,
        name,
        normalization,
        blind_index: blind_index.then(|| BlindIndex {
            bytes,
            key_id: blind_index_key.as_ref().map(LitStr::value),
        }),
        ciphertext_column,
        blind_index_column,
    }))
}

/// Two fields sharing a name would silently share associated data; two sharing
/// a column would silently overwrite each other. Two whose generated constants
/// collide — `email` and `eMail` both give `EMAIL_FIELD` — still fail to
/// compile, but with a message about a duplicate definition rather than about
/// the fields that caused it.
fn check_uniqueness(fields: &[Field], errors: &mut Errors) {
    let mut seen_names: Vec<&str> = Vec::new();
    let mut seen_columns: Vec<&str> = Vec::new();
    let mut seen_consts: Vec<&str> = Vec::new();

    for field in fields {
        if seen_consts.contains(&field.const_ident.as_str()) {
            errors.push(syn::Error::new(
                field.ident.span(),
                format!(
                    "this field and an earlier one both generate the constant \
                     `{}`; rename one, or give it a `rename` that differs by \
                     more than letter case",
                    field.const_ident
                ),
            ));
        }
        seen_consts.push(&field.const_ident);

        if seen_names.contains(&field.name.as_str()) {
            errors.push(syn::Error::new(
                field.ident.span(),
                format!("the field name `{}` is used twice", field.name),
            ));
        }
        seen_names.push(&field.name);

        for column in [
            Some(&field.ciphertext_column),
            field.blind_index_column.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if seen_columns.contains(&column.as_str()) {
                errors.push(syn::Error::new(
                    field.ident.span(),
                    format!("the column `{column}` is used twice"),
                ));
            }
            seen_columns.push(column);
        }
    }
}
