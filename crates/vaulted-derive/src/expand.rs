//! Turning the parsed model into an impl of `VaultedSchema`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::parse::{Field, Model};

pub fn expand(model: &Model, vis: &syn::Visibility) -> TokenStream {
    let ident = &model.ident;
    let table = &model.table;
    let krate = &model.krate;

    let name_consts = model.fields.iter().map(|field| {
        let const_ident = format_ident!("{}", field.const_ident);
        let name = &field.name;
        let doc = format!(
            "The vault field name for [`{ident}::{}`]: `{name}`.",
            unraw(&field.ident)
        );
        quote! {
            #[doc = #doc]
            #vis const #const_ident: &'static ::core::primitive::str = #name;
        }
    });

    let entries = model.fields.iter().map(|field| {
        let struct_field = unraw(&field.ident);
        let name = &field.name;
        let ciphertext_column = &field.ciphertext_column;
        let blind_index_column = match &field.blind_index_column {
            Some(column) => quote!(::core::option::Option::Some(#column)),
            None => quote!(::core::option::Option::None),
        };
        let optional = field.optional;
        quote! {
            #krate::schema::EncryptedField::new(
                #struct_field,
                #name,
                #ciphertext_column,
                #blind_index_column,
                #optional,
            )
        }
    });

    let configs = model.fields.iter().map(|field| field_config(field, krate));

    quote! {
        #[automatically_derived]
        impl #ident {
            #(#name_consts)*
        }

        #[automatically_derived]
        impl #krate::schema::VaultedSchema for #ident {
            const TABLE: &'static ::core::primitive::str = #table;

            const ENCRYPTED_FIELDS: &'static [#krate::schema::EncryptedField] = &[
                #(#entries),*
            ];

            fn field_configs() -> #krate::Result<
                ::std::vec::Vec<#krate::FieldConfig>
            > {
                ::core::result::Result::Ok(::std::vec![#(#configs),*])
            }
        }
    }
}

fn field_config(field: &Field, krate: &syn::Path) -> TokenStream {
    let name = &field.name;
    let normalization = format_ident!("{}", field.normalization);

    let blind_index = field.blind_index.as_ref().map(|index| {
        let mut config = quote!(#krate::BlindIndexConfig::new());
        if let Some(bytes) = index.bytes {
            config = quote!(#config.with_output_bytes(#bytes)?);
        }
        if let Some(key_id) = &index.key_id {
            config = quote!(#config.with_key_id(#krate::KeyId::new(#key_id)?));
        }
        quote!(.with_blind_index(#config))
    });

    quote! {
        #krate::FieldConfig::new(#name)?
            .with_normalization(#krate::Normalization::#normalization)
            #blind_index
    }
}

/// `r#type` names a field just as well as `type` does; the string forms of it
/// must not carry the escape.
fn unraw(ident: &syn::Ident) -> String {
    let text = ident.to_string();
    text.strip_prefix("r#").unwrap_or(&text).to_string()
}
