//! Derive macros for KOFFER's byte-backed value types.
//!
//! Both derives target a single-field tuple struct that wraps a
//! `koffer_common::bytes::Bytes<MAX>`. They generate the shared boilerplate: an
//! `as_slice` accessor and a length-checked `TryFrom<&[u8]>` that routes through
//! `Bytes`. `SecretByteNewtype` additionally redacts the `Debug` output and wipes the
//! bytes on drop, for secret material.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Derives `as_slice` and a length-checked `TryFrom<&[u8]>` for a public byte value.
///
/// Apply it to a single-field tuple struct wrapping `Bytes<MAX>`, alongside the usual
/// `#[derive(Debug, Clone, PartialEq, Eq)]`.
#[proc_macro_derive(ByteNewtype)]
pub fn derive_byte_newtype(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    if let Err(err) = check_single_field_tuple(&input) {
        return err.into_compile_error().into();
    }
    let name = &input.ident;
    let common = bytes_common(name);
    quote! { #common }.into()
}

/// Like [`macro@ByteNewtype`], but for secret material: it also redacts the `Debug`
/// output (printing only the type name) and zeroizes the bytes on drop.
///
/// Do not also derive `Debug` -- this macro provides the redacted one. Pair it with
/// `#[derive(Clone, PartialEq, Eq)]`.
#[proc_macro_derive(SecretByteNewtype)]
pub fn derive_secret_byte_newtype(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    if let Err(err) = check_single_field_tuple(&input) {
        return err.into_compile_error().into();
    }
    let name = &input.ident;
    let common = bytes_common(name);
    quote! {
        #common

        impl ::core::fmt::Debug for #name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                // Redacted: print only the type name, never the secret bytes.
                f.debug_struct(::core::stringify!(#name)).finish_non_exhaustive()
            }
        }

        impl ::core::ops::Drop for #name {
            fn drop(&mut self) {
                use ::zeroize::Zeroize;
                self.0.zeroize();
            }
        }
    }
    .into()
}

/// The `as_slice` accessor and length-checked `TryFrom<&[u8]>` shared by both derives.
fn bytes_common(name: &syn::Ident) -> proc_macro2::TokenStream {
    quote! {
        impl #name {
            /// Returns the value's bytes.
            pub fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }
        }

        impl ::core::convert::TryFrom<&[u8]> for #name {
            type Error = ::koffer_common::bytes::BytesError;

            fn try_from(
                bytes: &[u8],
            ) -> ::core::result::Result<Self, ::koffer_common::bytes::BytesError> {
                ::koffer_common::bytes::Bytes::try_from(bytes).map(Self)
            }
        }
    }
}

/// Rejects anything that is not a single-field tuple struct, with a clear error.
fn check_single_field_tuple(input: &DeriveInput) -> syn::Result<()> {
    let is_single_field_tuple = matches!(
        &input.data,
        Data::Struct(data) if matches!(&data.fields, Fields::Unnamed(fields) if fields.unnamed.len() == 1),
    );
    if is_single_field_tuple {
        Ok(())
    } else {
        Err(syn::Error::new_spanned(
            input,
            "this derive requires a tuple struct with exactly one field, e.g. `struct Key(Bytes<MAX>)`",
        ))
    }
}
