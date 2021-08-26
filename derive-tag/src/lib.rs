use proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(ToTag)]
pub fn to_tag_derive(input: TokenStream) -> TokenStream {
    syn::parse(input)
        .map(|ast| impl_to_tag(&ast))
        .unwrap_or_else(|e| e.to_compile_error().into())
}

fn impl_to_tag(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let gen = quote! {
        impl tag::ToTag for #name {
            fn to_tag(&self) -> u8 {
                unsafe { *(self as *const Self as *const u8) }
            }
        }
    };

    gen.into()
}

#[proc_macro_derive(FromTag)]
pub fn from_tag_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse_macro_input!(input as syn::DeriveInput);

    impl_from_tag(&ast).unwrap_or_else(|e| e.to_compile_error().into())
}

fn impl_from_tag(ast: &syn::DeriveInput) -> Result<TokenStream, syn::Error> {
    let name = &ast.ident;

    let mut match_variants = quote!();

    match &ast.data {
        syn::Data::Enum(syn::DataEnum { variants, .. }) => {
            for variant in variants.iter() {
                if variant.discriminant.is_none() {
                    continue;
                }

                let variant_ident = &variant.ident;

                match_variants.extend(quote! {
                    x if x == (#name::#variant_ident).to_tag() => #name::#variant_ident,
                });
            }
        }
        syn::Data::Struct(s) => {
            return Err(syn::Error::new(
                s.struct_token.span,
                "Can only use FromTag on Enums.",
            ))
        }
        syn::Data::Union(u) => {
            return Err(syn::Error::new(
                u.union_token.span,
                "Can only use FromTag on Enums.",
            ))
        }
    };

    let gen = quote! {
        impl tag::FromTag for #name {
            fn from_tag(tag: u8) -> #name {
                match tag {
                    #match_variants
                    _ => panic!("Some variant does not have a explicit discriminant."),
                }
            }
        }
    };

    Ok(gen.into())
}
