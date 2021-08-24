use proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(ToTag)]
pub fn to_tag_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_to_tag(&ast)
}

fn impl_to_tag(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let gen = quote! {
        impl ToTag for #name {
            fn to_tag(&self) -> u8 {
                unsafe { *(self as *const Self as *const u8) }
            }
        }
    };

    gen.into()
}

#[proc_macro_derive(FromTag)]
pub fn from_tag_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_from_tag(&ast)
}

fn impl_from_tag(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let mut match_variants = quote!();

    match &ast.data {
        syn::Data::Enum(syn::DataEnum {
            variants,
            enum_token: _x,
            brace_token: _y,
        }) => {
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
        _ => panic!("Can only use FromTag on Enums."),
    };

    let gen = quote! {
        impl FromTag for #name {
            fn from_tag(tag: u8) -> #name {
                match tag {
                    #match_variants
                    _ => panic!("Some variant does not have a explicit discriminant."),
                }
            }
        }
    };

    gen.into()
}
