// This is a really naive implementation with almost no error handling,
// but should be enough for our purposes.
use hex;
use proc_macro::{TokenStream, TokenTree};
use quote::quote;
use std::iter::Iterator;
use std::panic::panic_any;
use std::str::FromStr;
use wallet::{FromScript, Script};

fn get_pushdata(val: &str, iterator: &mut impl Iterator<Item = TokenTree>) -> Script {
    let data_size = hex::decode(val).unwrap();

    if let Some(next_val) = iterator.next() {
        let hex_val = match next_val {
            TokenTree::Ident(i) => i.to_string(),
            TokenTree::Literal(l) => l.to_string(),
            _ => panic!("next_val must be a hex."),
        };

        Script::Data(data_size, hex::decode(hex_val).unwrap())
    } else {
        panic!("next_val must be a hex.");
    }
}

#[proc_macro]
pub fn script(input: TokenStream) -> TokenStream {
    if input.is_empty() {
        panic!("TokenStream is empty.");
    }

    let mut script_vec: Vec<Script> = Vec::new();

    let mut input_iter = input.into_iter();

    while let Some(token) = input_iter.next() {
        match token {
            TokenTree::Ident(ident) => {
                let name = ident.to_string();

                if name.starts_with("OP_") {
                    match Script::from_str(&name) {
                        Ok(op) => script_vec.push(op),
                        Err(err) => panic_any(err),
                    }
                } else {
                    script_vec.push(get_pushdata(&name, &mut input_iter));
                }
            }
            TokenTree::Literal(literal) => {
                let val = literal.to_string();
                script_vec.push(get_pushdata(&val, &mut input_iter))
            }
            _ => panic!("TokenTree variant not supported by script! {}", token),
        };
    }

    let script_hex = script_vec.from_script();
    (quote! {
        vec![#(#script_hex),*]
    })
    .into()
}
