// We originally tried to avoid writing derive macros by implementing SSZ traits for HLists.
// That approach turned out to be unviable for a number of reasons:
// - Impls for containers had to be written manually even if all they did was call utility code.
//   This was partly due to limitations of the type system and partly due to the lack of supporting
//   traits in HList crates.
// - None of the HList crates we considered could construct an HList of references from a reference
//   to a non-HList type, which made it necessary to list struct fields in the aforementioned
//   manually written impls.
// - `frunk` made compilation so resource-intensive that the compiler would crash after several
//   minutes of trying to build a binary.

use darling::FromDeriveInput as _;
use proc_macro::TokenStream;
use syn::{Error, parse_macro_input};

use crate::ssz_type::SszType;

mod crate_path;
mod ssz_field;
mod ssz_type;

#[proc_macro_derive(Ssz, attributes(ssz))]
pub fn derive(input: TokenStream) -> TokenStream {
    match SszType::from_derive_input(&parse_macro_input!(input)) {
        Ok(ssz_type) => ssz_type.impls().unwrap_or_else(Error::into_compile_error),
        Err(error) => error.write_errors(),
    }
    .into()
}
