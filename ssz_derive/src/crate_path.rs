use std::borrow::Cow;

use proc_macro_crate::FoundCrate;
use proc_macro2::Span;
use syn::{Error, Ident, Path, parse_quote};

pub fn crate_path(original_name: &str) -> Result<Path, Error> {
    let call_site = Span::call_site();

    let found_crate = proc_macro_crate::crate_name(original_name)
        .map_err(|error| Error::new(call_site, error))?;

    let name = match found_crate {
        FoundCrate::Itself => Cow::Borrowed(original_name),
        FoundCrate::Name(renamed) => Cow::Owned(renamed),
    };

    let ident = Ident::new(&name, call_site);

    Ok(parse_quote! { ::#ident })
}
