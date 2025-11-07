use darling::FromField;
use syn::{ExprPath, Ident, Path, Type, parse_quote};

#[derive(FromField)]
#[darling(attributes(ssz))]
pub struct SszField {
    pub ident: Option<Ident>,
    pub ty: Type,

    #[darling(default)]
    pub skip: bool,
}

impl SszField {
    pub fn size_expr(&self, ssz: &Path) -> ExprPath {
        let ty = &self.ty;
        parse_quote! { <#ty as #ssz::SszSize>::SIZE }
    }
}
