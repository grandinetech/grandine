use darling::FromField;
use syn::{parse_quote, ExprPath, Ident, Path, Type};

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
