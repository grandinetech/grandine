use darling::{ast::Data, FromDeriveInput};
use easy_ext::ext;
use itertools::Itertools as _;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, TokenStreamExt as _};
use syn::{
    parse_quote,
    punctuated::Punctuated,
    token::{Comma, Where},
    Error, Expr, Generics, Ident, ImplGenerics, ImplItemFn, ImplItemType, Member, Path,
    TypeGenerics, TypeParam, WhereClause, WherePredicate,
};

use crate::{crate_path, ssz_field::SszField};

#[expect(
    clippy::struct_excessive_bools,
    reason = "False positive. The `bool`s are independent and using enums would be too verbose."
)]
#[derive(FromDeriveInput)]
// Darling has the `#[darling(supports(…))]` attribute for restricting the shape of types that the
// derive macro can be applied to. We don't use it because the error messages it produces are too
// generic. We accept types of all shapes and validate them ourselves in `SszType::all_fields`.
#[darling(attributes(ssz))]
pub struct SszType {
    ident: Ident,
    generics: Generics,
    data: Data<(), SszField>,

    // This is named `bound` to mimic other derive macros.
    //
    // The type is taken from <https://docs.rs/syn/1.0.72/syn/struct.WhereClause.html>.
    // `darling` implements `FromMeta` for `Vec<WherePredicate>`, but the implementation is
    // convoluted and less efficient than using `Punctuated<WherePredicate, Comma>` directly.
    bound: Option<Punctuated<WherePredicate, Comma>>,
    bound_for_read: Option<Punctuated<WherePredicate, Comma>>,
    // Attributes defined using `darling::util::Flag` cannot be set to `false`.
    #[darling(default = "default_to_true")]
    derive_hash: bool,
    #[darling(default = "default_to_true")]
    derive_read: bool,
    #[darling(default = "default_to_true")]
    derive_size: bool,
    #[darling(default = "default_to_true")]
    derive_write: bool,
    // This is needed to make deriving work inside the `ssz` crate itself.
    #[darling(default)]
    internal: bool,
    // This can be enabled for newtype structs to generate simpler impls marked with `#[inline]`.
    // By default, newtype structs that wrap a variable-size type add an additional offset.
    #[darling(default)]
    transparent: bool,
}

impl SszType {
    pub fn impls(&self) -> Result<TokenStream, Error> {
        self.validate()?;

        let (impl_generics, ty_generics, where_clause) = self.split_for_impl();
        let ssz = self.ssz_path()?;
        let ident = &self.ident;

        let mut impls = quote! {};

        if self.derive_size {
            let size_expr = self.size_expr(&ssz)?;

            impls.append_all(quote! {
                impl #impl_generics #ssz::SszSize for #ident #ty_generics #where_clause {
                    const SIZE: #ssz::Size = #size_expr;
                }
            });
        }

        if self.derive_read {
            let (impl_generics, where_clause) = self.split_for_read_impl();
            let context_type = context_type();
            let from_ssz_unchecked_fn_impl = self.from_ssz_unchecked_fn_impl(&ssz)?;

            impls.append_all(quote! {
                impl #impl_generics #ssz::SszRead<#context_type> for #ident #ty_generics
                    #where_clause
                {
                    #from_ssz_unchecked_fn_impl
                }
            });
        }

        if self.derive_write {
            let write_fixed_fn_impl = self.write_fixed_fn_impl(&ssz)?;
            let write_variable_fn_impl = self.write_variable_fn_impl(&ssz)?;

            impls.append_all(quote! {
                impl #impl_generics #ssz::SszWrite for #ident #ty_generics #where_clause {
                    #write_fixed_fn_impl

                    #write_variable_fn_impl
                }
            });
        }

        if self.derive_hash {
            let packing_factor_type_impl = self.packing_factor_type_impl(&ssz)?;
            let hash_tree_root_fn_impl = self.hash_tree_root_fn_impl(&ssz)?;

            impls.append_all(quote! {
                impl #impl_generics #ssz::SszHash for #ident #ty_generics #where_clause {
                    #packing_factor_type_impl

                    #hash_tree_root_fn_impl
                }
            });
        }

        Ok(impls)
    }

    fn validate(&self) -> Result<(), Error> {
        let Self {
            derive_hash,
            derive_read,
            derive_size,
            derive_write,
            ..
        } = *self;

        if !(derive_hash || derive_read || derive_size || derive_write) {
            return Err(Error::new(
                Span::call_site(),
                "at least one impl must be derived",
            ));
        }

        Ok(())
    }

    fn split_for_impl(&self) -> (ImplGenerics, TypeGenerics, Option<WhereClause>) {
        let (impl_generics, ty_generics, where_clause) = self.generics.split_for_impl();

        let where_clause = self
            .bound
            .clone()
            .map(|predicates| WhereClause {
                where_token: Where::default(),
                predicates,
            })
            .or_else(|| where_clause.cloned());

        (impl_generics, ty_generics, where_clause)
    }

    fn split_for_read_impl(&self) -> (Generics, Option<WhereClause>) {
        // See <https://github.com/dtolnay/syn/issues/732#issuecomment-562259968>.
        let mut generics = self.generics.clone();

        generics.params.insert(0, context_type().into());

        let (impl_generics, _, where_clause) = generics.split_for_impl();

        let impl_generics = parse_quote! { #impl_generics };

        let where_clause = self
            .bound_for_read
            .clone()
            .map(|predicates| WhereClause {
                where_token: Where::default(),
                predicates,
            })
            .or_else(|| where_clause.cloned());

        (impl_generics, where_clause)
    }

    fn ssz_path(&self) -> Result<Path, Error> {
        if self.internal {
            Ok(parse_quote! { crate })
        } else {
            crate_path::crate_path("ssz")
        }
    }

    fn size_expr(&self, ssz: &Path) -> Result<Expr, Error> {
        if self.transparent {
            self.single_unskipped_field()?;
        }

        let size_exprs = self
            .unskipped_fields()?
            .map(|(_, ssz_field)| ssz_field.size_expr(ssz))
            .collect_vec();

        if size_exprs.is_empty() {
            return Err(Error::new(
                Span::call_site(),
                "struct has no unskipped fields",
            ));
        }

        Ok(parse_quote! {
            #ssz::Size::for_container([
                #(#size_exprs,)*
            ])
        })
    }

    #[expect(
        clippy::wrong_self_convention,
        reason = "False positive. The name refers to the function whose implementation this generates."
    )]
    fn from_ssz_unchecked_fn_impl(&self, ssz: &Path) -> Result<ImplItemFn, Error> {
        if self.transparent {
            let (member, _) = self.single_unskipped_field()?;

            let skipped_members = self.all_fields()?.filter_map(|(member, ssz_field)| {
                ssz_field.skip.then(|| {
                    let ty = &ssz_field.ty;
                    quote! { #member: <#ty as ::core::default::Default>::default(), }
                })
            });

            return Ok(parse_quote! {
                #[inline]
                fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, #ssz::ReadError> {
                    ::core::result::Result::Ok(Self {
                        #member: #ssz::SszRead::from_ssz_unchecked(context, bytes)?,
                        #(#skipped_members)*
                    })
                }
            });
        }

        let init_stmts = quote! {
            let current_position_in_fixed = 0;
            let lowest_used_offset = bytes.len();
        };

        let fixed_part_stmts = self.unskipped_fields()?.map(|(member, ssz_field)| {
            let size_expr = ssz_field.size_expr(ssz);
            let offset_ident = member.offset_ident();

            quote! {
                let #offset_ident = match #size_expr {
                    #ssz::Size::Fixed { size } => current_position_in_fixed,
                    #ssz::Size::Variable { .. } => {
                        let end = current_position_in_fixed + #ssz::BYTES_PER_LENGTH_OFFSET;
                        let subslice = #ssz::subslice(bytes, current_position_in_fixed..end)?;

                        #ssz::read_offset_unchecked(subslice)?
                    }
                };

                let current_position_in_fixed = current_position_in_fixed + #size_expr.fixed_part();
            }
        });

        // Deserialize fields in reverse.
        // This simplifies the macro but makes errors more confusing.
        // Errors should still only be reported for invalid data.
        let variable_part_stmts = self
            .unskipped_fields()?
            .collect_vec()
            .into_iter()
            .rev()
            .map(|(member, ssz_field)| {
                let size_expr = ssz_field.size_expr(ssz);
                let offset_ident = member.offset_ident();
                let value_ident = member.value_ident();

                quote! {
                    let (lowest_used_offset, end) = match #size_expr {
                        #ssz::Size::Fixed { size } => (lowest_used_offset, #offset_ident + size),
                        #ssz::Size::Variable { .. } => (#offset_ident, lowest_used_offset),
                    };

                    let subslice = #ssz::subslice(bytes, #offset_ident..end)?;
                    let #value_ident = #ssz::SszRead::from_ssz_unchecked(context, subslice)?;
                }
            });

        let members = self.all_fields()?.map(|(member, ssz_field)| {
            if ssz_field.skip {
                let ty = &ssz_field.ty;
                quote! { #member: <#ty as ::core::default::Default>::default(), }
            } else {
                let value_ident = member.value_ident();
                quote! { #member: #value_ident, }
            }
        });

        let first_offset_validation_stmt = quote! {
            let expected = current_position_in_fixed;
            let actual = lowest_used_offset;

            // Check the first offset after deserializing all fields.
            // This simplifies the macro but makes errors more confusing.
            // It also means that the impl may waste time deserializing invalid data.
            if actual != expected {
                let error = #ssz::ReadError::ContainerFirstOffsetMismatch {
                    expected,
                    actual,
                };

                return ::core::result::Result::Err(error);
            }
        };

        Ok(parse_quote! {
            fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, #ssz::ReadError> {
                #init_stmts
                #(#fixed_part_stmts)*
                #(#variable_part_stmts)*
                #first_offset_validation_stmt
                ::core::result::Result::Ok(Self { #(#members)* })
            }
        })
    }

    fn write_fixed_fn_impl(&self, ssz: &Path) -> Result<ImplItemFn, Error> {
        if self.transparent {
            let (member, _) = self.single_unskipped_field()?;

            return Ok(parse_quote! {
                #[inline]
                fn write_fixed(&self, bytes: &mut [u8]) {
                    #ssz::SszWrite::write_fixed(&self.#member, bytes)
                }
            });
        }

        let stmts = self.unskipped_fields()?.map(|(member, ssz_field)| {
            let size_expr = ssz_field.size_expr(ssz);

            quote! {
                let size = #size_expr.fixed_part();
                #ssz::SszWrite::write_fixed(&self.#member, &mut bytes[..size]);
                let bytes = &mut bytes[size..];
            }
        });

        Ok(parse_quote! {
            fn write_fixed(&self, bytes: &mut [u8]) {
                #(#stmts)*
            }
        })
    }

    fn write_variable_fn_impl(&self, ssz: &Path) -> Result<ImplItemFn, Error> {
        if self.transparent {
            let (member, _) = self.single_unskipped_field()?;

            return Ok(parse_quote! {
                #[inline]
                fn write_variable(
                    &self,
                    bytes: &mut ::std::vec::Vec<u8>,
                ) -> ::core::result::Result<(), #ssz::WriteError> {
                    #ssz::SszWrite::write_variable(&self.#member, bytes)
                }
            });
        }

        let init_stmts = quote! {
            let length_before = bytes.len();
        };

        let fixed_part_stmts = self.unskipped_fields()?.map(|(member, ssz_field)| {
            let size_expr = ssz_field.size_expr(ssz);
            let offset_ident = member.offset_ident();

            quote! {
                let #offset_ident = bytes.len();
                let length_with_fixed_part = #offset_ident + #size_expr.fixed_part();

                // For some reason it's faster to resize `bytes` multiple times instead of once at
                // the beginning. It may be an artifact of how we benchmarked this. Some of the
                // benchmarks for `types` behave strangely (for example, some of them are
                // significantly slower when run individually).
                bytes.resize(length_with_fixed_part, 0);

                if let #ssz::Size::Fixed { size } = #size_expr {
                    let subslice = &mut bytes[#offset_ident..length_with_fixed_part];
                    #ssz::SszWrite::write_fixed(&self.#member, subslice);
                }
            }
        });

        let variable_part_stmts = self.unskipped_fields()?.map(|(member, ssz_field)| {
            let size_expr = ssz_field.size_expr(ssz);
            let offset_ident = member.offset_ident();

            quote! {
                if let #ssz::Size::Variable { .. } = #size_expr {
                    let offset = bytes.len() - length_before;
                    #ssz::write_offset(bytes, #offset_ident, offset)?;
                    #ssz::SszWrite::write_variable(&self.#member, bytes)?;
                }
            }
        });

        Ok(parse_quote! {
            fn write_variable(
                &self,
                bytes: &mut ::std::vec::Vec<u8>,
            ) -> ::core::result::Result<(), #ssz::WriteError> {
                #init_stmts
                #(#fixed_part_stmts)*
                #(#variable_part_stmts)*
                ::core::result::Result::Ok(())
            }
        })
    }

    fn packing_factor_type_impl(&self, ssz: &Path) -> Result<ImplItemType, Error> {
        if self.transparent {
            let (_, ssz_field) = self.single_unskipped_field()?;
            let ty = &ssz_field.ty;

            Ok(parse_quote! { type PackingFactor = <#ty as #ssz::SszHash>::PackingFactor; })
        } else {
            Ok(parse_quote! { type PackingFactor = #ssz::U1; })
        }
    }

    fn hash_tree_root_fn_impl(&self, ssz: &Path) -> Result<ImplItemFn, Error> {
        if self.transparent {
            let (member, _) = self.single_unskipped_field()?;

            return Ok(parse_quote! {
                #[inline]
                fn hash_tree_root(&self) -> #ssz::H256 {
                    #ssz::SszHash::hash_tree_root(&self.#member)
                }
            });
        }

        let mut nodes = self
            .unskipped_fields()?
            .map(|(member, _)| quote! { #ssz::SszHash::hash_tree_root(&self.#member) })
            .collect_vec();

        let mut height = 0_usize;

        let root = loop {
            match nodes.len() {
                0 => {
                    return Err(Error::new(
                        Span::call_site(),
                        "struct has no unskipped fields",
                    ));
                }
                1 => {
                    break nodes
                        .into_iter()
                        .exactly_one()
                        .expect("this branch is executed when nodes contains exactly 1 element");
                }
                _ => {
                    let zero_hash_expr = quote! { #ssz::hashing::ZERO_HASHES[#height] };

                    nodes = nodes
                        .into_iter()
                        .chain(core::iter::once(zero_hash_expr))
                        .tuples()
                        .map(|(left, right)| quote! { #ssz::hashing::hash_256_256(#left, #right) })
                        .collect();

                    height += 1;
                }
            }
        };

        Ok(parse_quote! {
            fn hash_tree_root(&self) -> #ssz::H256 {
                #root
            }
        })
    }

    fn single_unskipped_field(&self) -> Result<(Member, &SszField), Error> {
        self.unskipped_fields()?.exactly_one().map_err(|_| {
            Error::new(
                Span::call_site(),
                "struct with transparent attribute must have exactly one unskipped field",
            )
        })
    }

    fn unskipped_fields(&self) -> Result<impl Iterator<Item = (Member, &SszField)>, Error> {
        let fields = self.all_fields()?;
        Ok(fields.filter(|(_, ssz_field)| !ssz_field.skip))
    }

    fn all_fields(&self) -> Result<impl Iterator<Item = (Member, &SszField)>, Error> {
        match &self.data {
            // Enums could be used to represent SSZ unions,
            // but SSZ unions are not used in the currently stable parts of `consensus-specs`.
            Data::Enum(_) => Err(Error::new(
                Span::call_site(),
                "SSZ unions are not implemented",
            )),
            Data::Struct(fields) if fields.is_empty() => Err(Error::new(
                Span::call_site(),
                "SSZ containers with no fields are illegal",
            )),
            Data::Struct(fields) => Ok(fields.iter().enumerate().map(|(position, ssz_field)| {
                let member = ssz_field
                    .ident
                    .clone()
                    .map(Member::Named)
                    .unwrap_or_else(|| Member::Unnamed(position.into()));
                (member, ssz_field)
            })),
        }
    }
}

#[ext]
impl Member {
    // Formatting like this is needed to make newtype and tuple structs work.
    fn offset_ident(&self) -> Ident {
        format_ident!("offset_of_{}", self)
    }

    fn value_ident(&self) -> Ident {
        format_ident!("value_of_{}", self)
    }
}

fn context_type() -> TypeParam {
    // `C` is intentionally unhygienic to make the `bound_for_read` attribute work.
    // Not that there's any way to make it hygienic anyway.
    // Type parameters currently cannot have definition site hygiene.
    // `Span::mixed_site` resolves at the call site for type parameters.
    // `Span::def_size` requires feature `proc_macro_def_site`.
    // See <https://github.com/rust-lang/rust/issues/54724>.
    parse_quote! { C }
}

// The value of the `default` attribute passed to Darling must be a path to a function.
// `(|| true)` is not a path.
const fn default_to_true() -> bool {
    true
}
