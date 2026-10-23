use core::marker::PhantomData;

use crate::{
    consts::BYTES_PER_LENGTH_OFFSET,
    error::ReadError,
    porcelain::{SszContainer, SszRead},
    shared::{read_offset_unchecked, subslice},
    size::Size,
};

#[derive(Clone, Copy)]
pub struct SszCursor<'a> {
    buf: &'a [u8],
}

impl<'a> SszCursor<'a> {
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    #[must_use]
    pub const fn container<T: SszContainer>(&self) -> SszContainerCursor<'a, T> {
        SszContainerCursor {
            buf: self.buf,
            _marker: PhantomData,
        }
    }

    pub fn union(&self) -> Result<(u8, Self), ReadError> {
        let (selector, payload) = self.buf.split_first().ok_or(ReadError::Custom {
            message: "union is missing its selector byte",
        })?;

        Ok((*selector, Self::new(payload)))
    }

    pub fn read<C, T: SszRead<C>>(&self, context: &C) -> Result<T, ReadError> {
        T::from_ssz(context, self.buf)
    }
}

pub struct SszContainerCursor<'a, T: SszContainer> {
    buf: &'a [u8],
    _marker: PhantomData<T>,
}

impl<'a, T: SszContainer> SszContainerCursor<'a, T> {
    #[expect(clippy::inline_always)]
    #[inline(always)]
    pub fn field(&self, idx: usize) -> Result<SszCursor<'a>, ReadError> {
        let mut fields = T::FIELDS.iter().scan(0_usize, |position, size| {
            let field = (*position, *size);
            *position = position.saturating_add(size.fixed_part());
            Some(field)
        });

        let (position, size) = fields.nth(idx).ok_or(ReadError::Custom {
            message: "field index is out of bounds",
        })?;

        let range = match size {
            Size::Fixed { size } => position..position.saturating_add(size),
            Size::Variable { .. } => {
                let end = position.saturating_add(BYTES_PER_LENGTH_OFFSET.get());
                let start = read_offset_unchecked(subslice(self.buf, position..end)?)?;

                // fields.nth(idx) call consumed all items up to `idx`, so we now look in all subsequent items for
                // variable sized field, to know where our variable sized field ends.
                let end = match fields.find(|(_, size)| matches!(size, Size::Variable { .. })) {
                    Some((position, _)) => {
                        let end = position.saturating_add(BYTES_PER_LENGTH_OFFSET.get());
                        read_offset_unchecked(subslice(self.buf, position..end)?)?
                    }
                    None => self.buf.len(),
                };

                start..end
            }
        };

        subslice(self.buf, range).map(SszCursor::new)
    }

    pub fn read<C>(&self, context: &C) -> Result<T, ReadError>
    where
        T: SszRead<C>,
    {
        T::from_ssz(context, self.buf)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use ethereum_types::H256;
    use ssz_derive::Ssz;
    use typenum::{U8, Unsigned};

    use crate::{byte_list::ByteList, contiguous_list::ContiguousList, porcelain::SszWrite as _};

    use super::*;

    type Bytes = ContiguousList<u8, U8>;

    #[derive(Ssz)]
    #[ssz(internal)]
    struct Inner {
        head: u16,
        body: Bytes,
    }

    // Progressive containers are serialized exactly like ordinary containers.
    // The `active` bits only affect merkleization.
    #[derive(Ssz)]
    #[ssz(internal, stable(active = [1, 0, 1]))]
    struct Progressive {
        head: u32,
        tail: Bytes,
    }

    #[derive(Ssz)]
    #[ssz(internal)]
    struct Outer {
        leading: u32,
        first: Bytes,
        middle: u16,
        inner: Inner,
        last: Bytes,
    }

    #[derive(Ssz)]
    #[ssz(internal, derive_cursor = true)]
    struct Navigable {
        leading: u32,
        nested: NestedNavigable,
        trailing: ByteList<U8>,
    }

    #[derive(PartialEq, Eq, Debug, Ssz)]
    #[ssz(internal, derive_cursor = true)]
    struct NestedNavigable {
        head: u64,
        tail: H256,
    }

    #[derive(Ssz)]
    #[ssz(internal, derive_cursor = true, derive_hash = false)]
    struct GenericNavigable<N: Unsigned> {
        head: u64,
        #[ssz(skip)]
        _ignored: u64,
        tail: ByteList<N>,
    }

    #[test]
    fn field_returns_bytes_of_every_field() -> Result<()> {
        let outer = Outer {
            leading: 0x0102_0304,
            first: ContiguousList::try_from([0xAA, 0xBB])?,
            middle: 0x0506,
            inner: Inner {
                head: 0x0708,
                body: ContiguousList::try_from([0xCC])?,
            },
            last: ContiguousList::try_from([0xDD, 0xEE, 0xFF])?,
        };

        let bytes = outer.to_ssz()?;
        let cursor = SszCursor::new(&bytes).container::<Outer>();

        assert_eq!(cursor.field(0)?.buf, outer.leading.to_ssz()?);
        assert_eq!(cursor.field(1)?.buf, outer.first.to_ssz()?);
        assert_eq!(cursor.field(2)?.buf, outer.middle.to_ssz()?);
        assert_eq!(cursor.field(3)?.buf, outer.inner.to_ssz()?);
        assert_eq!(cursor.field(4)?.buf, outer.last.to_ssz()?);
        assert!(cursor.field(5).is_err());

        Ok(())
    }

    #[test]
    fn field_returns_bytes_of_progressive_container_field() -> Result<()> {
        let progressive = Progressive {
            head: 0x0102_0304,
            tail: ContiguousList::try_from([0xAA, 0xBB])?,
        };

        let bytes = progressive.to_ssz()?;
        let cursor = SszCursor::new(&bytes).container::<Progressive>();

        assert_eq!(cursor.field(0)?.buf, progressive.head.to_ssz()?);
        assert_eq!(cursor.field(1)?.buf, progressive.tail.to_ssz()?);

        Ok(())
    }

    #[test]
    fn union_splits_selector_from_payload() -> Result<()> {
        let bytes = Some(0x42_u8).to_ssz()?;
        let (selector, payload) = SszCursor::new(&bytes).union()?;

        assert_eq!(selector, 1);
        assert_eq!(payload.read::<(), u8>(&())?, 0x42);

        let bytes = None::<u8>.to_ssz()?;
        let (selector, payload) = SszCursor::new(&bytes).union()?;

        assert_eq!(selector, 0);
        assert!(payload.buf.is_empty());

        assert!(SszCursor::new(&[]).union().is_err());

        Ok(())
    }

    #[test]
    fn derived_cursor_reads_fields_without_deserializing_container() -> Result<()> {
        let navigable = Navigable {
            leading: 0x0102_0304,
            nested: NestedNavigable {
                head: 0x0506_0708_090A_0B0C,
                tail: H256::repeat_byte(0xDD),
            },
            trailing: ByteList::from(ContiguousList::try_from([0xAA, 0xBB])?),
        };

        let bytes = navigable.to_ssz()?;
        let cursor = Navigable::cursor(&bytes);

        assert_eq!(cursor.get_leading()?, navigable.leading);
        assert_eq!(cursor.get_trailing()?, navigable.trailing);

        let nested = cursor.get_nested()?;

        assert_eq!(nested.get_head()?, navigable.nested.head);
        assert_eq!(nested.get_tail()?, navigable.nested.tail);
        assert_eq!(nested.read(&())?, navigable.nested);

        Ok(())
    }

    #[test]
    fn derived_cursor_is_generic_and_skips_skipped_fields() -> Result<()> {
        let navigable = GenericNavigable::<U8> {
            head: 0x0102_0304_0506_0708,
            _ignored: 0x0900_0000_0000_0000,
            tail: ByteList::from(ContiguousList::try_from([0xAA, 0xBB])?),
        };

        let bytes = navigable.to_ssz()?;
        let cursor = GenericNavigable::<U8>::cursor(&bytes);

        assert_eq!(cursor.get_head()?, navigable.head);
        assert_eq!(cursor.get_tail()?, navigable.tail);

        Ok(())
    }

    #[test]
    fn field_returns_bytes_of_nested_container_field() -> Result<()> {
        let outer = Outer {
            leading: 0x0102_0304,
            first: ContiguousList::try_from([0xAA, 0xBB])?,
            middle: 0x0506,
            inner: Inner {
                head: 0x0708,
                body: ContiguousList::try_from([0xCC])?,
            },
            last: ContiguousList::try_from([0xDD, 0xEE, 0xFF])?,
        };

        let bytes = outer.to_ssz()?;
        let cursor = SszCursor::new(&bytes)
            .container::<Outer>()
            .field(3)?
            .container::<Inner>();

        assert_eq!(cursor.field(0)?.buf, outer.inner.head.to_ssz()?);
        assert_eq!(cursor.field(1)?.buf, outer.inner.body.to_ssz()?);

        Ok(())
    }
}
