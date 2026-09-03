use crate::{
    error::{ReadError, WriteError},
    porcelain::{SszRead, SszSize, SszWrite},
    size::Size,
};

impl<T: SszSize> SszSize for Option<T> {
    const SIZE: Size = Size::Variable { minimum_size: 1 };
}

impl<C, T: SszRead<C>> SszRead<C> for Option<T> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        match bytes.split_first() {
            None => Err(ReadError::Custom {
                message: "Option: missing selector byte",
            }),
            Some((&0, &[])) => Ok(None),
            Some((&0, _)) => Err(ReadError::Custom {
                message: "Option: trailing bytes after absent selector",
            }),
            Some((&1, value_bytes)) => Ok(Some(T::from_ssz(context, value_bytes)?)),
            Some((_, _)) => Err(ReadError::Custom {
                message: "Option: invalid selector byte",
            }),
        }
    }
}

impl<T: SszWrite> SszWrite for Option<T> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match &self {
            None => bytes.push(0),
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.to_ssz()?);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::{ReadError, WriteError},
        porcelain::{SszReadDefault, SszWrite},
    };

    #[test]
    fn encoding_matches_ssz_union_option() -> Result<(), WriteError> {
        assert_eq!(None::<u8>.to_ssz()?, [0]);
        assert_eq!(Some(42_u8).to_ssz()?, [1, 42]);

        Ok(())
    }

    #[test]
    fn decoding_matches_ssz_union_option() {
        assert!(matches!(
            Option::<u8>::from_ssz_default([]),
            Err(ReadError::Custom { message: _ }),
        ));

        assert!(matches!(
            Option::<u8>::from_ssz_default([0, 42]),
            Err(ReadError::Custom { message: _ }),
        ));

        assert!(matches!(
            Option::<u8>::from_ssz_default([2]),
            Err(ReadError::Custom { message: _ }),
        ));

        assert!(matches!(
            Option::<u8>::from_ssz_default([255]),
            Err(ReadError::Custom { message: _ }),
        ));

        assert!(matches!(Option::<u8>::from_ssz_default([0]), Ok(None),));

        assert!(matches!(
            Option::<u8>::from_ssz_default([1, 42]),
            Ok(Some(42)),
        ));
    }
}
