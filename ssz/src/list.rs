use core::fmt::Debug;

use serde::{Serialize, Serializer};
use typenum::U1;

use crate::{
    error::{IndexError, PushError, ReadError, WriteError},
    porcelain::{SszHash, SszSize, SszWrite},
    shared,
    size::Size,
};

pub trait SszList<T>: SszHash<PackingFactor = U1> + Send + Sync + Debug {
    fn len_usize(&self) -> usize;

    fn len_u64(&self) -> u64;

    fn get(&self, index: u64) -> Result<&T, IndexError>;

    fn iter<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = &'a T> + 'a>;

    fn clone_boxed(&self) -> Box<dyn SszList<T>>
    where
        T: Clone + 'static;
}

pub trait SszListMut<T>: SszList<T> {
    fn get_mut(&mut self, index: u64) -> Result<&mut T, IndexError>
    where
        T: Clone;

    fn push(&mut self, value: T) -> Result<(), PushError>
    where
        T: Clone;

    fn update(&mut self, f: &mut dyn FnMut(&mut T))
    where
        T: Clone + PartialEq;

    fn try_assign_from_iter(&mut self, iter: &mut dyn Iterator<Item = T>) -> Result<(), ReadError>;

    fn iter_mut<'a>(&'a mut self) -> Box<dyn ExactSizeIterator<Item = &'a mut T> + 'a>
    where
        T: Clone;
}

pub trait SszBitList: SszHash<PackingFactor = U1> + Send + Sync + Debug {
    fn len_usize(&self) -> usize;

    fn len_u64(&self) -> u64;

    fn get_bit(&self, index: usize) -> Option<bool>;

    fn count_ones(&self) -> usize;

    fn iter_bits<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = bool> + 'a>;
}

impl<'a, T> IntoIterator for &'a (dyn SszList<T> + 'a) {
    type Item = &'a T;
    type IntoIter = Box<dyn ExactSizeIterator<Item = &'a T> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T: Clone> IntoIterator for &'a mut (dyn SszListMut<T> + 'a) {
    type Item = &'a mut T;
    type IntoIter = Box<dyn ExactSizeIterator<Item = &'a mut T> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T: Serialize> Serialize for dyn SszList<T> + '_ {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter())
    }
}

impl<T: SszSize> SszSize for dyn SszList<T> + '_ {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<T: SszWrite> SszWrite for dyn SszList<T> + '_ {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        shared::write_list(bytes, self.iter())
    }
}
