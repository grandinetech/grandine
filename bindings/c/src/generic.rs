use anyhow::Result;
use generic_array::ArrayLength;
use ssz::ByteList;
use std::{
    fmt::Debug,
    mem,
    ops::{Deref, DerefMut},
};

#[repr(C)]
pub struct CResult<T> {
    value: T,
    error: u64,
}

impl<T> From<CResult<T>> for Result<T> {
    fn from(value: CResult<T>) -> Self {
        if value.error == 0 {
            Ok(value.value)
        } else {
            anyhow::bail!("failed with error code {}", value.error)
        }
    }
}

#[repr(C)]
pub struct COption<T> {
    is_something: bool,
    value: T,
}

impl<T> COption<T> {
    pub fn some(value: T) -> Self {
        Self {
            is_something: true,
            value,
        }
    }
}

impl<T: Default> COption<T> {
    pub fn none() -> Self {
        Self {
            is_something: false,
            value: Default::default(),
        }
    }
}

impl<T: Clone> Clone for COption<T> {
    fn clone(&self) -> Self {
        Self {
            is_something: self.is_something.clone(),
            value: self.value.clone(),
        }
    }
}

impl<T: Debug> Debug for COption<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("COption")
            .field("is_something", &self.is_something)
            .field("value", &self.value)
            .finish()
    }
}

impl<T> Into<Option<T>> for COption<T> {
    fn into(self) -> Option<T> {
        if self.is_something {
            Some(self.value)
        } else {
            None
        }
    }
}

impl<T: Default> From<Option<T>> for COption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => COption::some(value),
            None => COption::none(),
        }
    }
}

#[repr(C)]
pub struct CVec<T> {
    data: *mut T,
    data_len: u64,
}

impl<T> Deref for CVec<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> DerefMut for CVec<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T: Debug> Debug for CVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T> Drop for CVec<T> {
    fn drop(&mut self) {
        if self.data == core::ptr::null_mut() {
            return;
        }

        let _ = unsafe {
            Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                self.data,
                self.data_len as usize,
            ))
        };
        self.data = core::ptr::null_mut();
        self.data_len = 0;
    }
}

impl<T: Clone> Clone for CVec<T> {
    fn clone(&self) -> Self {
        let data = unsafe { &*core::ptr::slice_from_raw_parts(self.data, self.data_len as usize) };
        let cloned = data.to_vec().into_boxed_slice();
        let new_ptr = Box::into_raw(cloned);

        Self {
            data: new_ptr as *mut T,
            data_len: self.data_len,
        }
    }
}

impl<T> Default for CVec<T> {
    fn default() -> Self {
        Self {
            data: std::ptr::null_mut(),
            data_len: 0,
        }
    }
}

impl<T> Into<CVec<T>> for Vec<T> {
    fn into(self) -> CVec<T> {
        let boxed = self.into_boxed_slice();
        let data_len = boxed.len() as u64;
        let data = Box::into_raw(boxed);

        CVec::<T> {
            data: data as *mut T,
            data_len,
        }
    }
}

impl<T> Into<Vec<T>> for CVec<T> {
    fn into(self) -> Vec<T> {
        let boxed = unsafe { Box::from_raw(self.into_raw()) };

        boxed.into_vec()
    }
}

impl<T> CVec<T> {
    /// Returns inner pointer, consuming current container.
    /// Required if this vec contains pointer to foreign memory,
    /// and you want to free it with custom allocator.
    pub fn into_raw(self) -> *mut [T] {
        let ptr = core::ptr::slice_from_raw_parts_mut(self.data, self.data_len as usize);
        mem::forget(self);
        ptr
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        if self.data == core::ptr::null_mut() {
            [].iter()
        } else {
            unsafe { &*core::ptr::slice_from_raw_parts(self.data, self.data_len as usize) }.iter()
        }
    }

    pub fn as_slice(&self) -> &[T] {
        if self.data == core::ptr::null_mut() {
            &[]
        } else {
            unsafe { &*core::ptr::slice_from_raw_parts(self.data, self.data_len as usize) }
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        if self.data == core::ptr::null_mut() {
            &mut []
        } else {
            unsafe { &mut *core::ptr::slice_from_raw_parts_mut(self.data, self.data_len as usize) }
        }
    }
}

impl<T> IntoIterator for CVec<T> {
    type Item = T;

    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let vec: Vec<_> = self.into();

        vec.into_iter()
    }
}

impl<T> FromIterator<T> for CVec<T> {
    fn from_iter<V: IntoIterator<Item = T>>(iter: V) -> Self {
        Vec::<T>::from_iter(iter).into()
    }
}

pub type CByteVector = CVec<u8>;

impl CByteVector {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<&'_ [u8]> for CByteVector {
    fn from(value: &'_ [u8]) -> Self {
        value.to_vec().into()
    }
}

impl<T: ArrayLength<u8>> Into<ByteList<T>> for CByteVector {
    fn into(self) -> ByteList<T> {
        // TODO: don't panic here
        let vec: Vec<_> = self.into();
        ByteList::try_from(vec).unwrap()
    }
}

// #[derive(Clone, Debug)]
// struct CCharPtr(*const c_char);

// impl Default for CCharPtr {
//     fn default() -> Self {
//         Self(generic::ptr::null())
//     }
// }
