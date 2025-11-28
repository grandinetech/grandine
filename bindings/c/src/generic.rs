use core::{ptr, slice};
use std::{
    ffi::{CStr, CString},
    fmt::{self, Debug},
    mem,
    ops::{Deref, DerefMut},
    os::raw::c_char,
};

use anyhow::Result;
use generic_array::ArrayLength;
use ssz::ByteList;

pub const GRANDINE_SUCCESS: u32 = 0;
pub const GRANDINE_ERROR_GENERIC: u32 = 1;
pub const GRANDINE_ERROR_ENGINE_API: u32 = 2;

#[repr(C)]
#[derive(Debug)]
pub struct CErrorMessage(*mut c_char);

impl Drop for CErrorMessage {
    fn drop(&mut self) {
        if self.0 != ptr::null_mut() {
            let _ = unsafe { CString::from_raw(self.0) };
        }
    }
}

impl Into<Option<CString>> for CErrorMessage {
    fn into(self) -> Option<CString> {
        if self.0 == ptr::null_mut() {
            None
        } else {
            let result = unsafe { CString::from_raw(self.0) };
            // avoid double freeing pointer, as we pass ownership to CString
            mem::forget(self);
            Some(result)
        }
    }
}

impl CErrorMessage {
    pub fn empty() -> Self {
        Self(ptr::null_mut())
    }

    pub unsafe fn new(v: *const c_char) -> Self {
        let v = CStr::from_ptr(v);

        Self(v.to_owned().into_raw())
    }
}

#[repr(C)]
pub struct CResult<T> {
    pub value: T,
    pub code: u32,
    pub message: CErrorMessage,
}

impl<T: Debug> Debug for CResult<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.code == GRANDINE_SUCCESS {
            f.debug_tuple("Ok").field(&self.value).finish()
        } else {
            f.debug_struct("Err")
                .field("code", &self.code)
                .field("message", &self.message)
                .finish()
        }
    }
}

impl<T: Default> CResult<T> {
    pub fn ok(value: T) -> Self {
        Self {
            value,
            code: GRANDINE_SUCCESS,
            message: CErrorMessage::empty(),
        }
    }

    pub fn err(code: u32, message: Option<String>) -> Self {
        Self {
            value: Default::default(),
            code,
            message: message
                .and_then(|v| Some(CErrorMessage(CString::new(v).ok()?.into_raw())))
                .unwrap_or(CErrorMessage::empty()),
        }
    }
}

impl<T> From<CResult<T>> for Result<T> {
    fn from(error: CResult<T>) -> Self {
        if error.code == GRANDINE_SUCCESS {
            return Ok(error.value);
        }

        let header = match error.code {
            GRANDINE_ERROR_ENGINE_API => "api error occurred",
            GRANDINE_ERROR_GENERIC => "unexpected error occurred",
            _ => "unknown error occurred",
        };

        let Some(message): Option<CString> = error.message.into() else {
            anyhow::bail!("{header}, code {code}", code = error.code);
        };

        anyhow::bail!(
            "{header}, code {code}: {message}",
            code = error.code,
            message = message.to_string_lossy()
        );
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
            is_something: self.is_something,
            value: self.value.clone(),
        }
    }
}

impl<T: Debug> Debug for COption<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.debug_list().entries(self.iter()).finish()
        } else {
            f.debug_struct("CVec")
                .field("data", &self.data)
                .field("data_len", &self.data_len)
                .finish()
        }
    }
}

impl<T> Drop for CVec<T> {
    fn drop(&mut self) {
        if self.data == ptr::null_mut() {
            return;
        }

        let _ = unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                self.data,
                self.data_len as usize,
            ))
        };
        self.data = ptr::null_mut();
        self.data_len = 0;
    }
}

impl<T: Clone> Clone for CVec<T> {
    fn clone(&self) -> Self {
        if self.data == ptr::null_mut() {
            Self {
                data: ptr::null_mut(),
                data_len: 0,
            }
        } else {
            let data = unsafe { &*ptr::slice_from_raw_parts(self.data, self.data_len as usize) };
            let cloned = data.to_vec().into_boxed_slice();
            let new_ptr = Box::into_raw(cloned);

            Self {
                data: new_ptr as *mut T,
                data_len: self.data_len,
            }
        }
    }
}

impl<T> Default for CVec<T> {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            data_len: 0,
        }
    }
}

impl<T> Into<CVec<T>> for Vec<T> {
    fn into(self) -> CVec<T> {
        if self.is_empty() {
            CVec::<T> {
                data: ptr::null_mut(),
                data_len: 0,
            }
        } else {
            let boxed = self.into_boxed_slice();
            let data_len = boxed.len() as u64;
            let data = Box::into_raw(boxed);

            CVec::<T> {
                data: data as *mut T,
                data_len,
            }
        }
    }
}

impl<T> Into<Vec<T>> for CVec<T> {
    fn into(self) -> Vec<T> {
        if self.data == ptr::null_mut() {
            Vec::new()
        } else {
            let boxed = unsafe { Box::from_raw(self.into_raw()) };
            boxed.into_vec()
        }
    }
}

impl<T> CVec<T> {
    /// Returns inner pointer, consuming current container.
    /// Required if this vec contains pointer to foreign memory,
    /// and you want to free it with custom allocator.
    pub fn into_raw(self) -> *mut [T] {
        let ptr = ptr::slice_from_raw_parts_mut(self.data, self.data_len as usize);
        mem::forget(self);
        ptr
    }

    pub fn iter(&self) -> slice::Iter<'_, T> {
        if self.data == ptr::null_mut() {
            [].iter()
        } else {
            unsafe { &*ptr::slice_from_raw_parts(self.data, self.data_len as usize) }.iter()
        }
    }

    pub fn as_slice(&self) -> &[T] {
        if self.data == ptr::null_mut() {
            &[]
        } else {
            unsafe { &*ptr::slice_from_raw_parts(self.data, self.data_len as usize) }
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        if self.data == ptr::null_mut() {
            &mut []
        } else {
            unsafe { &mut *ptr::slice_from_raw_parts_mut(self.data, self.data_len as usize) }
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

impl CVec<u8> {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<&'_ [u8]> for CVec<u8> {
    fn from(value: &'_ [u8]) -> Self {
        value.to_vec().into()
    }
}

impl<T: ArrayLength<u8>> TryInto<ByteList<T>> for CVec<u8> {
    type Error = ssz::ReadError;

    fn try_into(self) -> Result<ByteList<T>, Self::Error> {
        let vec: Vec<_> = self.into();
        ByteList::try_from(vec)
    }
}
