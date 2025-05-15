use std::alloc::{Layout, LayoutError};

use anyhow::Result;

use crate::{
    arrays::{CH256, CH384},
    containers::{CBlobAndProofV1, CBlobAndProofV2, CTransaction, CWithdrawalV1},
    generic::{COption, CVec},
};

#[repr(C)]
pub struct CLayout {
    size: usize,
    align: usize,
}

impl CLayout {
    pub const fn new(layout: Layout) -> Self {
        Self {
            size: layout.size(),
            align: layout.align(),
        }
    }
}

impl TryInto<Layout> for CLayout {
    type Error = LayoutError;

    fn try_into(self) -> Result<Layout, Self::Error> {
        Layout::from_size_align(self.size, self.align)
    }
}

// layouts for every used type in CVec
// they're defined as functions, because cbindgen somehow doesn't support consts for computed values,
// and csbindgen doesn't support statics.

#[no_mangle]
pub extern "C" fn grandine_layout_u8() -> CLayout {
    CLayout::new(Layout::new::<u8>())
}

#[no_mangle]
pub extern "C" fn grandine_layout_transaction() -> CLayout {
    CLayout::new(Layout::new::<CTransaction>())
}

#[no_mangle]
pub extern "C" fn grandine_layout_withdrawal() -> CLayout {
    CLayout::new(Layout::new::<CWithdrawalV1>())
}

#[no_mangle]
pub extern "C" fn grandine_layout_h256() -> CLayout {
    CLayout::new(Layout::new::<CH256>())
}

#[no_mangle]
pub extern "C" fn grandine_layout_h384() -> CLayout {
    CLayout::new(Layout::new::<CH384>())
}

#[no_mangle]
pub extern "C" fn grandine_layout_vec_u8() -> CLayout {
    CLayout::new(Layout::new::<CVec<u8>>())
}

#[no_mangle]
pub extern "C" fn grandine_layout_option_blob_and_proof_v1() -> CLayout {
    CLayout::new(Layout::new::<COption<CBlobAndProofV1>>())
}

#[no_mangle]
pub extern "C" fn grandine_layout_blob_and_proof_v2() -> CLayout {
    CLayout::new(Layout::new::<CBlobAndProofV2>())
}

// this is just straight copy-paste from rust std library
// TODO: once Layout.repeat(n) stabilizes, remove this function.
pub fn repeat_layout(item_layout: Layout, n: usize) -> Result<Layout> {
    let padded = item_layout.pad_to_align();

    if let Some(size) = padded.size().checked_mul(n) {
        // The safe constructor is called here to enforce the isize size limit.
        Ok(Layout::from_size_align(size, padded.align())?)
    } else {
        anyhow::bail!("Invalid layout");
    }
}
