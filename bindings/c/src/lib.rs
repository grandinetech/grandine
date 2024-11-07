use libc::c_char;
use runtime::{run, GrandineArgs};
use std::ffi::CStr;
use clap::Parser;
use allocator as _;
use anyhow::Result;
use log::error;
use clap::Error as ClapError;

pub fn try_run(argc: u64, argv: *const *const c_char) -> Result<()> {
    let args = unsafe {
        std::iter::once("").chain(std::slice::from_raw_parts(argv, argc as usize).into_iter().filter_map(|it| CStr::from_ptr(*it).to_str().ok()))
    };

    let args = GrandineArgs::try_parse_from(args)?;

    let config = args.try_into_config()?;

    run(config)
}

#[no_mangle]
pub extern "C" fn grandine_run(argc: u64, argv: *const *const c_char) -> u64 {
    if let Err(error) = try_run(argc, argv) {
        error.downcast_ref().map(ClapError::exit);
        error!("{error:?}");

        return 1;
    }

    return 0;
}
