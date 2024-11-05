use libc::c_char;
use runtime::{run, GrandineArgs};
use std::ffi::CStr;
use clap::Parser;
use allocator as _;

#[no_mangle]
pub extern "C" fn grandine_run(argc: u64, argv: *const *const c_char) -> u64 {
    let args = unsafe {
        std::slice::from_raw_parts(argv, argc as usize).into_iter().filter_map(|it| CStr::from_ptr(*it).to_str().ok())
    };

    println!("{:?}", args.clone().collect::<Vec<_>>());

    let Ok(args) = GrandineArgs::try_parse_from(args) else {
        return 1;
    };

    let Ok(config) = args.try_into_config() else {
        return 1;
    };

    if run(config).is_err() { 1 } else { 0 }
}
