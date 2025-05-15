use std::process::ExitCode;

use allocator as _;
use anyhow::Result;
use clap::{Error as ClapError, Parser as _};
use logging::error_with_peers;
use runtime::grandine_args::GrandineArgs;

#[cfg(not(any(feature = "preset-any", test, doc)))]
compile_error! {
    "at least one preset must be enabled; \
     pass --features … to Cargo; \
     see grandine/Cargo.toml for a list of features"
}

fn main() -> ExitCode {
    if let Err(error) = try_main() {
        error.downcast_ref().map(ClapError::exit);
        error_with_peers!("{error:?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn try_main() -> Result<()> {
    let parsed_args = GrandineArgs::try_parse()?;

    runtime::run(parsed_args)
}
