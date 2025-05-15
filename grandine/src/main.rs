use std::process::ExitCode;

use allocator as _;
use anyhow::Result;
use clap::{Error as ClapError, Parser as _};
use log::error;
use runtime::grandine_args::GrandineArgs;

#[cfg(any(feature = "preset-mainnet", test))]
use types::preset::Mainnet;
#[cfg(any(feature = "preset-minimal", test))]
use types::preset::Minimal;

#[cfg(not(any(feature = "preset-any", test, doc)))]
compile_error! {
    "at least one preset must be enabled; \
     pass --features … to Cargo; \
     see grandine/Cargo.toml for a list of features"
}

fn main() -> ExitCode {
    if let Err(error) = try_main() {
        error.downcast_ref().map(ClapError::exit);
        error!("{error:?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[expect(clippy::too_many_lines)]
fn try_main() -> Result<()> {
    let config = GrandineArgs::try_parse()?
        .try_into_config()
        .map_err(GrandineArgs::clap_error)?;

    runtime::run(config)
}
