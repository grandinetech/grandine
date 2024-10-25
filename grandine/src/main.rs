use std::process::ExitCode;

use allocator as _;
use anyhow::Result;
use clap::{Error as ClapError, Parser as _};
use log::error;
use runtime::Error;

use crate::grandine_args::GrandineArgs;

mod grandine_args;

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

fn try_main() -> Result<()> {
    let config = GrandineArgs::try_parse()?
        .try_into_config()
        .map_err(GrandineArgs::clap_error)?;

    match runtime::run(config) {
        Ok(()) => Ok(()),
        Err(error) => {
            if matches!(error.downcast_ref(), Some(Error::ArgumentsError { .. })) {
                Err(GrandineArgs::clap_error(error).into())
            } else {
                Err(error)
            }
        }
    }
}
