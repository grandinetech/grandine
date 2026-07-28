#![allow(
    unused_crate_dependencies,
    reason = "the binary target shares the package's dependencies with the library; most are used by the library rather than by `main.rs`."
)]

use std::process::ExitCode;

use allocator as _;
use anyhow::Result;
use builder::BuilderArgs;
use clap::{Error as ClapError, Parser as _};
use tracing::error;

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
    let args = BuilderArgs::try_parse()?;
    builder::builder::run(args)
}
