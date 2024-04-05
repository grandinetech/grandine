use std::env::consts::{ARCH, OS};

use const_format::concatcp;
use git_version::git_version;

pub const APPLICATION_NAME: &str = "Grandine";
pub const APPLICATION_VERSION: &str = concatcp!(
    env!("CARGO_PKG_VERSION"),
    "-",
    git_version!(args = ["--always"]),
);

pub const APPLICATION_NAME_AND_VERSION: &str =
    concatcp!(APPLICATION_NAME, "/", APPLICATION_VERSION);

// Parts of a client version are conventionally separated with slashes.
// `eth2_libp2p` relies on this to identify clients.
pub const APPLICATION_VERSION_WITH_PLATFORM: &str =
    concatcp!(APPLICATION_NAME_AND_VERSION, "/", ARCH, "-", OS);
