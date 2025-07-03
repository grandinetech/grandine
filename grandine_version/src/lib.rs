use std::env::consts::{ARCH, OS};

use const_format::concatcp;

pub const APPLICATION_NAME: &str = "Grandine";

#[cfg(not(feature = "stub-grandine-version"))]
pub const APPLICATION_COMMIT: &str = git_version::git_version!(args = ["--always", "--abbrev=8"]);

#[cfg(feature = "stub-grandine-version")]
pub const APPLICATION_COMMIT: &str = "6a37d7fa";

#[cfg(not(feature = "stub-grandine-version"))]
pub const APPLICATION_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(feature = "stub-grandine-version")]
pub const APPLICATION_VERSION: &str = "1.2.3";

pub const APPLICATION_VERSION_WITH_COMMIT: &str =
    concatcp!(APPLICATION_VERSION, "-", APPLICATION_COMMIT);

pub const APPLICATION_NAME_WITH_VERSION: &str =
    concatcp!(APPLICATION_NAME, "/", APPLICATION_VERSION);

pub const APPLICATION_NAME_WITH_VERSION_AND_COMMIT: &str =
    concatcp!(APPLICATION_NAME, "/", APPLICATION_VERSION_WITH_COMMIT);

// Parts of a client version are conventionally separated with slashes.
// `eth2_libp2p` relies on this to identify clients.
pub const APPLICATION_VERSION_WITH_COMMIT_AND_PLATFORM: &str =
    concatcp!(APPLICATION_NAME_WITH_VERSION_AND_COMMIT, "/", ARCH, "-", OS);
