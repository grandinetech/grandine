use std::env::consts::{ARCH, OS};

pub const APPLICATION_NAME: &str = "Grandine";
pub const APPLICATION_VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub fn version_with_platform() -> String {
    // Parts of a client version are conventionally separated with slashes.
    // `eth2_libp2p` relies on this to identify clients.
    format!("{APPLICATION_NAME}/{APPLICATION_VERSION}/{ARCH}-{OS}")
}
