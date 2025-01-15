pub mod eip_4844;

mod bls;
mod error;
mod trusted_setup;

#[cfg(test)]
mod spec_tests;

#[cfg(not(any(feature = "bls-backend-any", test, doc)))]
compile_error! {
    "at least one backend must be enabled; \
     pass --features … to Cargo; \
     see kzg_utils/Cargo.toml for a list of features"
}

pub use bls::{KzgBackend, KzgBackendParseError, DEFAULT_KZG_BACKEND};
