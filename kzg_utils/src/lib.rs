pub use trusted_setup::settings;

pub mod eip_4844;

mod error;
mod trusted_setup;

#[cfg(test)]
mod spec_tests;

pub type KZGSettings = rust_kzg_blst::types::kzg_settings::FsKZGSettings;
