//! Utilities for loading data from the [`eth2-cache`] submodule at runtime.
//!
//! This crate is intended for use in tests and benchmarks.
//! Applications should use [`predefined_chains`].
//!
//! [`eth2-cache`]:        ../../../eth2-cache/
//! [`predefined_chains`]: ../predefined_chains/index.html

pub use generic::{LazyBeaconBlock, LazyBeaconBlocks, LazyBeaconState};

pub mod goerli;
pub mod holesky;
pub mod holesky_devnet;
pub mod mainnet;
pub mod medalla;
pub mod withdrawal_devnet_3;
pub mod withdrawal_devnet_4;

mod generic;
