pub mod accessors;
pub mod altair;
pub mod bellatrix;
pub mod capella;
pub mod electra;
pub mod error;
pub mod fork;
pub mod gloas;
pub mod misc;
pub mod mutators;
pub mod par_utils;
pub mod phase0;
pub mod predicates;
pub mod signing;
pub mod slot_report;
pub mod verifier;

// The runner for `bls/eth_fast_aggregate_verify` test cases uses `Verifier` from this crate.
// The runner had to be moved here due to an unexpected issue with cyclic dependencies. See:
// - <https://github.com/rust-lang/rust/issues/59305>
// - <https://github.com/rust-lang/rust/issues/79381>
#[cfg(test)]
mod spec_tests;
