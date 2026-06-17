//! Grandine builder client.
//!
//! Implements the staked builder duties defined in
//! - [Gloas](https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/builder.md)
//!
//! The builder runs as a separate process: it follows the chain via a configured
//! beacon node's REST API and SSE, builds payloads with its own execution engine
//! connection via the Engine API, signs bids and envelopes locally, and publishes them
//! back through the beacon node's API endpoints.

// `allocator` is linked only by the binary target; `kzg_utils` is pulled in via
// the `default` feature (`kzg_utils/blst`) to select the BLS backend.
use allocator as _;
use kzg_utils as _;

pub use crate::{args::BuilderArgs, builder::Builder, config::BuilderConfig};

mod args;
mod bn_client;
pub mod builder;
mod config;
mod error;
mod payload_builder;
