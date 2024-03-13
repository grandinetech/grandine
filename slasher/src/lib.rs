pub use crate::{
    messages::{SlasherToValidator, ValidatorToSlasher},
    slasher::{Databases, Slasher},
    slasher_config::SlasherConfig,
};

mod attestation_votes;
mod attestations;
mod blocks;
mod indexed_attestations;
mod messages;
mod slasher;
mod slasher_config;
mod status;
mod targets;
