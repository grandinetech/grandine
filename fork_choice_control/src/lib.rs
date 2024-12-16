//! Supporting code for the fork choice store.
//!
//! This crate handles the following concerns:
//! - [Persistence](`storage`).
//! - [Exporting data from the database](`storage_tool`).
//! - [Parallel processing and task priorities](`thread_pool`).
//! - [Waiting for task completion](`Controller::wait_for_tasks`).
//! - Delaying and retrying objects that cannot be processed immediately.
//! - Waiting for checkpoint states.
//! - Notifying other components of the application about changes to the fork choice store.
//! - Testing.
//!
//! This crate exists primarily to separate [`fork_choice_store`] from persistence.
//! [`fork_choice_store`] should never depend on [`storage`] or any other databases.
//!
//! [`storage`]: ::storage

pub use crate::{
    controller::Controller,
    messages::{
        AttestationVerifierMessage, P2pMessage, PoolMessage, SubnetMessage, SyncMessage,
        ValidatorMessage,
    },
    misc::{MutatorRejectionReason, VerifyAggregateAndProofResult, VerifyAttestationResult},
    queries::{BlockWithRoot, ForkChoiceContext, ForkTip, Snapshot},
    specialized::{AdHocBenchController, BenchController},
    storage::{
        BlobSidecarByBlobId, BlockCheckpoint, BlockRootBySlot, FinalizedBlockByRoot, PrefixableKey,
        SlotBlobId, SlotByStateRoot, StateByBlockRoot, StateCheckpoint, UnfinalizedBlockByRoot,
    },
    storage::{StateLoadStrategy, Storage, DEFAULT_ARCHIVAL_EPOCH_INTERVAL},
    storage_tool::{export_state_and_blocks, replay_blocks},
    wait::Wait,
};

pub mod checkpoint_sync;

mod block_processor;
mod controller;
mod messages;
mod misc;
mod mutator;
mod queries;
mod specialized;
mod storage;
mod storage_back_sync;
mod storage_tool;
mod tasks;
mod thread_pool;
mod unbounded_sink;
mod wait;

#[cfg(test)]
mod extra_tests;
#[cfg(test)]
mod helpers;
#[cfg(test)]
mod spec_tests;
