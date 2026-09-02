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
//! [`storage`]: ::storage

pub use crate::{
    controller::Controller,
    events::{DEFAULT_MAX_EVENTS, Event, EventChannels, Topic},
    hierarchy::Hierarchy,
    messages::{
        AttestationVerifierMessage, P2pMessage, PoolMessage, SubnetMessage, SyncMessage,
        ValidatorMessage,
    },
    misc::{
        MutatorIgnoreReason, MutatorRejectionReason, SidecarsPendingReconstruction,
        VerifyAggregateAndProofResult, VerifyAttestationResult, VerifyPayloadAttestationResult,
    },
    queries::{BlockWithRoot, ForkChoiceContext, ForkTip, Snapshot},
    specialized::{AdHocBenchController, BenchController},
    state_storage_config::StateStorageConfig,
    storage::{
        BlobSidecarByBlobId, BlockCheckpoint, BlockRootBySlot, DataColumnSidecarByColumnId,
        Error as StorageError, FinalizedBlockByRoot, SlotBlobId, SlotByStateRoot, SlotColumnId,
        StateByBlockRoot, StateCheckpoint, StateLoadStrategy, Storage, UnfinalizedBlockByRoot, get,
        print_beacon_database_info, save,
    },
    storage_tool::{export_state_and_blocks, replay_blocks},
    wait::Wait,
};

pub mod checkpoint_sync;
pub mod controller;

mod archival_pool;
mod block_processor;
mod events;
mod frame_cache;
mod hierarchy;
mod messages;
mod misc;
mod mutator;
mod queries;
mod specialized;
mod spine;
mod state_at_slot_cache;
mod state_storage_config;
mod storage;
mod storage_back_sync;
mod storage_tool;
mod tasks;
mod thread_pool;
mod unbounded_sink;
mod wait;

#[cfg(test)]
mod compliance_tests;
#[cfg(test)]
mod extra_tests;
#[cfg(test)]
mod helpers;
#[cfg(test)]
mod spec_tests;
