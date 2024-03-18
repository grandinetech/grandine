pub use crate::{
    attestation_agg_pool::{AttestationPacker, Manager as AttestationAggPool},
    bls_to_execution_change_pool::{
        BlsToExecutionChangePool, Service as BlsToExecutionChangePoolService,
    },
    messages::{PoolToApiMessage, PoolToLivenessMessage, PoolToP2pMessage},
    misc::{Origin, PoolAdditionOutcome, PoolRejectionReason},
    sync_committee_agg_pool::Manager as SyncCommitteeAggPool,
};

mod attestation_agg_pool {
    pub use attestation_packer::AttestationPacker;
    pub use manager::Manager;

    mod attestation_packer;
    mod manager;
    mod pool;
    mod tasks;
    mod types;
}

mod bls_to_execution_change_pool;
mod messages;
mod misc;

mod sync_committee_agg_pool {
    pub use manager::Manager;

    mod manager;
    mod pool;
    mod tasks;
    mod types;
}
