pub mod ids;
pub mod local;
pub mod traits;
pub mod types;

pub use crate::local::{LocalBeaconClient, LocalConfig};

pub use crate::{
    ids::{BlockId, StateId},
    traits::{BeaconChainReader, BeaconDutyEndpoints, BeaconEventStream, BeaconPublisher},
    types::{
        AttesterDuty, BlockEncoding, BlockHeaderSummary, BlockProductionOptions,
        BroadcastValidation, CommitteeIndexAndSlot, DutiesResponse, GenesisData,
        OwnSyncMessageAggregates, ProposerDuty, ProposerGasLimit, ProposerPreparation,
        ProposerRegistrationStatus, SyncCommitteeDuty, SyncingStatus, ValidatorLiveness,
    },
};
