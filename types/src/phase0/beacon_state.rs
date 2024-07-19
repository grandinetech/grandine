use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::{BitVector, Ssz};

use crate::{
    cache::Cache,
    collections::{
        Attestations, Balances, Eth1DataVotes, HistoricalRoots, RandaoMixes, RecentRoots,
        Slashings, Validators,
    },
    phase0::{
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork},
        primitives::{DepositIndex, Slot, UnixSeconds, H256},
    },
    preset::Preset,
};

#[derive(Clone, Default, Debug, Derivative, Deserialize, Serialize, Ssz)]
#[derivative(PartialEq, Eq)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BeaconState<P: Preset> {
    // > Versioning
    #[serde(with = "serde_utils::string_or_native")]
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub fork: Fork,

    // > History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: RecentRoots<P>,
    pub state_roots: RecentRoots<P>,
    pub historical_roots: HistoricalRoots<P>,

    // > Eth1
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Eth1DataVotes<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub eth1_deposit_index: DepositIndex,

    // > Registry
    pub validators: Validators<P>,
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub balances: Balances<P>,

    // > Randomness
    pub randao_mixes: RandaoMixes<P>,

    // > Slashings
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub slashings: Slashings<P>,

    // > Attestations
    pub previous_epoch_attestations: Attestations<P>,
    pub current_epoch_attestations: Attestations<P>,

    // > Finality
    pub justification_bits: BitVector<JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // Cache
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    #[ssz(skip)]
    pub cache: Cache,
}
