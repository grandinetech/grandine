use core::num::NonZeroU64;

use hex_literal::hex;
use nonzero_ext::nonzero;
use static_assertions::const_assert_eq;
use typenum::{assert_type_eq, U1, U105, U2, U20, U22, U23, U24, U4, U54, U55};

use crate::{
    phase0::primitives::{DomainType, H32},
    unphased::consts::{ConcatGeneralizedIndices, GeneralizedIndexInContainer},
};

pub const DOMAIN_CONTRIBUTION_AND_PROOF: DomainType = H32(hex!("09000000"));
pub const DOMAIN_SYNC_COMMITTEE: DomainType = H32(hex!("07000000"));
pub const DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF: DomainType = H32(hex!("08000000"));

pub const TIMELY_SOURCE_FLAG_INDEX: usize = 0;
pub const TIMELY_TARGET_FLAG_INDEX: usize = 1;
pub const TIMELY_HEAD_FLAG_INDEX: usize = 2;

pub const TIMELY_SOURCE_WEIGHT: u64 = 14;
pub const TIMELY_TARGET_WEIGHT: u64 = 26;
pub const TIMELY_HEAD_WEIGHT: u64 = 14;

pub const PARTICIPATION_FLAG_WEIGHTS: [(usize, u64); 3] = [
    (TIMELY_SOURCE_FLAG_INDEX, TIMELY_SOURCE_WEIGHT),
    (TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_WEIGHT),
    (TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT),
];

pub const SYNC_REWARD_WEIGHT: u64 = 2;
pub const PROPOSER_WEIGHT: u64 = 8;
pub const WEIGHT_DENOMINATOR: NonZeroU64 = nonzero!(64_u64);

const_assert_eq!(
    WEIGHT_DENOMINATOR.get(),
    TIMELY_SOURCE_WEIGHT
        + TIMELY_TARGET_WEIGHT
        + TIMELY_HEAD_WEIGHT
        + SYNC_REWARD_WEIGHT
        + PROPOSER_WEIGHT,
);

pub const TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE: NonZeroU64 = nonzero!(16_u64);

pub type SyncCommitteeSubnetCount = U4;

/// [`FINALIZED_ROOT_INDEX`](https://github.com/ethereum/consensus-specs/blob/d8e74090cf33864f1956a1ee12ba5a94d21a6ac4/specs/altair/light-client/sync-protocol.md#constants)
///
/// ```text
/// 1┬2 Checkpoint.epoch
///  └3 Checkpoint.root
///
/// 52 BeaconState.finalized_checkpoint┬104 Checkpoint.epoch
///                                    └105 Checkpoint.root
/// ```
pub type FinalizedRootIndex = ConcatGeneralizedIndices<
    GeneralizedIndexInContainer<U20, U24>,
    GeneralizedIndexInContainer<U1, U2>,
>;

/// [`CURRENT_SYNC_COMMITTEE_INDEX`](https://github.com/ethereum/consensus-specs/blob/d8e74090cf33864f1956a1ee12ba5a94d21a6ac4/specs/altair/light-client/sync-protocol.md#constants)
///
/// ```text
/// 1┬─2┬─4┬─8┬16┬32 BeaconState.genesis_time
///  │  │  │  │  └33 BeaconState.genesis_validators_root
///  │  │  │  └17┬34 BeaconState.slot
///  │  │  │     └35 BeaconState.fork
///  │  │  └─9┬18┬36 BeaconState.latest_block_header
///  │  │     │  └37 BeaconState.block_roots
///  │  │     └19┬38 BeaconState.state_roots
///  │  │        └39 BeaconState.historical_roots
///  │  └─5┬10┬20┬40 BeaconState.eth1_data
///  │     │  │  └41 BeaconState.eth1_data_votes
///  │     │  └21┬42 BeaconState.eth1_deposit_index
///  │     │     └43 BeaconState.validators
///  │     └11┬22┬44 BeaconState.balances
///  │        │  └45 BeaconState.randao_mixes
///  │        └23┬46 BeaconState.slashings
///  │           └47 BeaconState.previous_epoch_participation
///  └─3──6┬12┬24┬48 BeaconState.current_epoch_participation
///        │  │  └49 BeaconState.justification_bits
///        │  └25┬50 BeaconState.previous_justified_checkpoint
///        │     └51 BeaconState.current_justified_checkpoint
///        └13┬26┬52 BeaconState.finalized_checkpoint
///           │  └53 BeaconState.inactivity_scores
///           └27┬54 BeaconState.current_sync_committee
///              └55 BeaconState.next_sync_committee
/// ```
pub type CurrentSyncCommitteeIndex = GeneralizedIndexInContainer<U22, U24>;

/// [`NEXT_SYNC_COMMITTEE_INDEX`](https://github.com/ethereum/consensus-specs/blob/d8e74090cf33864f1956a1ee12ba5a94d21a6ac4/specs/altair/light-client/sync-protocol.md#constants)
///
/// See the diagram for [`CurrentSyncCommitteeIndex`].
pub type NextSyncCommitteeIndex = GeneralizedIndexInContainer<U23, U24>;

// This could also be done using `static_assertions::assert_type_eq_all!`.
assert_type_eq!(FinalizedRootIndex, U105);
assert_type_eq!(CurrentSyncCommitteeIndex, U54);
assert_type_eq!(NextSyncCommitteeIndex, U55);
