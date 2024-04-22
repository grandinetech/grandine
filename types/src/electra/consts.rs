use hex_literal::hex;
use typenum::{assert_type_eq, U1, U169, U2, U20, U22, U23, U37, U86, U87};

use crate::{
    phase0::primitives::{DomainType, H32},
    unphased::consts::{ConcatGeneralizedIndices, GeneralizedIndexInContainer},
};

// Misc
pub const UNSET_DEPOSIT_RECEIPTS_START_INDEX: u64 = u64::MAX;
pub const FULL_EXIT_REQUEST_AMOUNT: u64 = 0;

pub const COMPOUNDING_WITHDRAWAL_PREFIX: &[u8] = &hex!("02");

// Domains
pub const DOMAIN_CONSOLIDATION: DomainType = H32(hex!("0B000000"));

/// ```text
/// 1┬2 Checkpoint.epoch
///  └3 Checkpoint.root
///
/// 84 BeaconState.finalized_checkpoint┬168 Checkpoint.epoch
///                                    └169 Checkpoint.root
/// ```
pub type FinalizedRootIndex = ConcatGeneralizedIndices<
    GeneralizedIndexInContainer<U20, U37>,
    GeneralizedIndexInContainer<U1, U2>,
>;

/// ```text
/// 1┬─2┬─4┬─8┬16┬32┬─64 BeaconState.genesis_time
///  │  │  │  │  │  └─65 BeaconState.genesis_validators_root
///  │  │  │  │  └33┬─66 BeaconState.slot
///  │  │  │  │     └─67 BeaconState.fork
///  │  │  │  └17┬34┬─68 BeaconState.latest_block_header
///  │  │  │     │  └─69 BeaconState.block_roots
///  │  │  │     └35┬─70 BeaconState.state_roots
///  │  │  │        └─71 BeaconState.historical_roots
///  │  │  └─9┬18┬36┬─72 BeaconState.eth1_data
///  │  │     │  │  └─73 BeaconState.eth1_data_votes
///  │  │     │  └37┬─74 BeaconState.eth1_deposit_index
///  │  │     │     └─75 BeaconState.validators
///  │  │     └19┬38┬─76 BeaconState.balances
///  │  │        │  └─77 BeaconState.randao_mixes
///  │  │        └39┬─78 BeaconState.slashings
///  │  │           └─79 BeaconState.previous_epoch_participation
///  │  └─5┬10┬20┬40┬─80 BeaconState.current_epoch_participation
///  │     │  │  │  └─81 BeaconState.justification_bits
///  │     │  │  └41┬─82 BeaconState.previous_justified_checkpoint
///  │     │  │     └─83 BeaconState.current_justified_checkpoint
///  │     │  └21┬42┬─84 BeaconState.finalized_checkpoint
///  │     │     │  └─85 BeaconState.inactivity_scores
///  │     │     └43┬─86 BeaconState.current_sync_committee
///  │     │        └─87 BeaconState.next_sync_committee
///  │     └11┬22┬44┬─88 BeaconState.latest_execution_payload_header
///  │        │  │  └─89 BeaconState.next_withdrawal_index
///  │        │  └45┬─90 BeaconState.next_withdrawal_validator_index
///  │        │     └─91 BeaconState.deposit_receipts_start_index
///  │        └23┬46┬─92 BeaconState.historical_summaries
///  │           │  └─93 BeaconState.deposit_balance_to_consume
///  │           └47┬─94 BeaconState.exit_balance_to_consume
///  │              └─95 BeaconState.earliest_exit_epoch
///  └─3──6─12┬24┬48┬─96 BeaconState.consolidation_balance_to_consume
///           │  │  └─97 BeaconState.earliest_consolidation_epoch
///           │  └49┬─98 BeaconState.pending_balance_deposits
///           │     └─99 BeaconState.pending_partial_withdrawals
///           └──────100 BeaconState.pending_consolidations
/// ```
pub type CurrentSyncCommitteeIndex = GeneralizedIndexInContainer<U22, U37>;

/// [`NEXT_SYNC_COMMITTEE_INDEX`](https://github.com/ethereum/consensus-specs/blob/d8e74090cf33864f1956a1ee12ba5a94d21a6ac4/specs/altair/light-client/sync-protocol.md#constants)
///
/// See the diagram for [`CurrentSyncCommitteeIndex`].
pub type NextSyncCommitteeIndex = GeneralizedIndexInContainer<U23, U37>;

// This could also be done using `static_assertions::assert_type_eq_all!`.
assert_type_eq!(FinalizedRootIndex, U169);
assert_type_eq!(CurrentSyncCommitteeIndex, U86);
assert_type_eq!(NextSyncCommitteeIndex, U87);
