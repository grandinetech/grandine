use core::num::NonZeroUsize;

use typenum::{
    Prod, Sum, U0, U1, U2, U4, U46, U64, U357, U367, U735, U808, U897, U898, U2048, assert_type_eq,
};

use crate::{
    gloas::primitives::{BuilderIndex, PayloadStatus},
    phase0::primitives::{DomainType, H32},
    unphased::consts::{ConcatGeneralizedIndices, GeneralizedIndexInContainer},
};
use hex_literal::hex;
use nonzero_ext::nonzero;

/// Generalized indices in gloas `ProgressiveContainer`s (EIP-7495 + EIP-7916).
///
/// The root of a `ProgressiveContainer` is `hash(progressive_root, active_fields)`,
/// which places the progressive Merkle tree at generalized index 2. The tree itself
/// is a spine of binary subtrees with capacities 1, 4, 16, 64, …:
/// `hash(merkleize(chunks[..k], k), merkleize_progressive(chunks[k..], 4 * k))`.
///
/// Fields of a progressive container therefore land at:
///
/// ```text
/// field 0:        gindex 4
/// fields 1..=4:   gindexes 40..=43   (10 * 4 + i - 1)
/// fields 5..=20:  gindexes 352..=367 (22 * 16 + i - 5)
/// fields 21..=84: gindexes 2944..=3007 (46 * 64 + i - 21)
/// ```
///
/// `signed_execution_payload_bid` is field 10 of the gloas `BeaconBlockBody`
/// (a `ProgressiveContainer` with 13 active fields): 352 + (10 - 5) = 357.
type SignedExecutionPayloadBidGindex = U357;

/// [`EXECUTION_BLOCK_HASH_GINDEX_GLOAS`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/light-client/sync-protocol.md#constants)
///
/// `get_generalized_index(BeaconBlockBody, 'signed_execution_payload_bid', 'message', 'parent_block_hash')`
///
/// `SignedExecutionPayloadBid` is a plain container (`message` at gindex 2), while
/// `ExecutionPayloadBid` is a `ProgressiveContainer` with 12 active fields
/// (`parent_block_hash` is field 0, gindex 4): concat(357, 2, 4) = 2856.
pub type ExecutionBlockHashGindexGloas = ConcatGeneralizedIndices<
    ConcatGeneralizedIndices<SignedExecutionPayloadBidGindex, GeneralizedIndexInContainer<U0, U2>>,
    U4,
>;

assert_type_eq!(ExecutionBlockHashGindexGloas, Sum<U2048, U808>); // 2856

/// [`FINALIZED_ROOT_GINDEX_GLOAS`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/light-client/sync-protocol.md#constants)
///
/// `get_generalized_index(BeaconState, 'finalized_checkpoint', 'root')`
///
/// `finalized_checkpoint` is field 20 of the gloas `BeaconState` (a
/// `ProgressiveContainer` with 46 active fields): 352 + (20 - 5) = 367.
/// `root` is field 1 of the plain `Checkpoint` container: concat(367, 3) = 735.
pub type FinalizedRootGindexGloas =
    ConcatGeneralizedIndices<U367, GeneralizedIndexInContainer<U1, U2>>;

assert_type_eq!(FinalizedRootGindexGloas, U735);

/// [`CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/light-client/sync-protocol.md#constants)
///
/// `get_generalized_index(BeaconState, 'current_sync_committee')`
///
/// `current_sync_committee` is field 22 of the gloas `BeaconState`:
/// 46 * 64 + (22 - 21) = 2945.
pub type CurrentSyncCommitteeGindexGloas = Sum<Prod<U46, U64>, U1>;

assert_type_eq!(CurrentSyncCommitteeGindexGloas, Sum<U2048, U897>); // 2945

/// [`NEXT_SYNC_COMMITTEE_GINDEX_GLOAS`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.12/specs/gloas/light-client/sync-protocol.md#constants)
///
/// `get_generalized_index(BeaconState, 'next_sync_committee')`
///
/// `next_sync_committee` is field 23 of the gloas `BeaconState`:
/// 46 * 64 + (23 - 21) = 2946.
pub type NextSyncCommitteeGindexGloas = Sum<Prod<U46, U64>, U2>;

assert_type_eq!(NextSyncCommitteeGindexGloas, Sum<U2048, U898>); // 2946

pub const INTERVALS_PER_SLOT_GLOAS: NonZeroUsize = nonzero!(4_usize);

// Domain types
pub const DOMAIN_BEACON_BUILDER: DomainType = H32(hex!("0B000000"));
pub const DOMAIN_PTC_ATTESTER: DomainType = H32(hex!("0C000000"));
pub const DOMAIN_PROPOSER_PREFERENCES: DomainType = H32(hex!("0D000000"));
pub const DOMAIN_BUILDER_DEPOSIT: DomainType = H32(hex!("0E000000"));

// Payload status
pub const PAYLOAD_STATUS_EMPTY: PayloadStatus = 0u8;
pub const PAYLOAD_STATUS_FULL: PayloadStatus = 1u8;
pub const PAYLOAD_STATUS_PENDING: PayloadStatus = 2u8;

// Misc
pub const BUILDER_INDEX_SELF_BUILD: BuilderIndex = BuilderIndex::MAX;
pub const BUILDER_PAYMENT_THRESHOLD_NUMERATOR: u64 = 6;
pub const BUILDER_PAYMENT_THRESHOLD_DENOMINATOR: u64 = 10;

// Flags
//
// Bitwise flag which indicates that a `ValidatorIndex` should be treated as a `BuilderIndex`
pub const BUILDER_INDEX_FLAG: u64 = 0x0100_0000_0000;
pub const BUILDER_WITHDRAWAL_PREFIX: &[u8] = &hex!("B0");

// Versioning
pub const PAYLOAD_BUILDER_VERSION: u8 = 0;
