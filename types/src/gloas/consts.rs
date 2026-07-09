use core::num::NonZeroUsize;

use typenum::{U0, U2, U10, U12, U13, U832, assert_type_eq};

use crate::{
    gloas::primitives::{BuilderIndex, PayloadStatus},
    phase0::primitives::{DomainType, H32},
    unphased::consts::{ConcatGeneralizedIndices, GeneralizedIndexInContainer},
};
use hex_literal::hex;
use nonzero_ext::nonzero;

/// [`EXECUTION_BLOCK_HASH_GINDEX_GLOAS`](https://github.com/ethereum/consensus-specs/blob/279b0ebe911ea02b626d632e372f78b59a53ba61/specs/gloas/light-client/sync-protocol.md#new-constants)
///
/// `get_generalized_index(BeaconBlockBody, 'signed_execution_payload_bid', 'message', 'parent_block_hash')`
///
/// ```text
///  1┬─2┬─4┬──8┬─16 BeaconBlockBody.randao_reveal
///   │  │  │   └─17 BeaconBlockBody.eth1_data
///   │  │  └──9┬─18 BeaconBlockBody.graffiti
///   │  │      └─19 BeaconBlockBody.proposer_slashings
///   │  └─5┬─10┬─20 BeaconBlockBody.attester_slashings
///   │     │   └─21 BeaconBlockBody.attestations
///   │     └─11┬─22 BeaconBlockBody.deposits
///   │         └─23 BeaconBlockBody.voluntary_exits
///   └─3┬─6┬─12┬─24 BeaconBlockBody.sync_aggregate
///      │  │   └─25 BeaconBlockBody.bls_to_execution_changes
///      │  └─13┬─26 BeaconBlockBody.signed_execution_payload_bid (see below)
///      │      └─27 BeaconBlockBody.payload_attestations
///      └─7──14┬─28 BeaconBlockBody.parent_execution_requests
///
///  26 SignedExecutionPayloadBid┬─52 .message (= ExecutionPayloadBid, see below)
///                              └─53 .signature
///
///  52 ExecutionPayloadBid┬─104┬─208┬─416┬─832 ExecutionPayloadBid.parent_block_hash
///                        │   │   │   └─833 ExecutionPayloadBid.parent_block_root
///                        │   │   └─417┬─834 ExecutionPayloadBid.block_hash
///                        │   │       └─835 ExecutionPayloadBid.prev_randao
///                        │   └─209┬─418┬─836 ExecutionPayloadBid.fee_recipient
///                        │       │   └─837 ExecutionPayloadBid.gas_limit
///                        │       └─419┬─838 ExecutionPayloadBid.builder_index
///                        │           └─839 ExecutionPayloadBid.slot
///                        └─105┬─210┬─420┬─840 ExecutionPayloadBid.value
///                             │   │   └─841 ExecutionPayloadBid.execution_payment
///                             │   └─421┬─842 ExecutionPayloadBid.blob_kzg_commitments
///                             │       └─843 ExecutionPayloadBid.execution_requests_root
/// ```
pub type ExecutionBlockHashGindexGloas = ConcatGeneralizedIndices<
    ConcatGeneralizedIndices<
        GeneralizedIndexInContainer<U10, U13>,
        GeneralizedIndexInContainer<U0, U2>,
    >,
    GeneralizedIndexInContainer<U0, U12>,
>;

assert_type_eq!(ExecutionBlockHashGindexGloas, U832);

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
