use hex_literal::hex;
use typenum::{U9, U11, U25, assert_type_eq};

use crate::{
    phase0::primitives::{DomainType, H32},
    unphased::consts::GeneralizedIndexInContainer,
};

pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: DomainType = H32(hex!("0a000000"));

/// [`EXECUTION_PAYLOAD_INDEX`](https://github.com/ethereum/consensus-specs/blob/0f2d25d919bf19d3421df791533d553af679a54f/specs/capella/light-client/sync-protocol.md#constants)
///
/// ```text
/// 1┬─2┬─4┬─8┬16 BeaconBlockBody.randao_reveal
///  │  │  │  └17 BeaconBlockBody.eth1_data
///  │  │  └─9┬18 BeaconBlockBody.graffiti
///  │  │     └19 BeaconBlockBody.proposer_slashings
///  │  └─5┬10┬20 BeaconBlockBody.attester_slashings
///  │     │  └21 BeaconBlockBody.attestations
///  │     └11┬22 BeaconBlockBody.deposits
///  │        └23 BeaconBlockBody.voluntary_exits
///  └─3──6┬12┬24 BeaconBlockBody.sync_aggregate
///        │  └25 BeaconBlockBody.execution_payload
///        └13─26 BeaconBlockBody.bls_to_execution_changes
/// ```
pub type ExecutionPayloadIndex = GeneralizedIndexInContainer<U9, U11>;

// This could also be done using `static_assertions::assert_type_eq_all!`.
assert_type_eq!(ExecutionPayloadIndex, U25);
