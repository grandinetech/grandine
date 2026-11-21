// Misc
pub const AGGREGATORS_PER_COMMITTEE: u64 = 1 << 2;

// XMSS
pub const XMSS_RESERVED_LEAVES: u64 = 1 << 15;
pub const XMSS_ATTESTATION_LEAVES: u64 = 1 << 29;
pub const XMSS_BUILDER_BID_LEAVES: u64 = 1 << 30;
pub const XMSS_LEAVES_PER_SLOT: u64 = 1 << 3;

// VRF
pub const VRF_TREE_DEPTH: u64 = 31;

// XMSS leaf offsets
pub const LEAF_OFFSET_BEACON_PROPOSER: u64 = 0;
pub const LEAF_OFFSET_AGGREGATE_AND_PROOF: u64 = 1;
pub const LEAF_OFFSET_PTC_ATTESTER: u64 = 2;
pub const LEAF_OFFSET_PROPOSER_PREFERENCES: u64 = 3;
pub const LEAF_OFFSET_EXECUTION_PAYLOAD_ENVELOPE: u64 = 4;

// Deposits
pub const XMSS_DEPOSIT_PREFIX: [u8; 16] = [0; 16];

// Legacy domains
pub const LEGACY_XMSS_PUBKEY_DOMAIN: u8 = 0x00;
pub const LEGACY_VRF_ROOT_DOMAIN: u8 = 0x01;

// Execution-layer triggered requests
pub const VALIDATOR_PREREGISTRATION_REQUEST_TYPE: u8 = 0x07;
pub const BUILDER_PREREGISTRATION_REQUEST_TYPE: u8 = 0x08;
pub const VOLUNTARY_EXIT_REQUEST_TYPE: u8 = 0x09;
