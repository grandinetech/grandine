use core::time::Duration;

use hex_literal::hex;
use typenum::{U64, U2048, U4096};
use types::phase0::primitives::{DomainType, H32};

pub const BUILDER_PROPOSAL_DELAY_TOLERANCE: u64 = 1;

pub const BUILDER_BID_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(BUILDER_PROPOSAL_DELAY_TOLERANCE);

/// [`DOMAIN_APPLICATION_BUILDER`] from `builder-specs`.
///
/// Also see [`DOMAIN_APPLICATION_MASK`] in `consensus-specs`.
///
/// [`DOMAIN_APPLICATION_BUILDER`]: https://github.com/ethereum/builder-specs/blob/58e2c66e6fecccbe14c5ddf718ebc68a3c6a03eb/specs/bellatrix/builder.md#domain-types
/// [`DOMAIN_APPLICATION_MASK`]:    https://github.com/ethereum/consensus-specs/blob/0b76c8367ed19014d104e3fbd4718e73f459a748/specs/phase0/beacon-chain.md#domain-types
pub const DOMAIN_APPLICATION_BUILDER: DomainType = H32(hex!("00000001"));

pub const EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION: u64 = 1;

// SSZ limits for builder entry fields in builder config
pub type MaxBuilderEntries = U64;
pub type MaxBuilderAuthDataSize = U4096;
pub type MaxBuilderPubkeys = U64;
pub type MaxBuilderUrlSize = U2048;

// MAX_BUILDER_ENTRIES * (MIN_SEED_LOOKAHEAD + 1) * SLOTS_PER_EPOCH
pub type MaxBuilderPreferencesEntries = U4096;
