use hex_literal::hex;
use types::{
    bellatrix::primitives::Gas,
    phase0::primitives::{DomainType, H32},
};

pub const BUILDER_PROPOSAL_DELAY_TOLERANCE: u64 = 1;

/// [`DOMAIN_APPLICATION_BUILDER`] from `builder-specs`.
///
/// Also see [`DOMAIN_APPLICATION_MASK`] in `consensus-specs`.
///
/// [`DOMAIN_APPLICATION_BUILDER`]: https://github.com/ethereum/builder-specs/blob/58e2c66e6fecccbe14c5ddf718ebc68a3c6a03eb/specs/bellatrix/builder.md#domain-types
/// [`DOMAIN_APPLICATION_MASK`]:    https://github.com/ethereum/consensus-specs/blob/0b76c8367ed19014d104e3fbd4718e73f459a748/specs/phase0/beacon-chain.md#domain-types
pub const DOMAIN_APPLICATION_BUILDER: DomainType = H32(hex!("00000001"));

pub const EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION: u64 = 1;

// From <https://github.com/ethereum/builder-specs/issues/17>:
//
// > 30M is the value "we" currently feel comfortable running as a balance between how
// > big blocks are and how expensive they are for the network to validate. When I say "we",
// > I mean the collective community of client devs, miners and others in the community --
// > rough consensus across many participating entities.
//
// > For this reason, I think it is currently a sensible default if the validator operator
// > does not provide another option.
pub const PREFERRED_EXECUTION_GAS_LIMIT: Gas = 30_000_000;
