use core::num::{NonZeroU64, NonZeroUsize};

use hex_literal::hex;
use nonzero_ext::nonzero;
use typenum::{U16, U32, U4, U64};

use crate::phase0::primitives::{DomainType, Epoch, Slot, H32};

pub const ATTESTATION_PROPAGATION_SLOT_RANGE: u64 = 32;
pub const BASE_REWARDS_PER_EPOCH: NonZeroU64 = nonzero!(4_u64);
pub const BLS_WITHDRAWAL_PREFIX: &[u8] = &hex!("00");
pub const DOMAIN_AGGREGATE_AND_PROOF: DomainType = H32(hex!("06000000"));
pub const DOMAIN_BEACON_ATTESTER: DomainType = H32(hex!("01000000"));
pub const DOMAIN_BEACON_PROPOSER: DomainType = H32(hex!("00000000"));
pub const DOMAIN_DEPOSIT: DomainType = H32(hex!("03000000"));
pub const DOMAIN_RANDAO: DomainType = H32(hex!("02000000"));
pub const DOMAIN_SELECTION_PROOF: DomainType = H32(hex!("05000000"));
pub const DOMAIN_VOLUNTARY_EXIT: DomainType = H32(hex!("04000000"));
pub const ETH1_ADDRESS_WITHDRAWAL_PREFIX: &[u8] = &hex!("01");
pub const FAR_FUTURE_EPOCH: Epoch = Epoch::MAX;
pub const GENESIS_EPOCH: Epoch = 0;
pub const GENESIS_SLOT: Slot = 0;
pub const INTERVALS_PER_SLOT: NonZeroUsize = nonzero!(3_usize);

pub type AttestationSubnetCount = U64;
pub type DepositContractTreeDepth = U32;
pub type JustificationBitsLength = U4;
pub type TargetAggregatorsPerCommittee = U16;
