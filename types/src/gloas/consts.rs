use core::num::NonZeroUsize;

use crate::{
    gloas::primitives::PayloadStatus,
    phase0::primitives::{DomainType, H32},
};
use hex_literal::hex;
use nonzero_ext::nonzero;

pub const INTERVALS_PER_SLOT_GLOAS: NonZeroUsize = nonzero!(4_usize);

// Domain types
pub const DOMAIN_BEACON_BUILDER: DomainType = H32(hex!("1B000000"));
pub const DOMAIN_PTC_ATTESTER: DomainType = H32(hex!("0C000000"));

// Payload status
pub const PAYLOAD_STATUS_PENDING: PayloadStatus = 0u8;
pub const PAYLOAD_STATUS_EMPTY: PayloadStatus = 1u8;
pub const PAYLOAD_STATUS_FULL: PayloadStatus = 2u8;

// Misc
pub const BUILDER_PAYMENT_THRESHOLD_NUMERATOR: u64 = 6;
pub const BUILDER_PAYMENT_THRESHOLD_DENOMINATOR: u64 = 10;

pub const BUILDER_WITHDRAWAL_PREFIX: &[u8] = &hex!("03");
