use ethereum_types::H32;
use hex_literal::hex;
use typenum::{U32, U6};

use crate::phase0::primitives::DomainType;

// TODO(feature/deneb): Remove `DOMAIN_BLOB_SIDECAR` and everything that uses it.
//                      Blob sidecars are no longer signed starting with v1.4.0-beta.5.
pub const DOMAIN_BLOB_SIDECAR: DomainType = H32(hex!("0b000000"));
pub const VERSIONED_HASH_VERSION_KZG: &[u8] = &hex!("01");

// TODO(feature/deneb): Can `BlobSidecarSubnetCount` be a `const`?
//                      It's never used as a type even in `eth2_libp2p`.
pub type BlobSidecarSubnetCount = U6;
pub type BytesPerFieldElement = U32;
