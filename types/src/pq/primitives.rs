use ssz::{ByteList, ContiguousVector, ProgressiveList};
use typenum::U32;

use crate::{
    phase0::primitives::{H256, ValidatorIndex},
    preset::{Preset, PtcWindowLength},
};

/// A leaf of the tree under a validator's VRF root, followed by the leaf's Merkle branch
/// (`VRF_TREE_DEPTH + 1` = 32 entries).
pub type VrfProof = ContiguousVector<H256, U32>;

/// A STARK proof of the XMSS signatures of attestations.
pub type AttestationProof<P> = ByteList<<P as Preset>::MaxStarkProofSize>;

/// The aggregators of a beacon committee.
pub type AggregationCommittee = ProgressiveList<ValidatorIndex>;

/// The aggregation committee of each beacon committee of a slot, in committee order.
pub type AggregationCommittees = ProgressiveList<AggregationCommittee>;

/// The aggregation committees of the previous, current, and lookahead epochs.
///
/// Same length as the PTC window: `(MIN_SEED_LOOKAHEAD + 2) * SLOTS_PER_EPOCH`.
pub type AggregationCommitteeWindow<P> =
    ContiguousVector<AggregationCommittees, PtcWindowLength<P>>;
