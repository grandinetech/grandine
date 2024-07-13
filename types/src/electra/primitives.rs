use ssz::ContiguousVector;

use crate::{phase0::primitives::H256, preset::Preset};

pub type ElectraBlobCommitmentInclusionProof<P> =
    ContiguousVector<H256, <P as Preset>::ElectraKzgCommitmentInclusionProofDepth>;
