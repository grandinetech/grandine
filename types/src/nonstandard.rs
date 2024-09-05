use core::fmt::Debug;
use std::sync::Arc;

use bit_field::BitField as _;
use bls::Signature;
use derive_more::Constructor;
use enum_iterator::Sequence;
use enum_map::Enum;
use serde::Serialize;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use smallvec::SmallVec;
use ssz::ContiguousList;
use static_assertions::assert_eq_size;
use strum::{AsRefStr, Display, EnumString};

use crate::{
    altair::{
        consts::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
        primitives::ParticipationFlags,
    },
    bellatrix::{containers::PowBlock, primitives::Wei},
    combined::{BeaconState, SignedBeaconBlock},
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::{Blob, KzgCommitment, KzgProof},
    },
    phase0::{
        containers::Attestation,
        primitives::{Gwei, Uint256, UnixSeconds, ValidatorIndex, H256},
    },
    preset::Preset,
};

pub use smallvec::smallvec;

pub const WEI_IN_GWEI: Uint256 = Uint256::from_u64(1_000_000_000);

pub type Publishable = bool;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Sequence,
    AsRefStr,
    Display,
    EnumString,
    DeserializeFromStr,
    SerializeDisplay,
)]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum Phase {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
}

/// Like [`Option`], but with [`None`] greater than any [`Some`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(test, derive(Debug))]
pub enum Toption<T> {
    // The order of variants affects the derived `PartialOrd` and `Ord` impls.
    Some(T),
    None,
}

impl<T> Toption<T> {
    #[must_use]
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Some(value) => Some(value),
            Self::None => None,
        }
    }

    pub fn expect(self, message: &str) -> T {
        self.into_option().expect(message)
    }
}

// TODO(Grandine Team): Several places in the codebase compute next epoch indices in an ad-hoc manner:
//                      - `http_api::standard::validator_subscribe_to_beacon_committee`
//                      - `p2p::BlockVerificationPool::verify_and_process_blocks`
//                      They use existing cached indices but do not cache the ones they compute.
// TODO(Grandine Team): Some HTTP API endpoints still needlessly transition a state to the next epoch:
//                      - `http_api::standard::validator_attester_duties`
//                      - `http_api::standard::validator_proposer_duties`
#[derive(Clone, Copy, Debug, Enum)]
pub enum RelativeEpoch {
    Previous,
    Current,
    Next,
}

impl From<AttestationEpoch> for RelativeEpoch {
    fn from(attestation_epoch: AttestationEpoch) -> Self {
        match attestation_epoch {
            AttestationEpoch::Previous => Self::Previous,
            AttestationEpoch::Current => Self::Current,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AttestationEpoch {
    Previous,
    Current,
}

#[derive(Clone, Copy)]
pub enum SyncCommitteeEpoch {
    Current,
    Next,
}

#[derive(Debug, Enum)]
pub enum SlashingKind {
    Proposer,
    Attester,
}

pub type UsizeVec = SmallVec<[usize; 2]>;

assert_eq_size!(UsizeVec, Vec<usize>);

type U64Vec = SmallVec<[u64; 2 * size_of::<usize>() / size_of::<u64>()]>;

assert_eq_size!(U64Vec, Vec<u64>);

pub type GweiVec = U64Vec;
pub type SlotVec = U64Vec;

pub trait Outcome: Copy {
    fn compare(actual: H256, expected: H256) -> Self;
}

impl Outcome for bool {
    #[inline]
    fn compare(actual: H256, expected: H256) -> Self {
        actual == expected
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum AttestationOutcome {
    Match { root: H256 },
    Mismatch { expected: H256, actual: H256 },
}

impl Outcome for AttestationOutcome {
    #[inline]
    fn compare(actual: H256, expected: H256) -> Self {
        if actual == expected {
            Self::Match { root: expected }
        } else {
            Self::Mismatch { expected, actual }
        }
    }
}

impl AttestationOutcome {
    #[inline]
    #[must_use]
    pub const fn is_match(self) -> bool {
        matches!(self, Self::Match { .. })
    }

    #[inline]
    #[must_use]
    pub const fn should_replace(earlier: Option<Self>, later: Option<Self>) -> bool {
        matches!(
            (earlier, later),
            (Some(Self::Mismatch { .. }), Some(Self::Match { .. })) | (None, Some(_)),
        )
    }
}

#[derive(Clone, Debug)]
pub struct BlobSidecarWithId<P: Preset> {
    pub blob_sidecar: Arc<BlobSidecar<P>>,
    pub blob_id: BlobIdentifier,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct BlockRewards {
    pub total: Gwei,
    pub attestations: Gwei,
    pub sync_aggregate: Gwei,
    pub proposer_slashings: Gwei,
    pub attester_slashings: Gwei,
}

#[derive(Clone, Copy)]
pub struct Participation {
    pub previous: ParticipationFlags,
    pub current: ParticipationFlags,
}

impl Participation {
    #[inline]
    #[must_use]
    pub fn previous_epoch_matching_source(self) -> bool {
        self.previous.get_bit(TIMELY_SOURCE_FLAG_INDEX)
    }

    #[inline]
    #[must_use]
    pub fn previous_epoch_matching_target(self) -> bool {
        self.previous.get_bit(TIMELY_TARGET_FLAG_INDEX)
    }

    #[inline]
    #[must_use]
    pub fn previous_epoch_matching_head(self) -> bool {
        self.previous.get_bit(TIMELY_HEAD_FLAG_INDEX)
    }

    #[inline]
    #[must_use]
    pub fn current_epoch_matching_target(self) -> bool {
        self.current.get_bit(TIMELY_TARGET_FLAG_INDEX)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadStatus {
    Valid,
    Invalid,
    Optimistic,
}

impl PayloadStatus {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }

    #[must_use]
    pub const fn is_invalid(self) -> bool {
        matches!(self, Self::Invalid)
    }

    #[must_use]
    pub const fn is_optimistic(self) -> bool {
        matches!(self, Self::Optimistic)
    }
}

#[derive(Clone, Copy)]
pub struct TimedPowBlock {
    pub pow_block: PowBlock,
    pub timestamp: UnixSeconds,
}

#[derive(Clone, PartialEq, Eq, Debug, Constructor)]
pub struct WithBlobsAndMev<T, P: Preset> {
    pub value: T,
    pub commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
    pub proofs: Option<ContiguousList<KzgProof, P::MaxBlobsPerBlock>>,
    pub blobs: Option<ContiguousList<Blob<P>, P::MaxBlobsPerBlock>>,
    pub mev: Option<Wei>,
}

impl<T, P: Preset> WithBlobsAndMev<T, P> {
    #[must_use]
    pub fn with_default(value: T) -> Self {
        Self::new(value, None, None, None, None)
    }

    #[must_use]
    pub fn with_mev(self, mev: Wei) -> Self {
        let Self {
            value,
            commitments,
            proofs,
            blobs,
            ..
        } = self;

        Self {
            value,
            commitments,
            proofs,
            blobs,
            mev: Some(mev),
        }
    }

    #[must_use]
    pub fn value(self) -> T {
        self.value
    }

    #[must_use]
    pub fn map<U>(self, function: impl FnOnce(T) -> U) -> WithBlobsAndMev<U, P> {
        let Self {
            value,
            commitments,
            proofs,
            blobs,
            mev,
        } = self;

        let value = function(value);

        WithBlobsAndMev {
            value,
            commitments,
            proofs,
            blobs,
            mev,
        }
    }
}

pub struct WithStatus<T> {
    pub value: T,
    pub optimistic: bool,
    pub finalized: bool,
}

/// [`WithStatus`] should not have a constructor that accepts values for all of its fields.
/// Anonymous arguments can lead to bugs when multiple of them have the same type.
/// Mixing up the two [`bool`] fields in [`WithStatus`] would be particularly dangerous.
/// ```compile_fail
/// # use types::nonstandard::WithStatus;
/// #
/// // Which is which? One is safe, one is dangerous.
/// WithStatus::new((), false, true);
/// WithStatus::new((), true, false);
/// ```
impl<T> WithStatus<T> {
    #[must_use]
    pub const fn valid(value: T, finalized: bool) -> Self {
        Self {
            value,
            optimistic: false,
            finalized,
        }
    }

    #[must_use]
    pub const fn valid_and_finalized(value: T) -> Self {
        Self {
            value,
            optimistic: false,
            finalized: true,
        }
    }

    #[must_use]
    pub const fn valid_and_unfinalized(value: T) -> Self {
        Self {
            value,
            optimistic: false,
            finalized: false,
        }
    }

    #[must_use]
    pub fn value(self) -> T {
        self.value
    }

    #[must_use]
    pub fn map<U>(self, function: impl FnOnce(T) -> U) -> WithStatus<U> {
        let Self {
            value,
            optimistic,
            finalized,
        } = self;

        WithStatus {
            value: function(value),
            optimistic,
            finalized,
        }
    }
}

impl<T: Clone> WithStatus<&T> {
    #[must_use]
    pub fn cloned(self) -> WithStatus<T> {
        let Self {
            value,
            optimistic,
            finalized,
        } = self;

        WithStatus {
            value: value.clone(),
            optimistic,
            finalized,
        }
    }
}

/// Outcome of extended validation in [gossipsub v1.1](https://github.com/libp2p/specs/blob/cfcf0230b2f5f11ed6dd060f97305faa973abed2/pubsub/gossipsub/gossipsub-v1.1.md#extended-validators).
///
/// We use [`Err`] to represent the `REJECT` outcome. This makes propagating errors easier.
/// This may result in validation failures being conflated with other errors, which could cause
/// messages to be incorrectly `REJECT`ed. We have not run into any issues due to this yet.
#[derive(PartialEq, Eq, Debug)]
pub enum ValidationOutcome {
    Accept,
    Ignore(Publishable),
}

#[derive(Clone)]
pub struct OwnAttestation<P: Preset> {
    pub validator_index: ValidatorIndex,
    pub attestation: Attestation<P>,
    pub signature: Signature,
}

#[derive(Debug, Serialize)]
pub struct SystemStats {
    pub core_count: usize,
    pub grandine_used_memory: u64,
    pub grandine_total_cpu_percentage: f32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub system_cpu_percentage: f32,
    pub system_used_memory: u64,
    pub system_total_memory: u64,
}

#[derive(Clone)]
pub struct FinalizedCheckpoint<P: Preset> {
    pub block: Arc<SignedBeaconBlock<P>>,
    pub state: Arc<BeaconState<P>>,
}

#[derive(Clone, Copy)]
pub enum Origin {
    CheckpointSync,
    Genesis,
}

impl Origin {
    #[must_use]
    pub const fn is_checkpoint_sync(self) -> bool {
        matches!(self, Self::CheckpointSync)
    }
}

#[derive(Clone, Constructor)]
pub struct WithOrigin<T> {
    pub value: T,
    pub origin: Origin,
}

impl<T: Clone> WithOrigin<T> {
    #[must_use]
    pub fn new_from_genesis(value: T) -> Self {
        Self::new(value, Origin::Genesis)
    }

    #[must_use]
    pub fn new_from_checkpoint(value: T) -> Self {
        Self::new(value, Origin::CheckpointSync)
    }

    #[must_use]
    pub fn checkpoint_synced(&self) -> Option<T> {
        match self.origin {
            Origin::CheckpointSync => Some(self.value.clone()),
            Origin::Genesis => None,
        }
    }

    #[must_use]
    pub fn genesis(&self) -> Option<T> {
        match self.origin {
            Origin::CheckpointSync => None,
            Origin::Genesis => Some(self.value.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools as _;
    use strum::ParseError;
    use test_case::test_case;

    use super::*;

    #[test]
    fn phase_order() {
        let expected_order = [
            Phase::Phase0,
            Phase::Altair,
            Phase::Bellatrix,
            Phase::Capella,
            Phase::Deneb,
        ];

        assert_eq!(expected_order.len(), Phase::CARDINALITY);

        assert!(expected_order
            .into_iter()
            .tuple_windows()
            .all(|(earlier, later)| earlier < later));
    }

    #[test_case(
        "phase0" => Ok(Phase::Phase0);
        "lowercase like in consensus-spec-tests and Eth Beacon Node API"
    )]
    #[test_case(
        "PHASE0" => Ok(Phase::Phase0);
        "uppercase like in Vouch or Web3Signer"
    )]
    fn phase_from_str(string: &str) -> Result<Phase, ParseError> {
        string.parse()
    }

    #[test_case(Phase::Phase0 => "phase0")]
    fn phase_display(phase: Phase) -> String {
        phase.to_string()
    }

    #[test]
    fn toption_comparisons() {
        assert_eq!(Toption::<usize>::None, Toption::<usize>::None);

        assert!(Toption::None > Toption::Some(usize::MIN));
        assert!(Toption::None > Toption::Some(usize::MAX));

        assert!(Toption::Some(usize::MIN) < Toption::None);
        assert!(Toption::Some(usize::MAX) < Toption::None);

        assert!(Toption::Some(usize::MIN) < Toption::Some(usize::MAX));
    }
}
