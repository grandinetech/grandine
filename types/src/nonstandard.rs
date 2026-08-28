use core::{convert::Infallible, fmt::Debug, iter};
use std::sync::Arc;
#[cfg(target_os = "zkvm")]
use std::{collections::HashMap, slice::Iter as VectorIter, vec::Vec as Vector};

use anyhow::{Result, ensure};
use bit_field::BitField as _;
use bls::{PublicKeyBytes, Signature};
use derivative::Derivative;
use derive_more::{Constructor, From};
use enum_iterator::Sequence;
use enum_map::Enum;
#[cfg(not(target_os = "zkvm"))]
use im::{HashMap, Vector, vector::Iter as VectorIter};
use serde::Serialize;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use smallvec::SmallVec;
use ssz::{
    ContiguousList, H256, IndexError, ReadError, Size, SszList, SszRead, SszSize, SszWrite,
    WriteError, read_list, write_list,
};
use static_assertions::assert_eq_size;
use std_ext::CopyExt as _;
use strum::{AsRefStr, Display, EnumString};
use try_from_iterator::TryFromIterator;

use crate::{
    altair::{
        consts::{TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX},
        primitives::ParticipationFlags,
    },
    bellatrix::{containers::PowBlock, primitives::Wei},
    combined::{Attestation, BeaconState, DataColumnSidecar, ExecutionRequests, SignedBeaconBlock},
    config::Config,
    deneb::{
        containers::{BlobIdentifier, BlobSidecar},
        primitives::{Blob, KzgCommitment, KzgProof},
    },
    fulu::containers::DataColumnIdentifier,
    phase0::{
        containers::{SignedBeaconBlockHeader, Validator},
        primitives::{Epoch, Gwei, Slot, Uint256, UnixSeconds, ValidatorIndex},
    },
    preset::Preset,
    traits::{BlockBodyWithBlobKzgCommitments, SignedBeaconBlock as _},
};

pub use smallvec::smallvec;

pub const WEI_IN_GWEI: Uint256 = Uint256::from_u64(1_000_000_000);

/// Defaults for the builder circuit breaker thresholds.
///
/// Defined here because they are shared by the pre-Gloas checks in `builder_api`, which count
/// missing blocks, and the Gloas circuit breaker in `fork_choice_store`, which counts withheld
/// payloads.
pub const DEFAULT_BUILDER_MAX_SKIPPED_SLOTS: u64 = 3;
pub const DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH: u64 = 8;

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
    Electra,
    Fulu,
    Gloas,
}

impl Phase {
    // Modify condition if we want to change the peerdas activation behaviour
    #[must_use]
    pub fn is_peerdas_activated(self) -> bool {
        self >= Self::Fulu
    }
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

pub type U64Vec = SmallVec<[u64; 2 * size_of::<usize>() / size_of::<u64>()]>;

// It appears that `SmallVec` does not use `union` feature on `riscv32` arch,
// so `SmallVecData` is `enum` type instead of `union`, and thus have a different size.
// `mips` arch exhibits similar `SmallVec` size variations
#[cfg(all(not(target_arch = "riscv32"), not(target_arch = "mips")))]
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

impl<P: Preset> From<Arc<BlobSidecar<P>>> for BlobSidecarWithId<P> {
    fn from(blob_sidecar: Arc<BlobSidecar<P>>) -> Self {
        let blob_id = blob_sidecar.as_ref().into();

        Self {
            blob_sidecar,
            blob_id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DataColumnSidecarWithId<P: Preset> {
    pub data_column_sidecar: Arc<DataColumnSidecar<P>>,
    pub data_column_id: DataColumnIdentifier,
}

impl<P: Preset> From<Arc<DataColumnSidecar<P>>> for DataColumnSidecarWithId<P> {
    fn from(data_column_sidecar: Arc<DataColumnSidecar<P>>) -> Self {
        let data_column_id = data_column_sidecar.as_ref().into();

        Self {
            data_column_sidecar,
            data_column_id,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct BlockRewards {
    pub total: Gwei,
    pub attestations: Gwei,
    pub sync_aggregate: Gwei,
    pub proposer_slashings: Gwei,
    pub attester_slashings: Gwei,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum CustodyMode {
    #[default]
    Minimal,
    Semi,
    Super,
}

#[derive(Clone, Copy, Debug)]
pub enum StorageMode {
    Prune,
    Standard {
        custom_data_availability_window: Option<u64>,
    },
    Archive,
}

impl Default for StorageMode {
    #[inline]
    fn default() -> Self {
        Self::Standard {
            custom_data_availability_window: None,
        }
    }
}

impl StorageMode {
    #[must_use]
    pub const fn is_prune(self) -> bool {
        matches!(self, Self::Prune)
    }

    #[must_use]
    pub const fn is_archive(self) -> bool {
        matches!(self, Self::Archive)
    }

    pub fn min_epochs_for_blob_sidecars_requests(self, config: &Config) -> u64 {
        match self {
            Self::Standard {
                custom_data_availability_window,
            } => custom_data_availability_window
                .unwrap_or(config.min_epochs_for_blob_sidecars_requests),
            Self::Archive | Self::Prune => config.min_epochs_for_blob_sidecars_requests,
        }
    }

    pub fn min_epochs_for_data_column_sidecars_requests(self, config: &Config) -> u64 {
        match self {
            Self::Standard {
                custom_data_availability_window,
            } => custom_data_availability_window
                .unwrap_or(config.min_epochs_for_data_column_sidecars_requests),
            Self::Archive | Self::Prune => config.min_epochs_for_data_column_sidecars_requests,
        }
    }
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

#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(bound = "", untagged)]
pub enum KzgProofs<P: Preset> {
    Deneb(ContiguousList<KzgProof, P::MaxBlobCommitmentsPerBlock>),
    Fulu(ContiguousList<KzgProof, P::MaxCellProofsPerBlock>),
}

impl<P: Preset> IntoIterator for KzgProofs<P> {
    type Item = KzgProof;
    type IntoIter = <Vec<KzgProof> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Deneb(list) => list.into_iter(),
            Self::Fulu(list) => list.into_iter(),
        }
    }
}

impl<P: Preset> AsRef<[KzgProof]> for KzgProofs<P> {
    fn as_ref(&self) -> &[KzgProof] {
        match self {
            Self::Deneb(list) => list.as_ref(),
            Self::Fulu(list) => list.as_ref(),
        }
    }
}

impl<P: Preset> SszSize for KzgProofs<P> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<P: Preset> SszWrite for KzgProofs<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Deneb(list) => list.write_variable(bytes),
            Self::Fulu(list) => list.write_variable(bytes),
        }
    }
}

impl<P: Preset> KzgProofs<P> {
    #[must_use]
    pub fn empty_deneb() -> Self {
        Self::Deneb(ContiguousList::default())
    }

    #[must_use]
    pub fn empty_fulu() -> Self {
        Self::Fulu(ContiguousList::default())
    }
}

#[derive(Clone, Debug, From)]
pub enum BlockOrDataColumnSidecar<P: Preset> {
    Block(Arc<SignedBeaconBlock<P>>),
    Sidecar(Arc<DataColumnSidecar<P>>),
    BlockRoot((H256, Slot)),
}

impl<P: Preset> BlockOrDataColumnSidecar<P> {
    #[must_use]
    pub fn slot(&self) -> Slot {
        match self {
            Self::Block(block) => block.message().slot(),
            Self::Sidecar(sidecar) => sidecar.slot(),
            Self::BlockRoot((_, slot)) => *slot,
        }
    }

    #[must_use]
    pub fn block_root(&self) -> H256 {
        match self {
            Self::Block(block) => block.message().hash_tree_root(),
            Self::Sidecar(sidecar) => sidecar.beacon_block_root(),
            Self::BlockRoot((block_root, _)) => *block_root,
        }
    }

    #[must_use]
    pub fn signed_block_header(&self) -> Option<SignedBeaconBlockHeader> {
        match self {
            Self::Block(block) => Some(block.to_header()),
            Self::Sidecar(sidecar) => sidecar
                .pre_gloas()
                .map(|sidecar| sidecar.signed_block_header),
            Self::BlockRoot(_) => None,
        }
    }

    pub fn kzg_commitments(&self) -> Option<&dyn SszList<KzgCommitment>> {
        match self {
            Self::Block(block) => block
                .message()
                .body()
                .with_blob_kzg_commitments()
                .map(BlockBodyWithBlobKzgCommitments::blob_kzg_commitments),
            Self::Sidecar(sidecar) => sidecar
                .kzg_commitments()
                .map(|kzg_commitments| -> &dyn SszList<KzgCommitment> { kzg_commitments }),
            Self::BlockRoot(_) => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Constructor)]
pub struct WithBlobsAndMev<T, P: Preset> {
    pub value: T,
    pub commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
    pub proofs: Option<KzgProofs<P>>,
    pub blobs: Option<ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>>,
    pub mev: Option<Wei>,
    pub execution_requests: Option<ExecutionRequests<P>>,
}

impl<T, P: Preset> WithBlobsAndMev<T, P> {
    #[must_use]
    pub const fn with_default(value: T) -> Self {
        Self::new(value, None, None, None, None, None)
    }

    #[must_use]
    pub fn with_mev(self, mev: Wei) -> Self {
        let Self {
            value,
            commitments,
            proofs,
            blobs,
            execution_requests,
            ..
        } = self;

        Self {
            value,
            commitments,
            proofs,
            blobs,
            mev: Some(mev),
            execution_requests,
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
            execution_requests,
        } = self;

        let value = function(value);

        WithBlobsAndMev {
            value,
            commitments,
            proofs,
            blobs,
            mev,
            execution_requests,
        }
    }
}

pub struct WithStatus<T> {
    pub value: T,
    pub status: PayloadStatus,
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
    pub const fn is_valid(&self) -> bool {
        self.status.is_valid()
    }

    #[must_use]
    pub const fn valid(value: T, finalized: bool) -> Self {
        Self {
            value,
            status: PayloadStatus::Valid,
            finalized,
        }
    }

    #[must_use]
    pub const fn valid_and_finalized(value: T) -> Self {
        Self {
            value,
            status: PayloadStatus::Valid,
            finalized: true,
        }
    }

    #[must_use]
    pub const fn valid_and_unfinalized(value: T) -> Self {
        Self {
            value,
            status: PayloadStatus::Valid,
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
            status,
            finalized,
        } = self;

        WithStatus {
            value: function(value),
            status,
            finalized,
        }
    }
}

impl<T: Clone> WithStatus<&T> {
    #[must_use]
    pub fn cloned(self) -> WithStatus<T> {
        let Self {
            value,
            status,
            finalized,
        } = self;

        WithStatus {
            value: value.clone(),
            status,
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

#[derive(PartialEq, Eq, Debug)]
pub enum ValidationOutcomeWithReason {
    Accept,
    Ignore(&'static str),
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
    pub const fn new_from_genesis(value: T) -> Self {
        Self::new(value, Origin::Genesis)
    }

    #[must_use]
    pub const fn new_from_checkpoint(value: T) -> Self {
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

#[cfg(target_os = "zkvm")]
trait VectorExt<T> {
    fn push_back(&mut self, value: T);
    fn slice(&mut self, range: core::ops::Range<usize>) -> Self;
}

#[cfg(target_os = "zkvm")]
impl<T> VectorExt<T> for Vec<T> {
    fn push_back(&mut self, value: T) {
        self.push(value);
    }

    fn slice(&mut self, range: core::ops::Range<usize>) -> Self {
        // Mirror `im::Vector::slice`: remove `range` from `self` and return it as a new vector,
        // leaving the elements outside the range in `self`.
        self.drain(range).collect()
    }
}

/// Validator public keys together with a public key -> index map.
#[derive(Clone, Debug, Default, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct PubkeyList {
    keys: Vector<PublicKeyBytes>,

    #[derivative(PartialEq = "ignore")]
    index_map: HashMap<PublicKeyBytes, ValidatorIndex>,
}

impl PubkeyList {
    #[must_use]
    pub fn index_of(&self, pubkey: &PublicKeyBytes) -> Option<ValidatorIndex> {
        let index = self.index_map.get(pubkey).copied()?;
        let in_bounds = usize::try_from(index).is_ok_and(|index| index < self.keys.len());
        in_bounds.then_some(index)
    }

    #[must_use]
    pub fn contains(&self, pubkey: &PublicKeyBytes) -> bool {
        self.index_of(pubkey).is_some()
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<&PublicKeyBytes> {
        self.keys.get(index)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn iter(&self) -> VectorIter<'_, PublicKeyBytes> {
        self.keys.iter()
    }

    pub fn push(&mut self, pubkey: PublicKeyBytes) {
        let index = ValidatorIndex::try_from(self.keys.len())
            .expect("validator count never exceeds ValidatorIndex range");

        self.keys.push_back(pubkey);
        self.index_map.insert(pubkey, index);
    }

    fn prefix(&self, length: usize) -> Self {
        let mut keys = self.keys.clone();
        let keys = keys.slice(0..length);

        Self {
            keys,
            index_map: self.index_map.clone(),
        }
    }

    fn clear_prefix(&mut self, count: usize) {
        let length = self.keys.len();

        let mut keys: Vector<PublicKeyBytes> =
            iter::repeat_n(PublicKeyBytes::zero(), count).collect();

        let mut tail = self.keys.clone();

        #[cfg(not(target_os = "zkvm"))]
        keys.append(tail.slice(count..length));
        #[cfg(target_os = "zkvm")]
        keys.append(&mut tail.slice(count..length));

        self.keys = keys;
    }
}

impl Extend<PublicKeyBytes> for PubkeyList {
    fn extend<T: IntoIterator<Item = PublicKeyBytes>>(&mut self, iter: T) {
        let Self {
            keys, index_map, ..
        } = self;

        let start = ValidatorIndex::try_from(keys.len())
            .expect("validator count never exceeds ValidatorIndex range");

        for (pubkey, index) in iter.into_iter().zip(start..) {
            keys.push_back(pubkey);
            index_map.insert(pubkey, index);
        }
    }
}

impl FromIterator<PublicKeyBytes> for PubkeyList {
    fn from_iter<T: IntoIterator<Item = PublicKeyBytes>>(iter: T) -> Self {
        let (keys, index_map) = iter
            .into_iter()
            .zip(0u64..)
            .map(|(pubkey, index)| (pubkey, (pubkey, index)))
            .unzip();

        Self { keys, index_map }
    }
}

impl TryFromIterator<PublicKeyBytes> for PubkeyList {
    type Error = Infallible;

    fn try_from_iter(items: impl IntoIterator<Item = PublicKeyBytes>) -> Result<Self, Self::Error> {
        Ok(Self::from_iter(items))
    }
}

impl<'list> IntoIterator for &'list PubkeyList {
    type Item = &'list PublicKeyBytes;
    type IntoIter = VectorIter<'list, PublicKeyBytes>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter()
    }
}

impl SszSize for PubkeyList {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl SszWrite for PubkeyList {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        write_list(bytes, self)
    }
}

impl<C> SszRead<C> for PubkeyList {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        read_list(usize::MAX, context, bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialValidator {
    pub withdrawal_credentials: H256,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

impl From<&Validator> for PartialValidator {
    fn from(value: &Validator) -> Self {
        Self {
            withdrawal_credentials: value.withdrawal_credentials.copy(),
            slashed: value.slashed.copy(),
            activation_eligibility_epoch: value.activation_eligibility_epoch.copy(),
            activation_epoch: value.activation_epoch.copy(),
            exit_epoch: value.exit_epoch.copy(),
            withdrawable_epoch: value.withdrawable_epoch.copy(),
        }
    }
}

#[expect(clippy::too_long_first_doc_paragraph)]
/// Low-level validator list implementation, containing only in-memory list
/// representation and methods for correctly operating on it. This allows
/// consumer to implement their own serialization and hashing, without caring
/// about list internals.
#[derive(Clone, Debug, Default, Derivative)]
#[derivative(PartialEq(bound = ""), Eq(bound = ""))]
pub struct RawValidatorList {
    /// Validator public keys never change, so we keep them separately, to
    /// structurally share keys even if any other field changes. The
    /// accompanying public key -> index map is shared along with them.
    pubkeys: PubkeyList,

    /// Validator effective balances change very frequently, comparing to other
    /// fields, so we keep them separately, so that we don't have to clone every
    /// other field when only balance changes.
    effective_balances: Vector<Gwei>,

    /// Rest validator fields. These change rarely, so kept separately.
    items: Vector<PartialValidator>,
}

impl RawValidatorList {
    pub fn get(&self, index: u64) -> Result<Validator, IndexError> {
        let index = self.validate_index(index)?;

        let pubkey = self.pubkeys.get(index).expect(
            "validator list invariant violated: \
                pubkey list is out of sync with current length",
        );
        let effective_balance = self.effective_balances.get(index).expect(
            "validator list invariant violated: \
                effective balance list is out of sync with current length",
        );
        let partial_validator = self.items.get(index).expect(
            "validator list invariant violated: \
                partial validator list is out of sync with current length",
        );

        Ok(Validator {
            pubkey: pubkey.copy(),
            withdrawal_credentials: partial_validator.withdrawal_credentials.copy(),
            effective_balance: effective_balance.copy(),
            slashed: partial_validator.slashed.copy(),
            activation_eligibility_epoch: partial_validator.activation_eligibility_epoch.copy(),
            activation_epoch: partial_validator.activation_epoch.copy(),
            exit_epoch: partial_validator.exit_epoch.copy(),
            withdrawable_epoch: partial_validator.withdrawable_epoch.copy(),
        })
    }

    pub fn pubkey(&self, index: u64) -> Result<&PublicKeyBytes, IndexError> {
        let index = self.validate_index(index)?;

        let pubkey = self.pubkeys.get(index).expect(
            "validator list invariant violated: \
                pubkey list is out of sync with current length",
        );

        Ok(pubkey)
    }

    pub fn effective_balance(&self, index: u64) -> Result<u64, IndexError> {
        let index = self.validate_index(index)?;

        let effective_balance = self.effective_balances.get(index).expect(
            "validator list invariant violated: \
                effective balance list is out of sync with current length",
        );

        Ok(effective_balance.copy())
    }

    pub fn effective_balance_mut(&mut self, index: u64) -> Result<&mut u64, IndexError> {
        let index = self.validate_index(index)?;

        let effective_balance = self.effective_balances.get_mut(index).expect(
            "validator list invariant violated: \
                effective balance list is out of sync with current length",
        );

        Ok(effective_balance)
    }

    pub fn partial_validator(&self, index: u64) -> Result<&PartialValidator, IndexError> {
        let index = self.validate_index(index)?;

        let partial_validator = self.items.get(index).expect(
            "validator list invariant violated: \
                partial validator list is out of sync with current length",
        );

        Ok(partial_validator)
    }

    pub fn partial_validator_mut(
        &mut self,
        index: u64,
    ) -> Result<&mut PartialValidator, IndexError> {
        let index = self.validate_index(index)?;

        let partial_validator = self.items.get_mut(index).expect(
            "validator list invariant violated: \
                partial validator list is out of sync with current length",
        );

        Ok(partial_validator)
    }

    pub fn update_effective_balances<E>(
        &mut self,
        mut updater: impl FnMut(&PartialValidator, Gwei) -> Result<Gwei, E>,
        mut invalidate: impl FnMut(usize, usize),
    ) -> Result<(), E> {
        let len = self.len_usize();

        let Self {
            effective_balances,
            items,
            ..
        } = self;

        for (index, (partial_validator, effective_balance)) in
            items.iter().zip(effective_balances.iter_mut()).enumerate()
        {
            let old_effective_balance = *effective_balance;
            let new_effective_balance = updater(partial_validator, old_effective_balance)?;

            if new_effective_balance == old_effective_balance {
                continue;
            }

            invalidate(index, len);

            *effective_balance = new_effective_balance;
        }

        Ok(())
    }

    #[must_use]
    pub const fn pubkeys(&self) -> &PubkeyList {
        &self.pubkeys
    }

    pub fn set_pubkeys(&mut self, pubkeys: &PubkeyList) -> Result<()> {
        let length = self.len_usize();

        ensure!(
            pubkeys.len() >= length,
            "pubkey list is shorter than validator count (expected at least {length}, got {})",
            pubkeys.len(),
        );

        self.pubkeys = pubkeys.prefix(length);

        Ok(())
    }

    pub fn clear_pubkeys(&mut self, count: usize) {
        let length = self.len_usize();
        let count = count.min(length);

        if count == 0 {
            return;
        }

        self.pubkeys.clear_prefix(count);
    }

    #[must_use]
    pub fn partial_validators(&self) -> VectorIter<'_, PartialValidator> {
        self.items.iter()
    }

    #[must_use]
    pub fn effective_balances(&self) -> VectorIter<'_, Gwei> {
        self.effective_balances.iter()
    }

    #[must_use]
    pub fn len_usize(&self) -> usize {
        self.pubkeys.len()
    }

    #[must_use]
    pub fn len_u64(&self) -> u64 {
        self.len_usize().try_into().expect("length must fit in u64")
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "takes the validator by value to mirror the conventional collection \
                  push API, even though every field happens to be Copy"
    )]
    pub fn push(&mut self, validator: Validator) {
        let Validator {
            pubkey,
            withdrawal_credentials,
            effective_balance,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        } = validator;

        self.items.push_back(PartialValidator {
            withdrawal_credentials,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        });
        self.pubkeys.push(pubkey);
        self.effective_balances.push_back(effective_balance);
    }

    fn validate_index(&self, index: u64) -> Result<usize, IndexError> {
        let index = index
            .try_into()
            .map_err(|_| IndexError::DoesNotFitInUsize { index })?;

        if index >= self.len_usize() {
            return Err(IndexError::OutOfBounds {
                length: self.len_usize(),
                index,
            });
        }

        Ok(index)
    }
}

impl FromIterator<Validator> for RawValidatorList {
    fn from_iter<T: IntoIterator<Item = Validator>>(iter: T) -> Self {
        let (items, (pubkeys, effective_balances)) = iter
            .into_iter()
            .map(|validator| {
                (
                    PartialValidator {
                        withdrawal_credentials: validator.withdrawal_credentials,
                        slashed: validator.slashed,
                        activation_eligibility_epoch: validator.activation_eligibility_epoch,
                        activation_epoch: validator.activation_epoch,
                        exit_epoch: validator.exit_epoch,
                        withdrawable_epoch: validator.withdrawable_epoch,
                    },
                    (validator.pubkey, validator.effective_balance),
                )
            })
            .unzip();

        Self {
            pubkeys,
            effective_balances,
            items,
        }
    }
}

pub struct ValidatorListIter<'a> {
    pubkeys: VectorIter<'a, PublicKeyBytes>,
    effective_balances: VectorIter<'a, Gwei>,
    items: VectorIter<'a, PartialValidator>,
}

impl Iterator for ValidatorListIter<'_> {
    type Item = Validator;

    fn next(&mut self) -> Option<Self::Item> {
        let pubkey = self.pubkeys.next()?;
        let effective_balance = self.effective_balances.next()?;
        let PartialValidator {
            withdrawal_credentials,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        } = self.items.next()?.copy();

        Some(Validator {
            pubkey: pubkey.copy(),
            withdrawal_credentials,
            effective_balance: effective_balance.copy(),
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.pubkeys.size_hint()
    }
}

impl ExactSizeIterator for ValidatorListIter<'_> {
    fn len(&self) -> usize {
        self.pubkeys.len()
    }
}

impl<'list> IntoIterator for &'list RawValidatorList {
    type Item = Validator;
    type IntoIter = ValidatorListIter<'list>;

    fn into_iter(self) -> Self::IntoIter {
        ValidatorListIter {
            pubkeys: self.pubkeys.iter(),
            effective_balances: self.effective_balances.iter(),
            items: self.items.iter(),
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
            Phase::Electra,
            Phase::Fulu,
            Phase::Gloas,
        ];

        assert_eq!(expected_order.len(), Phase::CARDINALITY);

        assert!(
            expected_order
                .into_iter()
                .tuple_windows()
                .all(|(earlier, later)| earlier < later)
        );
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
