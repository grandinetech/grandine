use core::{
    fmt::{Debug as FmtDebug, Formatter, Result as FmtResult},
    num::NonZeroUsize,
};
use std::sync::Arc;

use anyhow::{Error as AnyhowError, Result, bail};
use derivative::Derivative;
use derive_more::Debug;
use eth2_libp2p::{GossipId, PeerId};
use features::Feature;
use futures::channel::{mpsc::Sender, oneshot::Sender as OneshotSender};
use helper_functions::misc;
use serde::{Serialize, Serializer};
use ssz::{ProgressiveList, SszList};
use static_assertions::assert_eq_size;
use std_ext::ArcExt as _;
use strum::AsRefStr;
use thiserror::Error;
use transition_functions::unphased::StateRootPolicy;
use types::{
    combined::{
        Attestation, BeaconState, DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock,
    },
    config::Config as ChainConfig,
    deneb::containers::BlobSidecar,
    gloas::containers::{
        CombinedPayloadAttestation, PayloadAttestationData, SignedExecutionPayloadBid,
        SignedExecutionPayloadEnvelope, SignedProposerPreferences,
    },
    nonstandard::{
        PayloadStatus, Phase, Publishable, StorageMode, ValidationOutcome,
        ValidationOutcomeWithReason,
    },
    phase0::{
        containers::{AttestationData, Checkpoint},
        primitives::{ExecutionBlockHash, Gwei, H256, Slot, SubnetId, ValidatorIndex},
    },
    preset::Preset,
    traits::{SignedBeaconBlock as _, SszValidatorList},
};

use crate::{segment::Position, store::Store};

const EMPTY: &str = "empty";
const FULL: &str = "full";
const PENDING: &str = "pending";

#[derive(Clone, Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ChainLink<P: Preset> {
    pub block_root: H256,
    #[derivative(Debug(format_with = "fmt_block_concisely"))]
    pub block: Arc<SignedBeaconBlock<P>>,
    #[derivative(Debug(format_with = "fmt_as_wildcard"))]
    pub state: Option<Arc<BeaconState<P>>>,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub unrealized_justified_checkpoint: Checkpoint,
    pub unrealized_finalized_checkpoint: Checkpoint,
    pub payload_status: PayloadStatus,
    pub parent_payload_presence: PayloadPresence,
}

impl<P: Preset> ChainLink<P> {
    #[must_use]
    pub fn slot(&self) -> Slot {
        self.block.message().slot()
    }

    #[must_use]
    pub fn epoch(&self) -> Slot {
        misc::compute_epoch_at_slot::<P>(self.slot())
    }

    #[must_use]
    pub fn execution_block_hash(&self) -> Option<ExecutionBlockHash> {
        self.block.execution_block_hash()
    }

    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.payload_status.is_valid()
    }

    #[must_use]
    pub const fn is_invalid(&self) -> bool {
        self.payload_status.is_invalid()
    }

    #[must_use]
    pub const fn is_optimistic(&self) -> bool {
        self.payload_status.is_optimistic()
    }

    #[must_use]
    pub fn parent_root(&self) -> H256 {
        self.block.message().parent_root()
    }

    #[must_use]
    pub fn state<S: Storage<P>>(&self, store: &Store<P, S>) -> Arc<BeaconState<P>> {
        store.load_beacon_state(self.block_root, self.slot(), self.state.as_ref())
    }

    // TODO(feature/deneb): Confirm that post-Deneb states are always post-Merge. See:
    //                      - <https://github.com/ethereum/consensus-specs/pull/3232>
    //                      - <https://github.com/ethereum/consensus-specs/pull/3350>
    // fn is_post_deneb(&self) -> bool {
    //     self.block.message().body().with_blob_kzg_commitments().is_some()
    // }
}

pub enum PayloadAction {
    Accept,
    DelayUntilBlock(ExecutionBlockHash),
}

// It's too cumbersome to rename `PayloadStatus` and all the related fields and methods to something else.
// So what is called `PayloadStatus` in the Gloas consensus specs, is called `PayloadPresence` in Grandine.
#[derive(Clone, Copy, Debug, Default)]
pub enum PayloadPresence {
    Empty,
    Full,
    #[default]
    Pending,
}

impl PayloadPresence {
    #[must_use]
    pub const fn is_full(self) -> bool {
        matches!(self, Self::Full)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AttestingBalances {
    pub empty: Gwei,
    pub full: Gwei,
    pub pending: Gwei,
}

impl AttestingBalances {
    pub fn apply_differences(
        mut self,
        block_root: H256,
        payload_presence: Option<PayloadPresence>,
        differences: Differences,
    ) -> Result<Self> {
        self.pending = checked_add_balance(
            block_root,
            payload_presence,
            PENDING,
            self.pending,
            differences.pending,
        )?;

        match payload_presence {
            Some(PayloadPresence::Pending) => {}
            Some(PayloadPresence::Empty | PayloadPresence::Full) | None => {
                self.empty = checked_add_balance(
                    block_root,
                    payload_presence,
                    EMPTY,
                    self.empty,
                    differences.empty,
                )?;
                self.full = checked_add_balance(
                    block_root,
                    payload_presence,
                    FULL,
                    self.full,
                    differences.full,
                )?;
            }
        }

        Ok(self)
    }
}

fn checked_add_balance(
    block_root: H256,
    payload_presence: Option<PayloadPresence>,
    balance_kind: &str,
    current: u64,
    value: i64,
) -> Result<u64> {
    match current.checked_add_signed(value) {
        Some(balance) => Ok(balance),
        None => bail!(
            "attesting balance should never go below zero \
            (block: {block_root:?} with payload {payload_presence:?}, \
            balance kind: {balance_kind}, \
            current value: {current}, \
            add value: {value})",
        ),
    }
}

#[derive(Clone, Debug)]
pub struct UnfinalizedBlock<P: Preset> {
    pub chain_link: ChainLink<P>,
    pub attesting_balances: AttestingBalances,
}

impl<P: Preset> UnfinalizedBlock<P> {
    #[must_use]
    pub const fn new(chain_link: ChainLink<P>) -> Self {
        Self {
            chain_link,
            attesting_balances: AttestingBalances {
                empty: 0,
                full: 0,
                pending: 0,
            },
        }
    }

    #[must_use]
    pub const fn block_root(&self) -> H256 {
        self.chain_link.block_root
    }

    #[must_use]
    pub fn slot(&self) -> Slot {
        self.chain_link.slot()
    }

    #[must_use]
    pub fn epoch(&self) -> Slot {
        self.chain_link.epoch()
    }

    #[must_use]
    pub const fn is_invalid(&self) -> bool {
        self.chain_link.is_invalid()
    }

    #[must_use]
    pub const fn non_invalid(&self) -> bool {
        !self.is_invalid()
    }

    #[must_use]
    pub const fn is_optimistic(&self) -> bool {
        self.chain_link.is_optimistic()
    }

    #[must_use]
    pub const fn parent_payload_presence(&self) -> PayloadPresence {
        self.chain_link.parent_payload_presence
    }

    #[must_use]
    pub fn balances(&self) -> BlockBalances {
        self.into()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BlockBalances {
    pub block_root: H256,
    pub slot: Slot,
    pub attesting_balances: AttestingBalances,
}

impl<P: Preset> From<&UnfinalizedBlock<P>> for BlockBalances {
    fn from(block: &UnfinalizedBlock<P>) -> Self {
        Self {
            block_root: block.block_root(),
            slot: block.slot(),
            attesting_balances: block.attesting_balances,
        }
    }
}

impl BlockBalances {
    pub const fn empty(&self) -> Gwei {
        self.attesting_balances.empty
    }

    pub const fn full(&self) -> Gwei {
        self.attesting_balances.full
    }
}

#[derive(Debug, Clone, AsRefStr)]
pub enum BlockOrigin {
    Gossip(GossipId),
    Requested(Option<PeerId>),
    Own,
    Persisted,
    Api(Option<Sender<Result<ValidationOutcome>>>),
}

impl BlockOrigin {
    #[must_use]
    pub fn split(self) -> (Option<GossipId>, Option<Sender<Result<ValidationOutcome>>>) {
        match self {
            Self::Gossip(gossip_id) => (Some(gossip_id), None),
            Self::Api(sender) => (None, sender),
            Self::Requested(_) | Self::Own | Self::Persisted => (None, None),
        }
    }

    #[must_use]
    pub fn gossip_id(&self) -> Option<GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id.clone()),
            Self::Requested(_) | Self::Own | Self::Persisted | Self::Api(_) => None,
        }
    }

    #[must_use]
    pub const fn peer_id(&self) -> Option<PeerId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id.source),
            Self::Requested(peer_id) => *peer_id,
            Self::Own | Self::Persisted | Self::Api(_) => None,
        }
    }

    #[must_use]
    pub fn state_root_policy(&self) -> StateRootPolicy {
        match self {
            Self::Gossip(_) | Self::Requested(_) | Self::Api(_) => StateRootPolicy::Verify,
            Self::Own => {
                if Feature::TrustOwnStateRoots.is_enabled() {
                    StateRootPolicy::Trust
                } else {
                    StateRootPolicy::Verify
                }
            }
            Self::Persisted => StateRootPolicy::Trust,
        }
    }

    #[must_use]
    pub const fn data_availability_policy(&self) -> DataAvailabilityPolicy {
        match self {
            Self::Gossip(_) | Self::Requested(_) | Self::Api(_) | Self::Own => {
                DataAvailabilityPolicy::Check
            }
            Self::Persisted => DataAvailabilityPolicy::Trust,
        }
    }

    #[must_use]
    pub const fn should_send_gossip_event(&self) -> bool {
        match self {
            Self::Gossip(_) | Self::Api(_) => true,
            Self::Requested(_) | Self::Own | Self::Persisted => false,
        }
    }

    // TODO: use Debug instead
    #[must_use]
    pub const fn metrics_label(&self) -> &str {
        match self {
            Self::Gossip(_) => "Gossip",
            Self::Requested(_) => "Requested",
            Self::Own => "Own",
            Self::Persisted => "Persisted",
            Self::Api(_) => "Api",
        }
    }

    #[must_use]
    pub const fn is_requested(&self) -> bool {
        matches!(self, Self::Requested(..))
    }
}

#[derive(Debug, AsRefStr)]
pub enum AggregateAndProofOrigin<I> {
    Gossip(I),
    Api(OneshotSender<Result<ValidationOutcome>>),
}

impl Serialize for AggregateAndProofOrigin<GossipId> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<I> AggregateAndProofOrigin<I> {
    #[must_use]
    pub fn split(self) -> (Option<I>, Option<OneshotSender<Result<ValidationOutcome>>>) {
        match self {
            Self::Gossip(gossip_id) => (Some(gossip_id), None),
            Self::Api(sender) => (None, Some(sender)),
        }
    }

    #[must_use]
    pub fn gossip_id(self) -> Option<I> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id),
            Self::Api(_) => None,
        }
    }

    #[must_use]
    pub const fn gossip_id_ref(&self) -> Option<&I> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id),
            Self::Api(_) => None,
        }
    }

    #[must_use]
    pub const fn verify_signatures(&self) -> bool {
        match self {
            Self::Gossip(_) | Self::Api(_) => true,
        }
    }

    #[must_use]
    pub const fn send_to_validator(&self) -> bool {
        match self {
            Self::Gossip(_) | Self::Api(_) => true,
        }
    }

    // TODO: use Debug instead
    #[must_use]
    pub const fn metrics_label(&self) -> &str {
        match self {
            Self::Gossip(_) => "Gossip",
            Self::Api(_) => "Api",
        }
    }
}

#[derive(Debug, AsRefStr)]
pub enum ExecutionPayloadBidOrigin {
    Gossip(GossipId),
    Api(OneshotSender<Result<ValidationOutcomeWithReason>>),
}

impl Serialize for ExecutionPayloadBidOrigin {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl ExecutionPayloadBidOrigin {
    #[must_use]
    pub fn split(
        self,
    ) -> (
        Option<GossipId>,
        Option<OneshotSender<Result<ValidationOutcomeWithReason>>>,
    ) {
        match self {
            Self::Gossip(gossip_id) => (Some(gossip_id), None),
            Self::Api(sender) => (None, Some(sender)),
        }
    }

    #[must_use]
    pub fn gossip_id(self) -> Option<GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id),
            Self::Api(_) => None,
        }
    }

    #[must_use]
    pub const fn gossip_id_ref(&self) -> Option<&GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id),
            Self::Api(_) => None,
        }
    }

    #[must_use]
    pub const fn is_from_gossip(&self) -> bool {
        matches!(self, Self::Gossip(_))
    }

    #[must_use]
    pub const fn verify_signatures(&self) -> bool {
        match self {
            Self::Gossip(_) | Self::Api(_) => true,
        }
    }

    #[must_use]
    pub const fn send_to_validator(&self) -> bool {
        match self {
            Self::Gossip(_) | Self::Api(_) => true,
        }
    }

    // TODO: use Debug instead
    #[must_use]
    pub const fn metrics_label(&self) -> &str {
        match self {
            Self::Gossip(_) => "Gossip",
            Self::Api(_) => "Api",
        }
    }
}

#[derive(Debug)]
pub struct AttestationItem<P: Preset, I> {
    pub item: Arc<Attestation<P>>,
    pub origin: AttestationOrigin<I>,
    pub signature_status: SignatureStatus,
}

impl<P: Preset, I> AttestationItem<P, I> {
    #[must_use]
    pub const fn unverified(item: Arc<Attestation<P>>, origin: AttestationOrigin<I>) -> Self {
        Self {
            item,
            origin,
            signature_status: SignatureStatus::Unverified,
        }
    }

    #[must_use]
    pub const fn verified(item: Arc<Attestation<P>>, origin: AttestationOrigin<I>) -> Self {
        Self {
            item,
            origin,
            signature_status: SignatureStatus::Verified,
        }
    }

    #[must_use]
    pub fn into_verified(self) -> Self {
        let Self { item, origin, .. } = self;

        Self {
            item,
            origin,
            signature_status: SignatureStatus::Verified,
        }
    }

    #[must_use]
    pub fn verify_signatures(&self) -> bool {
        !self.signature_status.is_verified() && self.origin.verify_signatures()
    }

    #[must_use]
    pub fn slot(&self) -> Slot {
        self.data().slot
    }

    #[must_use]
    pub fn data(&self) -> AttestationData {
        self.item.data()
    }

    #[must_use]
    pub fn item(&self) -> Arc<Attestation<P>> {
        self.item.clone_arc()
    }
}

#[derive(Debug)]
pub struct PayloadAttestationItem<P: Preset> {
    pub item: Arc<CombinedPayloadAttestation<P>>,
    pub origin: PayloadAttestationOrigin,
    pub signature_status: SignatureStatus,
}

impl<P: Preset> PayloadAttestationItem<P> {
    #[must_use]
    pub const fn unverified(
        item: Arc<CombinedPayloadAttestation<P>>,
        origin: PayloadAttestationOrigin,
    ) -> Self {
        Self {
            item,
            origin,
            signature_status: SignatureStatus::Unverified,
        }
    }

    #[must_use]
    pub const fn verified(
        item: Arc<CombinedPayloadAttestation<P>>,
        origin: PayloadAttestationOrigin,
    ) -> Self {
        Self {
            item,
            origin,
            signature_status: SignatureStatus::Verified,
        }
    }

    #[must_use]
    pub fn into_verified(self) -> Self {
        let Self { item, origin, .. } = self;

        Self {
            item,
            origin,
            signature_status: SignatureStatus::Verified,
        }
    }

    #[must_use]
    pub fn verify_signatures(&self) -> bool {
        !self.signature_status.is_verified() && self.origin.verify_signatures()
    }

    #[must_use]
    pub fn data(&self) -> PayloadAttestationData {
        self.item.data()
    }

    #[must_use]
    pub fn item(&self) -> Arc<CombinedPayloadAttestation<P>> {
        self.item.clone_arc()
    }
}

#[derive(Debug, AsRefStr)]
pub enum SignatureStatus {
    Verified,
    Unverified,
}

impl SignatureStatus {
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Debug, AsRefStr, Serialize)]
pub enum AttestationOrigin<I> {
    Gossip(SubnetId, I),
    Own(SubnetId),
    Api(
        SubnetId,
        #[serde(skip)] OneshotSender<Result<ValidationOutcome>>,
    ),
    Block(H256),
    // Some test cases in `consensus-spec-tests` contain data that cannot occur in normal operation.
    // `fork_choice` test cases contain bare aggregate attestations.
    // Normally they can only occur inside blocks or alongside aggregate selection proofs.
    Test,
}

impl<I> AttestationOrigin<I> {
    #[must_use]
    pub fn split(self) -> (Option<I>, Option<OneshotSender<Result<ValidationOutcome>>>) {
        match self {
            Self::Gossip(_, gossip_id) => (Some(gossip_id), None),
            Self::Api(_, sender) => (None, Some(sender)),
            Self::Own(_) | Self::Block(_) | Self::Test => (None, None),
        }
    }

    #[must_use]
    pub const fn subnet_id(&self) -> Option<SubnetId> {
        match *self {
            Self::Gossip(subnet_id, _) | Self::Own(subnet_id) | Self::Api(subnet_id, _) => {
                Some(subnet_id)
            }
            Self::Block(_) | Self::Test => None,
        }
    }

    #[must_use]
    pub fn gossip_id(self) -> Option<I> {
        match self {
            Self::Gossip(_, gossip_id) => Some(gossip_id),
            _ => None,
        }
    }

    #[must_use]
    pub const fn gossip_id_ref(&self) -> Option<&I> {
        match self {
            Self::Gossip(_, gossip_id) => Some(gossip_id),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_from_block(&self) -> bool {
        matches!(self, Self::Block(_))
    }

    #[must_use]
    pub const fn validate_as_gossip(&self) -> bool {
        match self {
            Self::Gossip(_, _) | Self::Own(_) | Self::Api(_, _) | Self::Test => true,
            Self::Block(_) => false,
        }
    }

    #[must_use]
    pub const fn must_be_singular(&self) -> bool {
        match self {
            Self::Gossip(_, _) | Self::Own(_) | Self::Api(_, _) => true,
            Self::Block(_) | Self::Test => false,
        }
    }

    #[must_use]
    pub const fn should_generate_event(&self) -> bool {
        matches!(self, Self::Gossip(_, _) | Self::Api(_, _))
    }

    #[must_use]
    pub fn verify_signatures(&self) -> bool {
        match self {
            Self::Gossip(_, _) | Self::Api(_, _) | Self::Test => true,
            Self::Block(_) => false,
            Self::Own(_) => !Feature::TrustOwnAttestationSignatures.is_enabled(),
        }
    }

    #[must_use]
    pub const fn send_to_validator(&self) -> bool {
        match self {
            Self::Gossip(_, _) | Self::Api(_, _) => true,
            Self::Own(_) | Self::Block(_) | Self::Test => false,
        }
    }

    // TODO: use Debug instead
    #[must_use]
    pub const fn metrics_label(&self) -> &str {
        match self {
            Self::Gossip(_, _) => "Gossip",
            Self::Own(_) => "Own",
            Self::Api(_, _) => "Api",
            Self::Block(_) => "Block",
            Self::Test => "Test",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AttesterSlashingOrigin {
    Gossip,
    Block,
    Own,
}

impl AttesterSlashingOrigin {
    #[must_use]
    pub fn verify_signatures(self) -> bool {
        match self {
            Self::Gossip => true,
            Self::Block => false,
            Self::Own => !Feature::TrustOwnAttesterSlashingSignatures.is_enabled(),
        }
    }
}

#[derive(Debug, AsRefStr)]
pub enum PayloadAttestationOrigin {
    Gossip(GossipId),
    Api(OneshotSender<Result<ValidationOutcome>>),
    Block(H256),
    Own,
}

impl PayloadAttestationOrigin {
    #[must_use]
    pub fn split(
        self,
    ) -> (
        Option<GossipId>,
        Option<OneshotSender<Result<ValidationOutcome>>>,
    ) {
        match self {
            Self::Gossip(gossip_id) => (Some(gossip_id), None),
            Self::Api(sender) => (None, Some(sender)),
            Self::Own | Self::Block(_) => (None, None),
        }
    }

    #[must_use]
    pub fn gossip_id(&self) -> Option<GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id.clone()),
            Self::Own | Self::Block(_) | Self::Api(_) => None,
        }
    }

    #[must_use]
    pub const fn gossip_id_ref(&self) -> Option<&GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id),
            _ => None,
        }
    }

    #[must_use]
    pub const fn peer_id(&self) -> Option<PeerId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id.source),
            Self::Api(_) | Self::Own | Self::Block(_) => None,
        }
    }

    #[must_use]
    pub fn verify_signatures(&self) -> bool {
        match self {
            Self::Gossip(_) | Self::Api(_) => true,
            Self::Block(_) => false,
            Self::Own => !Feature::TrustOwnAttestationSignatures.is_enabled(),
        }
    }

    #[must_use]
    pub const fn is_from_block(&self) -> bool {
        matches!(self, Self::Block(_))
    }

    #[must_use]
    pub const fn should_generate_event(&self) -> bool {
        matches!(self, Self::Gossip(_) | Self::Api(_))
    }

    #[must_use]
    pub const fn send_to_validator(&self) -> bool {
        matches!(self, Self::Gossip(_) | Self::Api(_))
    }

    #[must_use]
    pub const fn metrics_label(&self) -> &str {
        match self {
            Self::Gossip(_) => "Gossip",
            Self::Own => "Own",
            Self::Api(_) => "Api",
            Self::Block(_) => "Block",
        }
    }
}

#[derive(Debug)]
pub enum BlobSidecarOrigin {
    Api(Option<OneshotSender<Result<ValidationOutcome>>>),
    BackSync,
    ExecutionLayer,
    Gossip(SubnetId, GossipId),
    Requested(PeerId),
    Own,
}

impl BlobSidecarOrigin {
    #[must_use]
    pub fn split(
        self,
    ) -> (
        Option<GossipId>,
        Option<OneshotSender<Result<ValidationOutcome>>>,
    ) {
        match self {
            Self::Gossip(_, gossip_id) => (Some(gossip_id), None),
            Self::Api(sender) => (None, sender),
            Self::BackSync | Self::ExecutionLayer | Self::Own | Self::Requested(_) => (None, None),
        }
    }

    #[must_use]
    pub fn gossip_id(self) -> Option<GossipId> {
        match self {
            Self::Gossip(_, gossip_id) => Some(gossip_id),
            Self::Api(_)
            | Self::BackSync
            | Self::ExecutionLayer
            | Self::Own
            | Self::Requested(_) => None,
        }
    }

    #[must_use]
    pub const fn peer_id(&self) -> Option<PeerId> {
        match self {
            Self::Gossip(_, gossip_id) => Some(gossip_id.source),
            Self::Requested(peer_id) => Some(*peer_id),
            Self::Api(_) | Self::BackSync | Self::ExecutionLayer | Self::Own => None,
        }
    }

    #[must_use]
    pub const fn subnet_id(&self) -> Option<SubnetId> {
        match self {
            Self::Gossip(subnet_id, _) => Some(*subnet_id),
            Self::Api(_)
            | Self::BackSync
            | Self::ExecutionLayer
            | Self::Own
            | Self::Requested(_) => None,
        }
    }

    #[must_use]
    pub const fn is_from_el(&self) -> bool {
        matches!(self, Self::ExecutionLayer)
    }

    #[must_use]
    pub const fn is_from_back_sync(&self) -> bool {
        matches!(self, Self::BackSync)
    }
}

#[derive(Debug)]
pub enum DataColumnSidecarOrigin {
    Api(Option<OneshotSender<Result<ValidationOutcome>>>),
    BackSync,
    ExecutionLayer,
    Gossip(SubnetId, GossipId),
    Requested(PeerId),
    Own,
}

impl DataColumnSidecarOrigin {
    #[must_use]
    pub fn split(
        self,
    ) -> (
        Option<GossipId>,
        Option<OneshotSender<Result<ValidationOutcome>>>,
    ) {
        match self {
            Self::Gossip(_, gossip_id) => (Some(gossip_id), None),
            Self::Api(sender) => (None, sender),
            Self::BackSync | Self::ExecutionLayer | Self::Own | Self::Requested(_) => (None, None),
        }
    }

    #[must_use]
    pub fn gossip_id(self) -> Option<GossipId> {
        match self {
            Self::Gossip(_, gossip_id) => Some(gossip_id),
            Self::Api(_)
            | Self::BackSync
            | Self::ExecutionLayer
            | Self::Own
            | Self::Requested(_) => None,
        }
    }

    #[must_use]
    pub const fn peer_id(&self) -> Option<PeerId> {
        match self {
            Self::Gossip(_, gossip_id) => Some(gossip_id.source),
            Self::Requested(peer_id) => Some(*peer_id),
            Self::Api(_) | Self::BackSync | Self::ExecutionLayer | Self::Own => None,
        }
    }

    #[must_use]
    pub const fn subnet_id(&self) -> Option<SubnetId> {
        match self {
            Self::Gossip(subnet_id, _) => Some(*subnet_id),
            Self::Api(_)
            | Self::BackSync
            | Self::ExecutionLayer
            | Self::Own
            | Self::Requested(_) => None,
        }
    }

    #[must_use]
    pub const fn is_from_api(&self) -> bool {
        matches!(self, Self::Api(_))
    }

    #[must_use]
    pub const fn is_from_back_sync(&self) -> bool {
        matches!(self, Self::BackSync)
    }

    #[must_use]
    pub const fn is_from_el(&self) -> bool {
        matches!(self, Self::ExecutionLayer)
    }
}

pub enum BlockAction<P: Preset> {
    Accept(ChainLink<P>, Vec<Result<Vec<ValidatorIndex>>>),
    Ignore(Publishable),
    DelayUntilBlobs(Arc<SignedBeaconBlock<P>>, Arc<BeaconState<P>>),
    DelayUntilParent(Arc<SignedBeaconBlock<P>>),
    DelayUntilPayload(Arc<SignedBeaconBlock<P>>),
    DelayUntilSlot(Arc<SignedBeaconBlock<P>>),
    WaitForJustifiedState(ChainLink<P>, Vec<Result<Vec<ValidatorIndex>>>, Checkpoint),
}

impl<P: Preset> FmtDebug for BlockAction<P> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Accept(_, _) => f.write_str("accept"),
            Self::Ignore(_) => f.write_str("ignore"),
            Self::DelayUntilBlobs(_, _) => f.write_str("delay_until_blobs"),
            Self::DelayUntilParent(_) => f.write_str("delay_until_parent"),
            Self::DelayUntilPayload(_) => f.write_str("delay_until_payload"),
            Self::DelayUntilSlot(_) => f.write_str("delay_until_slot"),
            Self::WaitForJustifiedState(_, _, _) => f.write_str("wait_for_justified_state"),
        }
    }
}

pub enum AggregateAndProofAction<P: Preset> {
    Accept {
        aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
        attesting_indices: ProgressiveList<ValidatorIndex>,
        is_subset_aggregate: bool,
    },
    Ignore,
    DelayUntilBlock(Arc<SignedAggregateAndProof<P>>, H256),
    DelayUntilPayload(Arc<SignedAggregateAndProof<P>>, H256),
    DelayUntilSlot(Arc<SignedAggregateAndProof<P>>),
    WaitForTargetState(Arc<SignedAggregateAndProof<P>>),
}

pub enum AttestationAction<P: Preset, I> {
    Accept {
        attestation: AttestationItem<P, I>,
        attesting_indices: ProgressiveList<ValidatorIndex>,
    },
    Ignore(AttestationItem<P, I>),
    DelayUntilBlock(AttestationItem<P, I>, H256),
    DelayUntilPayload(AttestationItem<P, I>, H256),
    DelayUntilSlot(AttestationItem<P, I>),
    WaitForTargetState(AttestationItem<P, I>),
}

impl<P: Preset, I> AttestationAction<P, I> {
    #[must_use]
    pub fn into_verified(self) -> Self {
        match self {
            Self::Accept {
                attestation,
                attesting_indices,
            } => Self::Accept {
                attestation: attestation.into_verified(),
                attesting_indices,
            },
            Self::Ignore(attestation) => Self::Ignore(attestation.into_verified()),
            Self::DelayUntilBlock(attestation, block_root) => {
                Self::DelayUntilBlock(attestation.into_verified(), block_root)
            }
            Self::DelayUntilPayload(attestation, block_root) => {
                Self::DelayUntilPayload(attestation.into_verified(), block_root)
            }
            Self::DelayUntilSlot(attestation) => Self::DelayUntilSlot(attestation.into_verified()),
            Self::WaitForTargetState(attestation) => {
                Self::WaitForTargetState(attestation.into_verified())
            }
        }
    }
}

#[derive(Debug)]
pub enum BlobSidecarAction<P: Preset> {
    Accept(Arc<BlobSidecar<P>>),
    Ignore(Publishable),
    DelayUntilState(Arc<BlobSidecar<P>>, H256),
    DelayUntilParent(Arc<BlobSidecar<P>>),
    DelayUntilSlot(Arc<BlobSidecar<P>>),
}

impl<P: Preset> BlobSidecarAction<P> {
    #[must_use]
    pub const fn accepted(&self) -> bool {
        matches!(self, Self::Accept(_))
    }
}

#[derive(Debug)]
pub enum DataColumnSidecarAction<P: Preset> {
    Accept(Arc<DataColumnSidecar<P>>),
    Ignore(Publishable),
    DelayUntilState(Arc<DataColumnSidecar<P>>, H256),
    DelayUntilParent(Arc<DataColumnSidecar<P>>),
    DelayUntilSlot(Arc<DataColumnSidecar<P>>),
}

impl<P: Preset> DataColumnSidecarAction<P> {
    #[must_use]
    pub const fn accepted(&self) -> bool {
        matches!(self, Self::Accept(_))
    }

    #[must_use]
    pub const fn ignored(&self) -> bool {
        matches!(self, Self::Ignore(_))
    }
}

pub enum ExecutionPayloadBidAction<P: Preset> {
    Accept(Arc<SignedExecutionPayloadBid<P>>),
    Ignore(&'static str),
}

// a list of Tuple(attesting_index, positions_in_committee)
type AttestingIndicesPositions = Vec<(ValidatorIndex, Vec<usize>)>;

#[derive(Debug)]
pub enum PayloadAttestationAction<P: Preset> {
    Accept {
        payload_attestation: PayloadAttestationItem<P>,
        attesting_indices_positions: AttestingIndicesPositions,
    },
    Ignore(PayloadAttestationItem<P>),
    DelayUntilBlock(PayloadAttestationItem<P>, H256),
}

impl<P: Preset> PayloadAttestationAction<P> {
    #[must_use]
    pub fn into_verified(self) -> Self {
        match self {
            Self::Accept {
                payload_attestation,
                attesting_indices_positions,
            } => Self::Accept {
                payload_attestation: payload_attestation.into_verified(),
                attesting_indices_positions,
            },
            Self::Ignore(payload_attestation) => Self::Ignore(payload_attestation.into_verified()),
            Self::DelayUntilBlock(payload_attestation, block_root) => {
                Self::DelayUntilBlock(payload_attestation.into_verified(), block_root)
            }
        }
    }
}

pub enum ProposerPreferencesAction {
    Accept(Arc<SignedProposerPreferences>),
    Ignore(Publishable),
    DelayUntilBlock(Arc<SignedProposerPreferences>),
}

pub enum PartialBlockAction {
    Accept,
    Ignore,
}

pub enum PartialAttestationAction {
    Accept,
    Ignore,
    DelayUntilBlock(H256),
    DelayUntilPayload(H256),
    DelayUntilSlot,
}

#[derive(Debug, Clone, AsRefStr)]
pub enum ExecutionPayloadEnvelopeOrigin {
    BackSync,
    Gossip(GossipId),
    Requested(PeerId),
    Own,
    Api(Option<Sender<Result<ValidationOutcome>>>),
}

impl ExecutionPayloadEnvelopeOrigin {
    #[must_use]
    pub fn split(self) -> (Option<GossipId>, Option<Sender<Result<ValidationOutcome>>>) {
        match self {
            Self::Gossip(gossip_id) => (Some(gossip_id), None),
            Self::Api(sender) => (None, sender),
            Self::BackSync | Self::Requested(_) | Self::Own => (None, None),
        }
    }

    #[must_use]
    pub fn gossip_id(&self) -> Option<GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id.clone()),
            Self::BackSync | Self::Requested(_) | Self::Own | Self::Api(_) => None,
        }
    }

    #[must_use]
    pub const fn gossip_id_ref(&self) -> Option<&GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id),
            Self::BackSync | Self::Requested(_) | Self::Own | Self::Api(_) => None,
        }
    }

    #[must_use]
    pub const fn should_generate_event(&self) -> bool {
        matches!(self, Self::Gossip(_) | Self::Api(_) | Self::Own)
    }

    #[must_use]
    pub const fn should_send_gossip_event(&self) -> bool {
        matches!(self, Self::Gossip(_) | Self::Api(_))
    }

    #[must_use]
    pub const fn verify_signatures(&self) -> bool {
        match self {
            Self::BackSync | Self::Gossip(_) | Self::Requested(_) | Self::Api(_) => true,
            Self::Own => false,
        }
    }

    #[must_use]
    pub const fn is_own(&self) -> bool {
        matches!(self, Self::Own)
    }

    #[must_use]
    pub const fn is_from_back_sync(&self) -> bool {
        matches!(self, Self::BackSync)
    }

    #[must_use]
    pub const fn is_requested(&self) -> bool {
        matches!(self, Self::Requested(_))
    }
}

#[derive(Debug)]
pub enum ProposerPreferencesOrigin {
    Gossip(GossipId),
    Api(OneshotSender<Result<ValidationOutcome>>),
    Own,
}

impl ProposerPreferencesOrigin {
    #[must_use]
    pub fn split(
        self,
    ) -> (
        Option<GossipId>,
        Option<OneshotSender<Result<ValidationOutcome>>>,
    ) {
        match self {
            Self::Gossip(gossip_id) => (Some(gossip_id), None),
            Self::Api(sender) => (None, Some(sender)),
            Self::Own => (None, None),
        }
    }

    #[must_use]
    pub const fn verify_signatures(&self) -> bool {
        match self {
            Self::Gossip(_) | Self::Api(_) => true,
            Self::Own => false,
        }
    }

    #[must_use]
    pub fn gossip_id(self) -> Option<GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id),
            Self::Api(_) | Self::Own => None,
        }
    }

    #[must_use]
    pub const fn gossip_id_ref(&self) -> Option<&GossipId> {
        match self {
            Self::Gossip(gossip_id) => Some(gossip_id),
            Self::Api(_) | Self::Own => None,
        }
    }
}

#[derive(Debug)]
pub enum ExecutionPayloadEnvelopeAction<P: Preset> {
    Accept(Arc<SignedExecutionPayloadEnvelope<P>>),
    Ignore(Publishable),
    DelayUntilBeaconBlock(Arc<SignedExecutionPayloadEnvelope<P>>, H256),
    DelayUntilState(Arc<SignedExecutionPayloadEnvelope<P>>, H256),
    DelayUntilData(
        Arc<SignedExecutionPayloadEnvelope<P>>,
        Arc<SignedBeaconBlock<P>>,
    ),
}

impl<P: Preset> ExecutionPayloadEnvelopeAction<P> {
    #[must_use]
    pub const fn accepted(&self) -> bool {
        matches!(self, Self::Accept(_))
    }
}

#[derive(Clone)]
pub struct ValidAttestation {
    pub data: AttestationData,
    pub attesting_indices: ProgressiveList<ValidatorIndex>,
    pub is_from_block: bool,
}

#[derive(Clone)]
pub struct ValidPayloadAttestation {
    pub data: PayloadAttestationData,
    pub attesting_indices_positions: AttestingIndicesPositions,
    pub is_from_block: bool,
}

pub enum ApplyBlockChanges<P: Preset> {
    CanonicalChainExtended {
        finalized_checkpoint_updated: bool,
    },
    Reorganized {
        finalized_checkpoint_updated: bool,
        old_head: Box<ChainLink<P>>,
    },
    AlternateChainExtended {
        finalized_checkpoint_updated: bool,
    },
}

impl<P: Preset> ApplyBlockChanges<P> {
    #[must_use]
    pub const fn is_finalized_checkpoint_updated(&self) -> bool {
        match *self {
            Self::CanonicalChainExtended {
                finalized_checkpoint_updated,
            }
            | Self::Reorganized {
                finalized_checkpoint_updated,
                ..
            }
            | Self::AlternateChainExtended {
                finalized_checkpoint_updated,
            } => finalized_checkpoint_updated,
        }
    }
}

pub enum ApplyTickChanges<P: Preset> {
    TickUpdated,
    SlotUpdated {
        epoch_updated: bool,
        finalized_checkpoint_updated: bool,
    },
    Reorganized {
        epoch_updated: bool,
        finalized_checkpoint_updated: bool,
        old_head: Box<ChainLink<P>>,
    },
}

impl<P: Preset> ApplyTickChanges<P> {
    #[must_use]
    pub const fn is_finalized_checkpoint_updated(&self) -> bool {
        match *self {
            Self::TickUpdated => false,
            Self::SlotUpdated {
                finalized_checkpoint_updated,
                ..
            }
            | Self::Reorganized {
                finalized_checkpoint_updated,
                ..
            } => finalized_checkpoint_updated,
        }
    }

    #[must_use]
    pub const fn is_slot_updated(&self) -> bool {
        match self {
            Self::TickUpdated => false,
            Self::SlotUpdated { .. } | Self::Reorganized { .. } => true,
        }
    }

    #[must_use]
    pub const fn is_epoch_updated(&self) -> bool {
        match self {
            Self::TickUpdated => false,
            Self::SlotUpdated { epoch_updated, .. } | Self::Reorganized { epoch_updated, .. } => {
                *epoch_updated
            }
        }
    }
}

// This uses `NonZeroUsize` to make `Option<SegmentId>` fit in 1 word of memory.
// The current version doesn't use nearly as many `Option`s, making it less useful.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[debug("{_0}")]
pub struct SegmentId(NonZeroUsize);

assert_eq_size!(Option<SegmentId>, usize);

impl SegmentId {
    pub const FIRST: Self = Self(NonZeroUsize::MIN);

    pub fn next(self) -> Result<Self> {
        // Using `wrapping_add` here achieves the same as `checked_add` but with less code.
        self.0
            .get()
            .wrapping_add(1)
            .try_into()
            .map(Self)
            .map_err(Into::into)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Location {
    pub segment_id: SegmentId,
    pub position: Position,
}

assert_eq_size!(Option<Location>, [usize; 2]);

// We store attesting balances as `Gwei`, which may overflow with a sufficiently high number of
// validators. Balance calculations could be made infallible using the fact that effective balances
// are bounded by `MAX_EFFECTIVE_BALANCE` and vary by `EFFECTIVE_BALANCE_INCREMENT`, but that would
// be overkill. `i64` is enough for hundreds of millions of validators. It's less than the maximum
// length of the registry, but far more than the planned number (4 million maximum, 1 million with
// sortition). Also, we currently have `overflow-checks` enabled, so the calculations won't break
// silently.
pub type Difference = i64;

// Balance differences for fork choice nodes depending on payload presence status
#[derive(Clone, Copy, Debug, Default, Derivative)]
#[derivative(PartialEq, Eq, PartialOrd, Ord)]
pub struct Differences {
    pub empty: Difference,
    pub full: Difference,
    pub pending: Difference,
}

impl Differences {
    pub fn checked_add_balance_mut(
        &mut self,
        value: Gwei,
        payload_present: Option<bool>,
    ) -> Option<()> {
        self.pending = self.pending.checked_add_unsigned(value)?;

        if let Some(payload_present) = payload_present {
            if payload_present {
                self.full = self.full.checked_add_unsigned(value)?;
            } else {
                self.empty = self.empty.checked_add_unsigned(value)?;
            }
        }

        Some(())
    }

    pub fn checked_sub_balance_mut(
        &mut self,
        value: Gwei,
        payload_present: Option<bool>,
    ) -> Option<()> {
        self.pending = self.pending.checked_sub_unsigned(value)?;

        if let Some(payload_present) = payload_present {
            if payload_present {
                self.full = self.full.checked_sub_unsigned(value)?;
            } else {
                self.empty = self.empty.checked_sub_unsigned(value)?;
            }
        }

        Some(())
    }

    #[must_use]
    pub const fn non_zero(&self) -> bool {
        self.empty != 0 || self.full != 0 || self.pending != 0
    }
}

/// The [weight] of a block combined with its root as a [tiebreaker].
///
/// See [`consensus-specs` pull request #3250] for more information.
///
/// [weight]:                               https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_weight
/// [tiebreaker]:                           https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#get_head
/// [`consensus-specs` pull request #3250]: https://github.com/ethereum/consensus-specs/pull/3250
pub type Score = (Gwei, Gwei, H256);

#[derive(Clone, Copy, Derivative)]
#[derivative(PartialEq, Eq, PartialOrd, Ord)]
pub struct DifferenceAtLocation {
    #[derivative(PartialEq = "ignore", PartialOrd = "ignore", Ord = "ignore")]
    pub differences: Differences,
    pub location: Location,
    #[derivative(PartialEq = "ignore", PartialOrd = "ignore", Ord = "ignore")]
    pub last_block_payload_presence: Option<PayloadPresence>,
}

impl DifferenceAtLocation {
    pub const fn apply_from_start(self) -> DissolvedDifference {
        DissolvedDifference {
            segment_id: self.location.segment_id,
            start: None,
            end: self.location.position,
            differences: self.differences,
            last_block_payload_presence: self.last_block_payload_presence,
        }
    }

    pub fn apply_after(self, position: Position) -> Result<DissolvedDifference> {
        Ok(DissolvedDifference {
            segment_id: self.location.segment_id,
            start: Some(position.next()?),
            end: self.location.position,
            differences: self.differences,
            last_block_payload_presence: self.last_block_payload_presence,
        })
    }
}

#[derive(Debug)]
pub struct DissolvedDifference {
    pub segment_id: SegmentId,
    pub start: Option<Position>,
    pub end: Position,
    pub differences: Differences,
    pub last_block_payload_presence: Option<PayloadPresence>,
}

#[derive(Derivative)]
#[derivative(PartialEq, Eq, PartialOrd, Ord)]
pub struct BranchPoint {
    pub parent: Location,
    #[derivative(PartialEq = "ignore", PartialOrd = "ignore", Ord = "ignore")]
    pub segment_id: SegmentId,
    #[derivative(PartialEq = "ignore", PartialOrd = "ignore", Ord = "ignore")]
    pub best_descendant: SegmentId,
}

/// [`LatestMessage`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#latestmessage)
pub struct LatestMessage {
    pub slot: Slot,
    // This is named differently than in `consensus-specs` to avoid confusion with FFG vote roots.
    // This is the LMD GHOST vote root and it corresponds to `AttestationData.beacon_block_root`.
    pub root: H256,
    pub payload_present: bool,
}

impl LatestMessage {
    pub fn post_gloas<P: Preset>(&self, chain_config: &ChainConfig) -> bool {
        chain_config.phase_at_slot::<P>(self.slot) >= Phase::Gloas
    }
}

#[derive(Error, Debug)]
pub enum AttestationValidationError<P: Preset, I> {
    #[error(
        "singular attestation published on incorrect subnet \
         (attestation: {attestation:?}, expected: {expected}, actual: {actual})"
    )]
    SingularAttestationOnIncorrectSubnet {
        attestation: Box<AttestationItem<P, I>>,
        expected: SubnetId,
        actual: SubnetId,
    },
    #[error("singular attestation has multiple aggregation bits set: {attestation:?}")]
    SingularAttestationHasMultipleAggregationBitsSet {
        attestation: Box<AttestationItem<P, I>>,
    },
    #[error("singular attestation validation error: {attestation:?} {source:}")]
    Other {
        source: AnyhowError,
        attestation: Box<AttestationItem<P, I>>,
    },
}

impl<P: Preset, I> AttestationValidationError<P, I> {
    #[must_use]
    pub fn attestation(self) -> AttestationItem<P, I> {
        match self {
            Self::SingularAttestationOnIncorrectSubnet { attestation, .. }
            | Self::SingularAttestationHasMultipleAggregationBitsSet { attestation }
            | Self::Other { attestation, .. } => *attestation,
        }
    }
}

#[derive(Error, Debug)]
pub enum PayloadAttestationValidationError<P: Preset> {
    #[error(
        "block payload attestation's slot is not for the previous slot \
            (state_slot: {in_state}, attestation_slot: {in_block}, payload_attestation: {payload_attestation:?})"
    )]
    BlockPayloadAttestationInvalidSlot {
        in_state: Slot,
        in_block: Slot,
        payload_attestation: Box<PayloadAttestationItem<P>>,
    },
    #[error(
        "block payload attestation's beacon block root is not parent block root \
            (parent_root: {parent_root}, attestation_block_root: {block_root}, payload_attestation: {payload_attestation:?})"
    )]
    BlockPayloadAttestationMismatchParentRoot {
        parent_root: H256,
        block_root: H256,
        payload_attestation: Box<PayloadAttestationItem<P>>,
    },
    #[error("payload attestation's block is invalid: {payload_attestation:?}")]
    PayloadAttestationInvalidBlock {
        payload_attestation: Box<PayloadAttestationItem<P>>,
    },
    #[error("payload attestation's block is pre-Gloas: {payload_attestation:?}")]
    PayloadAttestationForPreGloasBlock {
        payload_attestation: Box<PayloadAttestationItem<P>>,
    },
    #[error("payload attestation validation error: {payload_attestation:?} {source:}")]
    Other {
        source: AnyhowError,
        payload_attestation: Box<PayloadAttestationItem<P>>,
    },
}

impl<P: Preset> PayloadAttestationValidationError<P> {
    #[must_use]
    pub fn payload_attestation(self) -> PayloadAttestationItem<P> {
        match self {
            Self::BlockPayloadAttestationInvalidSlot {
                payload_attestation,
                ..
            }
            | Self::BlockPayloadAttestationMismatchParentRoot {
                payload_attestation,
                ..
            }
            | Self::PayloadAttestationInvalidBlock {
                payload_attestation,
            }
            | Self::PayloadAttestationForPreGloasBlock {
                payload_attestation,
            }
            | Self::Other {
                payload_attestation,
                ..
            } => *payload_attestation,
        }
    }
}

fn fmt_block_concisely(
    block: &SignedBeaconBlock<impl Preset>,
    formatter: &mut Formatter,
) -> FmtResult {
    formatter
        .debug_struct("SignedBeaconBlock")
        .field("phase", &block.phase())
        .field("slot", &block.message().slot())
        .field("parent_root", &block.message().parent_root())
        .field("state_root", &block.message().state_root())
        .finish_non_exhaustive()
}

fn fmt_as_wildcard<T>(_: T, formatter: &mut Formatter) -> FmtResult {
    formatter.write_str("_")
}

#[derive(Clone, Copy)]
pub enum DataAvailabilityPolicy {
    Check,
    Trust,
}

impl DataAvailabilityPolicy {
    #[must_use]
    pub const fn check(self) -> bool {
        matches!(self, Self::Check)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BlockTimeliness {
    pub before_attestation_due: bool,
    pub before_payload_attestation_due: bool,
}

pub trait Storage<P: Preset>: Sync + Sized {
    fn storage_mode(&self) -> StorageMode;

    fn stored_state_by_block_root(
        &self,
        block_root: H256,
        finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<Arc<BeaconState<P>>>>;
}
