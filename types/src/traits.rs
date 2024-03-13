// TODO(Grandine Team): Consider adding associated types `BeaconBlock` and `SignedBeaconBlock` to
//                      `BeaconState` to enforce that state transitions are performed with the correct
//                      blocks.
// TODO(Grandine Team): Improve ergonomics.
//                      `&impl BeaconState<P>` would ideally be just `impl BeaconState`.
//
//                      Implementing traits for references would get rid of the `&`, but that forces
//                      functions that use `impl BeaconState` to borrow it when passing it elsewhere.
//                      Update the comment at the top of `ssz::traits` if needed.
// TODO(Grandine Team): GC unused impls for pointers.

use core::fmt::Debug;
use std::sync::Arc;

use bls::SignatureBytes;
use duplicate::duplicate_item;
use ssz::{BitVector, ContiguousList, Hc, SszHash};
use std_ext::{ArcExt as _, DefaultExt as _};
use typenum::U1;

use crate::{
    altair::{
        beacon_state::BeaconState as AltairBeaconState,
        containers::{
            BeaconBlock as AltairBeaconBlock, BeaconBlockBody as AltairBeaconBlockBody,
            SyncAggregate, SyncCommittee,
        },
    },
    bellatrix::{
        beacon_state::BeaconState as BellatrixBeaconState,
        containers::{
            BeaconBlock as BellatrixBeaconBlock, BeaconBlockBody as BellatrixBeaconBlockBody,
            BlindedBeaconBlock as BellatrixBlindedBeaconBlock,
            BlindedBeaconBlockBody as BellatrixBlindedBeaconBlockBody,
            ExecutionPayload as BellatrixExecutionPayload,
            ExecutionPayloadHeader as BellatrixExecutionPayloadHeader,
        },
    },
    cache::Cache,
    capella::{
        beacon_state::BeaconState as CapellaBeaconState,
        containers::{
            BeaconBlock as CapellaBeaconBlock, BeaconBlockBody as CapellaBeaconBlockBody,
            BlindedBeaconBlock as CapellaBlindedBeaconBlock,
            BlindedBeaconBlockBody as CapellaBlindedBeaconBlockBody,
            ExecutionPayload as CapellaExecutionPayload,
            ExecutionPayloadHeader as CapellaExecutionPayloadHeader, SignedBlsToExecutionChange,
            Withdrawal,
        },
        primitives::WithdrawalIndex,
    },
    collections::{
        Balances, EpochParticipation, Eth1DataVotes, HistoricalRoots, InactivityScores,
        RandaoMixes, RecentRoots, Slashings, Validators,
    },
    combined::{
        BeaconBlock as CombinedBeaconBlock, BeaconState as CombinedBeaconState,
        BlindedBeaconBlock as CombinedBlindedBeaconBlock,
        ExecutionPayloadHeader as CombinedExecutionPayloadHeader,
        SignedBeaconBlock as CombinedSignedBeaconBlock,
        SignedBlindedBeaconBlock as CombinedSignedBlindedBeaconBlock,
    },
    deneb::{
        beacon_state::BeaconState as DenebBeaconState,
        containers::{
            BeaconBlock as DenebBeaconBlock, BeaconBlockBody as DenebBeaconBlockBody,
            BlindedBeaconBlock as DenebBlindedBeaconBlock,
            BlindedBeaconBlockBody as DenebBlindedBeaconBlockBody,
            ExecutionPayload as DenebExecutionPayload,
            ExecutionPayloadHeader as DenebExecutionPayloadHeader,
        },
        primitives::KzgCommitment,
    },
    nonstandard::Phase,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::JustificationBitsLength,
        containers::{
            Attestation, AttesterSlashing, BeaconBlock as Phase0BeaconBlock,
            BeaconBlockBody as Phase0BeaconBlockBody, BeaconBlockHeader, Checkpoint, Deposit,
            Eth1Data, Fork, ProposerSlashing, SignedVoluntaryExit,
        },
        primitives::{DepositIndex, ExecutionBlockHash, Slot, UnixSeconds, ValidatorIndex, H256},
    },
    preset::Preset,
};

pub trait BeaconState<P: Preset>: SszHash<PackingFactor = U1> + Send + Sync {
    fn genesis_time(&self) -> UnixSeconds;
    fn genesis_validators_root(&self) -> H256;
    fn slot(&self) -> Slot;
    fn fork(&self) -> Fork;
    fn latest_block_header(&self) -> BeaconBlockHeader;
    fn block_roots(&self) -> &RecentRoots<P>;
    fn state_roots(&self) -> &RecentRoots<P>;
    fn historical_roots(&self) -> &HistoricalRoots<P>;
    fn eth1_data(&self) -> Eth1Data;
    fn eth1_data_votes(&self) -> &Eth1DataVotes<P>;
    fn eth1_deposit_index(&self) -> DepositIndex;
    fn validators(&self) -> &Validators<P>;
    fn balances(&self) -> &Balances<P>;
    fn randao_mixes(&self) -> &RandaoMixes<P>;
    fn slashings(&self) -> &Slashings<P>;
    fn justification_bits(&self) -> BitVector<JustificationBitsLength>;
    fn previous_justified_checkpoint(&self) -> Checkpoint;
    fn current_justified_checkpoint(&self) -> Checkpoint;
    fn finalized_checkpoint(&self) -> Checkpoint;
    fn cache(&self) -> &Cache;

    fn genesis_time_mut(&mut self) -> &mut UnixSeconds;
    fn genesis_validators_root_mut(&mut self) -> &mut H256;
    fn slot_mut(&mut self) -> &mut Slot;
    fn latest_block_header_mut(&mut self) -> &mut BeaconBlockHeader;
    fn block_roots_mut(&mut self) -> &mut RecentRoots<P>;
    fn state_roots_mut(&mut self) -> &mut RecentRoots<P>;
    fn historical_roots_mut(&mut self) -> &mut HistoricalRoots<P>;
    fn eth1_data_mut(&mut self) -> &mut Eth1Data;
    fn eth1_data_votes_mut(&mut self) -> &mut Eth1DataVotes<P>;
    fn eth1_deposit_index_mut(&mut self) -> &mut DepositIndex;
    fn validators_mut(&mut self) -> &mut Validators<P>;
    fn balances_mut(&mut self) -> &mut Balances<P>;
    fn randao_mixes_mut(&mut self) -> &mut RandaoMixes<P>;
    fn slashings_mut(&mut self) -> &mut Slashings<P>;
    fn justification_bits_mut(&mut self) -> &mut BitVector<JustificationBitsLength>;
    fn previous_justified_checkpoint_mut(&mut self) -> &mut Checkpoint;
    fn current_justified_checkpoint_mut(&mut self) -> &mut Checkpoint;
    fn finalized_checkpoint_mut(&mut self) -> &mut Checkpoint;
    fn cache_mut(&mut self) -> &mut Cache;

    // These are needed to split borrows in epoch processing.
    // A more general way to do this would be to return a struct containing references to all fields
    // in the state, but that would be unnecessarily verbose for our use case.
    fn validators_mut_with_balances(&mut self) -> (&mut Validators<P>, &Balances<P>);
    fn balances_mut_with_slashings(&mut self) -> (&mut Balances<P>, &Slashings<P>);

    // TODO(feature/deneb): Try to come up with some other solution.
    //                      See the TODO in `types::combined`.
    fn is_post_deneb(&self) -> bool;
}

#[duplicate_item(
    parameters
    implementor
    get_copy(field)
    get_ref(field)
    get_ref_mut(field, method)
    validators_mut_with_balances_body
    balances_mut_with_slashings_body
    is_post_deneb_body;

    [P: Preset, S: BeaconState<P> + Clone]
    [Arc<S>]
    [self.as_ref().field()]
    [self.as_ref().field()]
    [self.make_mut().method()]
    [self.make_mut().validators_mut_with_balances()]
    [self.make_mut().balances_mut_with_slashings()]
    [self.as_ref().is_post_deneb()];

    [P: Preset, S: BeaconState<P>]
    [Hc<S>]
    [self.as_ref().field()]
    [self.as_ref().field()]
    [self.as_mut().method()]
    [self.as_mut().validators_mut_with_balances()]
    [self.as_mut().balances_mut_with_slashings()]
    [self.as_ref().is_post_deneb()];

    [P: Preset]
    [Phase0BeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [false];

    [P: Preset]
    [AltairBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [false];

    [P: Preset]
    [BellatrixBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [false];

    [P: Preset]
    [CapellaBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [false];

    [P: Preset]
    [DenebBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [true];

    [P: Preset]
    [CombinedBeaconState<P>]
    [
        match self {
            Self::Phase0(state) => state.field,
            Self::Altair(state) => state.field,
            Self::Bellatrix(state) => state.field,
            Self::Capella(state) => state.field,
            Self::Deneb(state) => state.field,
        }
    ]
    [
        match self {
            Self::Phase0(state) => &state.field,
            Self::Altair(state) => &state.field,
            Self::Bellatrix(state) => &state.field,
            Self::Capella(state) => &state.field,
            Self::Deneb(state) => &state.field,
        }
    ]
    [
        match self {
            Self::Phase0(state) => &mut state.field,
            Self::Altair(state) => &mut state.field,
            Self::Bellatrix(state) => &mut state.field,
            Self::Capella(state) => &mut state.field,
            Self::Deneb(state) => &mut state.field,
        }
    ]
    [
        match self {
            Self::Phase0(state) => state.validators_mut_with_balances(),
            Self::Altair(state) => state.validators_mut_with_balances(),
            Self::Bellatrix(state) => state.validators_mut_with_balances(),
            Self::Capella(state) => state.validators_mut_with_balances(),
            Self::Deneb(state) => state.validators_mut_with_balances(),
        }
    ]
    [
        match self {
            Self::Phase0(state) => state.balances_mut_with_slashings(),
            Self::Altair(state) => state.balances_mut_with_slashings(),
            Self::Bellatrix(state) => state.balances_mut_with_slashings(),
            Self::Capella(state) => state.balances_mut_with_slashings(),
            Self::Deneb(state) => state.balances_mut_with_slashings(),
        }
    ]
    [
        self.phase() >= Phase::Deneb
    ];
)]
impl<parameters> BeaconState<P> for implementor {
    #[duplicate_item(
        field                           return_type;
        [genesis_time]                  [UnixSeconds];
        [genesis_validators_root]       [H256];
        [slot]                          [Slot];
        [fork]                          [Fork];
        [latest_block_header]           [BeaconBlockHeader];
        [eth1_data]                     [Eth1Data];
        [eth1_deposit_index]            [DepositIndex];
        [justification_bits]            [BitVector<JustificationBitsLength>];
        [previous_justified_checkpoint] [Checkpoint];
        [current_justified_checkpoint]  [Checkpoint];
        [finalized_checkpoint]          [Checkpoint];
    )]
    fn field(&self) -> return_type {
        get_copy([field])
    }

    #[duplicate_item(
        field              return_type;
        [block_roots]      [RecentRoots<P>];
        [state_roots]      [RecentRoots<P>];
        [historical_roots] [HistoricalRoots<P>];
        [eth1_data_votes]  [Eth1DataVotes<P>];
        [validators]       [Validators<P>];
        [balances]         [Balances<P>];
        [randao_mixes]     [RandaoMixes<P>];
        [slashings]        [Slashings<P>];
        [cache]            [Cache];
    )]
    fn field(&self) -> &return_type {
        get_ref([field])
    }

    #[duplicate_item(
        field                           method                              return_type;
        [genesis_time]                  [genesis_time_mut]                  [UnixSeconds];
        [genesis_validators_root]       [genesis_validators_root_mut]       [H256];
        [slot]                          [slot_mut]                          [Slot];
        [latest_block_header]           [latest_block_header_mut]           [BeaconBlockHeader];
        [block_roots]                   [block_roots_mut]                   [RecentRoots<P>];
        [state_roots]                   [state_roots_mut]                   [RecentRoots<P>];
        [historical_roots]              [historical_roots_mut]              [HistoricalRoots<P>];
        [eth1_data]                     [eth1_data_mut]                     [Eth1Data];
        [eth1_data_votes]               [eth1_data_votes_mut]               [Eth1DataVotes<P>];
        [eth1_deposit_index]            [eth1_deposit_index_mut]            [DepositIndex];
        [validators]                    [validators_mut]                    [Validators<P>];
        [balances]                      [balances_mut]                      [Balances<P>];
        [randao_mixes]                  [randao_mixes_mut]                  [RandaoMixes<P>];
        [slashings]                     [slashings_mut]                     [Slashings<P>];
        [justification_bits]            [justification_bits_mut]            [BitVector<JustificationBitsLength>];
        [previous_justified_checkpoint] [previous_justified_checkpoint_mut] [Checkpoint];
        [current_justified_checkpoint]  [current_justified_checkpoint_mut]  [Checkpoint];
        [finalized_checkpoint]          [finalized_checkpoint_mut]          [Checkpoint];
        [cache]                         [cache_mut]                         [Cache];
    )]
    fn method(&mut self) -> &mut return_type {
        get_ref_mut([field], [method])
    }

    fn validators_mut_with_balances(&mut self) -> (&mut Validators<P>, &Balances<P>) {
        validators_mut_with_balances_body
    }

    fn balances_mut_with_slashings(&mut self) -> (&mut Balances<P>, &Slashings<P>) {
        balances_mut_with_slashings_body
    }

    fn is_post_deneb(&self) -> bool {
        is_post_deneb_body
    }
}

pub trait PostAltairBeaconState<P: Preset>: BeaconState<P> {
    fn previous_epoch_participation(&self) -> &EpochParticipation<P>;
    fn current_epoch_participation(&self) -> &EpochParticipation<P>;
    fn current_sync_committee(&self) -> &Arc<Hc<SyncCommittee<P>>>;
    fn next_sync_committee(&self) -> &Arc<Hc<SyncCommittee<P>>>;

    fn previous_epoch_participation_mut(&mut self) -> &mut EpochParticipation<P>;
    fn current_epoch_participation_mut(&mut self) -> &mut EpochParticipation<P>;
    fn inactivity_scores_mut(&mut self) -> &mut InactivityScores<P>;
    fn current_sync_committee_mut(&mut self) -> &mut Arc<Hc<SyncCommittee<P>>>;
    fn next_sync_committee_mut(&mut self) -> &mut Arc<Hc<SyncCommittee<P>>>;
}

#[duplicate_item(
    parameters
    implementor
    get_ref(field)
    get_ref_mut(field, method);

    [P: Preset, S: PostAltairBeaconState<P>]
    [Hc<S>]
    [self.as_ref().field()]
    [self.as_mut().method()];

    [P: Preset]
    [AltairBeaconState<P>]
    [&self.field]
    [&mut self.field];

    [P: Preset]
    [BellatrixBeaconState<P>]
    [&self.field]
    [&mut self.field];

    [P: Preset]
    [CapellaBeaconState<P>]
    [&self.field]
    [&mut self.field];

    [P: Preset]
    [DenebBeaconState<P>]
    [&self.field]
    [&mut self.field];
)]
impl<parameters> PostAltairBeaconState<P> for implementor {
    #[duplicate_item(
        field                          return_type;
        [previous_epoch_participation] [EpochParticipation<P>];
        [current_epoch_participation]  [EpochParticipation<P>];
        [current_sync_committee]       [Arc<Hc<SyncCommittee<P>>>];
        [next_sync_committee]          [Arc<Hc<SyncCommittee<P>>>];
    )]
    fn field(&self) -> &return_type {
        get_ref([field])
    }

    #[duplicate_item(
        field                          method                             return_type;
        [previous_epoch_participation] [previous_epoch_participation_mut] [EpochParticipation<P>];
        [current_epoch_participation]  [current_epoch_participation_mut]  [EpochParticipation<P>];
        [inactivity_scores]            [inactivity_scores_mut]            [InactivityScores<P>];
        [current_sync_committee]       [current_sync_committee_mut]       [Arc<Hc<SyncCommittee<P>>>];
        [next_sync_committee]          [next_sync_committee_mut]          [Arc<Hc<SyncCommittee<P>>>]
    )]
    fn method(&mut self) -> &mut return_type {
        get_ref_mut([field], [method])
    }
}

pub trait PostBellatrixBeaconState<P: Preset>: PostAltairBeaconState<P> {
    fn latest_execution_payload_header(&self) -> &dyn ExecutionPayload<P>;
    fn latest_execution_payload_header_mut(&mut self) -> &mut dyn ExecutionPayload<P>;
}

impl<P: Preset, S: PostBellatrixBeaconState<P>> PostBellatrixBeaconState<P> for Hc<S> {
    fn latest_execution_payload_header(&self) -> &dyn ExecutionPayload<P> {
        self.as_ref().latest_execution_payload_header()
    }

    fn latest_execution_payload_header_mut(&mut self) -> &mut dyn ExecutionPayload<P> {
        self.as_mut().latest_execution_payload_header_mut()
    }
}

impl<P: Preset> PostBellatrixBeaconState<P> for BellatrixBeaconState<P> {
    fn latest_execution_payload_header(&self) -> &dyn ExecutionPayload<P> {
        &self.latest_execution_payload_header
    }

    fn latest_execution_payload_header_mut(&mut self) -> &mut dyn ExecutionPayload<P> {
        &mut self.latest_execution_payload_header
    }
}

impl<P: Preset> PostBellatrixBeaconState<P> for CapellaBeaconState<P> {
    fn latest_execution_payload_header(&self) -> &dyn ExecutionPayload<P> {
        &self.latest_execution_payload_header
    }

    fn latest_execution_payload_header_mut(&mut self) -> &mut dyn ExecutionPayload<P> {
        &mut self.latest_execution_payload_header
    }
}

impl<P: Preset> PostBellatrixBeaconState<P> for DenebBeaconState<P> {
    fn latest_execution_payload_header(&self) -> &dyn ExecutionPayload<P> {
        &self.latest_execution_payload_header
    }

    fn latest_execution_payload_header_mut(&mut self) -> &mut dyn ExecutionPayload<P> {
        &mut self.latest_execution_payload_header
    }
}

pub trait PostCapellaBeaconState<P: Preset>: PostBellatrixBeaconState<P> {
    fn next_withdrawal_index(&self) -> WithdrawalIndex;
    fn next_withdrawal_index_mut(&mut self) -> &mut WithdrawalIndex;

    fn next_withdrawal_validator_index(&self) -> ValidatorIndex;
    fn next_withdrawal_validator_index_mut(&mut self) -> &mut ValidatorIndex;
}

impl<P: Preset, S: PostCapellaBeaconState<P>> PostCapellaBeaconState<P> for Hc<S> {
    fn next_withdrawal_index(&self) -> WithdrawalIndex {
        self.as_ref().next_withdrawal_index()
    }

    fn next_withdrawal_index_mut(&mut self) -> &mut WithdrawalIndex {
        self.as_mut().next_withdrawal_index_mut()
    }

    fn next_withdrawal_validator_index(&self) -> ValidatorIndex {
        self.as_ref().next_withdrawal_validator_index()
    }

    fn next_withdrawal_validator_index_mut(&mut self) -> &mut ValidatorIndex {
        self.as_mut().next_withdrawal_validator_index_mut()
    }
}

impl<P: Preset> PostCapellaBeaconState<P> for CapellaBeaconState<P> {
    fn next_withdrawal_index(&self) -> WithdrawalIndex {
        self.next_withdrawal_index
    }

    fn next_withdrawal_index_mut(&mut self) -> &mut WithdrawalIndex {
        &mut self.next_withdrawal_index
    }

    fn next_withdrawal_validator_index(&self) -> ValidatorIndex {
        self.next_withdrawal_validator_index
    }

    fn next_withdrawal_validator_index_mut(&mut self) -> &mut ValidatorIndex {
        &mut self.next_withdrawal_validator_index
    }
}

impl<P: Preset> PostCapellaBeaconState<P> for DenebBeaconState<P> {
    fn next_withdrawal_index(&self) -> WithdrawalIndex {
        self.next_withdrawal_index
    }

    fn next_withdrawal_index_mut(&mut self) -> &mut WithdrawalIndex {
        &mut self.next_withdrawal_index
    }

    fn next_withdrawal_validator_index(&self) -> ValidatorIndex {
        self.next_withdrawal_validator_index
    }

    fn next_withdrawal_validator_index_mut(&mut self) -> &mut ValidatorIndex {
        &mut self.next_withdrawal_validator_index
    }
}

pub trait SignedBeaconBlock<P: Preset>: Debug + Send + Sync {
    type Message: BeaconBlock<P> + ?Sized;

    fn message(&self) -> &Self::Message;
    fn signature(&self) -> SignatureBytes;
}

impl<P: Preset, B: SignedBeaconBlock<P>> SignedBeaconBlock<P> for Arc<B> {
    type Message = B::Message;

    fn message(&self) -> &Self::Message {
        self.as_ref().message()
    }

    fn signature(&self) -> SignatureBytes {
        self.as_ref().signature()
    }
}

impl<P: Preset> SignedBeaconBlock<P> for CombinedSignedBeaconBlock<P> {
    type Message = dyn BeaconBlock<P>;

    fn message(&self) -> &Self::Message {
        match self {
            Self::Phase0(block) => &block.message,
            Self::Altair(block) => &block.message,
            Self::Bellatrix(block) => &block.message,
            Self::Capella(block) => &block.message,
            Self::Deneb(block) => &block.message,
        }
    }

    fn signature(&self) -> SignatureBytes {
        match self {
            Self::Phase0(block) => block.signature,
            Self::Altair(block) => block.signature,
            Self::Bellatrix(block) => block.signature,
            Self::Capella(block) => block.signature,
            Self::Deneb(block) => block.signature,
        }
    }
}

impl<P: Preset> SignedBeaconBlock<P> for CombinedSignedBlindedBeaconBlock<P> {
    type Message = dyn BeaconBlock<P>;

    fn message(&self) -> &Self::Message {
        match self {
            Self::Bellatrix(block) => &block.message,
            Self::Capella(block) => &block.message,
            Self::Deneb(block) => &block.message,
        }
    }

    fn signature(&self) -> SignatureBytes {
        match self {
            Self::Bellatrix(block) => block.signature,
            Self::Capella(block) => block.signature,
            Self::Deneb(block) => block.signature,
        }
    }
}

pub trait BeaconBlock<P: Preset>: SszHash<PackingFactor = U1> {
    fn slot(&self) -> Slot;
    fn proposer_index(&self) -> ValidatorIndex;
    fn parent_root(&self) -> H256;
    fn state_root(&self) -> H256;
    fn body(&self) -> &dyn BeaconBlockBody<P>;

    fn to_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot(),
            proposer_index: self.proposer_index(),
            parent_root: self.parent_root(),
            state_root: self.state_root(),
            body_root: self.body().hash_tree_root(),
        }
    }
}

#[duplicate_item(
    implementor                      get_copy(field) get_ref(field);

    [Phase0BeaconBlock<P>]           [self.field]    [&self.field];
    [AltairBeaconBlock<P>]           [self.field]    [&self.field];
    [BellatrixBeaconBlock<P>]        [self.field]    [&self.field];
    [CapellaBeaconBlock<P>]          [self.field]    [&self.field];
    [DenebBeaconBlock<P>]            [self.field]    [&self.field];

    [BellatrixBlindedBeaconBlock<P>] [self.field]    [&self.field];
    [CapellaBlindedBeaconBlock<P>]   [self.field]    [&self.field];
    [DenebBlindedBeaconBlock<P>]     [self.field]    [&self.field];

    [CombinedBeaconBlock<P>]
    [
        match self {
            Self::Phase0(block) => block.field,
            Self::Altair(block) => block.field,
            Self::Bellatrix(block) => block.field,
            Self::Capella(block) => block.field,
            Self::Deneb(block) => block.field,
        }
    ]
    [
        match self {
            Self::Phase0(block) => &block.field,
            Self::Altair(block) => &block.field,
            Self::Bellatrix(block) => &block.field,
            Self::Capella(block) => &block.field,
            Self::Deneb(block) => &block.field,
        }
    ];

    [CombinedBlindedBeaconBlock<P>]
    [
        match self {
            Self::Bellatrix(block) => block.field,
            Self::Capella(block) => block.field,
            Self::Deneb(block) => block.field,
        }
    ]
    [
        match self {
            Self::Bellatrix(block) => &block.field,
            Self::Capella(block) => &block.field,
            Self::Deneb(block) => &block.field,
        }
    ];
)]
impl<P: Preset> BeaconBlock<P> for implementor {
    fn slot(&self) -> Slot {
        get_copy([slot])
    }

    fn proposer_index(&self) -> ValidatorIndex {
        get_copy([proposer_index])
    }

    fn parent_root(&self) -> H256 {
        get_copy([parent_root])
    }

    fn state_root(&self) -> H256 {
        get_copy([state_root])
    }

    fn body(&self) -> &dyn BeaconBlockBody<P> {
        get_ref([body])
    }
}

pub trait BeaconBlockBody<P: Preset>: SszHash<PackingFactor = U1> {
    fn randao_reveal(&self) -> SignatureBytes;
    fn eth1_data(&self) -> Eth1Data;
    fn graffiti(&self) -> H256;
    fn proposer_slashings(&self) -> &ContiguousList<ProposerSlashing, P::MaxProposerSlashings>;
    fn attester_slashings(&self) -> &ContiguousList<AttesterSlashing<P>, P::MaxAttesterSlashings>;
    fn attestations(&self) -> &ContiguousList<Attestation<P>, P::MaxAttestations>;
    fn deposits(&self) -> &ContiguousList<Deposit, P::MaxDeposits>;
    fn voluntary_exits(&self) -> &ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits>;

    fn post_altair(&self) -> Option<&dyn PostAltairBeaconBlockBody<P>>;
    fn post_bellatrix(&self) -> Option<&dyn PostBellatrixBeaconBlockBody<P>>;
    fn post_deneb(&self) -> Option<&dyn PostDenebBeaconBlockBody<P>>;
}

#[duplicate_item(
    implementor                          post_altair_body post_bellatrix_body post_deneb_body;

    [Phase0BeaconBlockBody<P>]           [None]           [None]              [None];
    [AltairBeaconBlockBody<P>]           [Some(self)]     [None]              [None];
    [BellatrixBeaconBlockBody<P>]        [Some(self)]     [Some(self)]        [None];
    [CapellaBeaconBlockBody<P>]          [Some(self)]     [Some(self)]        [None];
    [DenebBeaconBlockBody<P>]            [Some(self)]     [Some(self)]        [Some(self)];

    // `BlindedBeaconBlockBody` does not implement `PostBellatrixBeaconBlockBody`
    // because it does not have an `execution_payload` field.
    [BellatrixBlindedBeaconBlockBody<P>] [Some(self)]     [None]              [None];
    [CapellaBlindedBeaconBlockBody<P>]   [Some(self)]     [None]              [None];
    [DenebBlindedBeaconBlockBody<P>]     [Some(self)]     [None]              [Some(self)];
)]
impl<P: Preset> BeaconBlockBody<P> for implementor {
    fn randao_reveal(&self) -> SignatureBytes {
        self.randao_reveal
    }

    fn eth1_data(&self) -> Eth1Data {
        self.eth1_data
    }

    fn graffiti(&self) -> H256 {
        self.graffiti
    }

    fn proposer_slashings(&self) -> &ContiguousList<ProposerSlashing, P::MaxProposerSlashings> {
        &self.proposer_slashings
    }

    fn attester_slashings(&self) -> &ContiguousList<AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }

    fn attestations(&self) -> &ContiguousList<Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn deposits(&self) -> &ContiguousList<Deposit, P::MaxDeposits> {
        &self.deposits
    }

    fn voluntary_exits(&self) -> &ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits> {
        &self.voluntary_exits
    }

    fn post_altair(&self) -> Option<&dyn PostAltairBeaconBlockBody<P>> {
        post_altair_body
    }

    fn post_bellatrix(&self) -> Option<&dyn PostBellatrixBeaconBlockBody<P>> {
        post_bellatrix_body
    }

    fn post_deneb(&self) -> Option<&dyn PostDenebBeaconBlockBody<P>> {
        post_deneb_body
    }
}

pub trait PostAltairBeaconBlockBody<P: Preset>: BeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P>;
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for AltairBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for BellatrixBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for CapellaBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for DenebBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for BellatrixBlindedBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for CapellaBlindedBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for DenebBlindedBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

pub trait PostBellatrixBeaconBlockBody<P: Preset>: PostAltairBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P>;
}

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for BellatrixBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P> {
        &self.execution_payload
    }
}

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for CapellaBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P> {
        &self.execution_payload
    }
}

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for CapellaBlindedBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P> {
        &self.execution_payload_header
    }
}

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for DenebBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P> {
        &self.execution_payload
    }
}

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for DenebBlindedBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P> {
        &self.execution_payload_header
    }
}

pub trait PostCapellaBeaconBlockBody<P: Preset>: PostBellatrixBeaconBlockBody<P> {
    fn bls_to_execution_changes(
        &self,
    ) -> &ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges>;
}

impl<P: Preset> PostCapellaBeaconBlockBody<P> for CapellaBeaconBlockBody<P> {
    fn bls_to_execution_changes(
        &self,
    ) -> &ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges> {
        &self.bls_to_execution_changes
    }
}

impl<P: Preset> PostCapellaBeaconBlockBody<P> for CapellaBlindedBeaconBlockBody<P> {
    fn bls_to_execution_changes(
        &self,
    ) -> &ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges> {
        &self.bls_to_execution_changes
    }
}

impl<P: Preset> PostCapellaBeaconBlockBody<P> for DenebBeaconBlockBody<P> {
    fn bls_to_execution_changes(
        &self,
    ) -> &ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges> {
        &self.bls_to_execution_changes
    }
}

impl<P: Preset> PostCapellaBeaconBlockBody<P> for DenebBlindedBeaconBlockBody<P> {
    fn bls_to_execution_changes(
        &self,
    ) -> &ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges> {
        &self.bls_to_execution_changes
    }
}

pub trait PostDenebBeaconBlockBody<P: Preset>: PostCapellaBeaconBlockBody<P> {
    // TODO(feature/deneb): method for state is_post_deneb
    fn blob_kzg_commitments(&self)
        -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>;
}

impl<P: Preset> PostDenebBeaconBlockBody<P> for DenebBeaconBlockBody<P> {
    fn blob_kzg_commitments(
        &self,
    ) -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock> {
        &self.blob_kzg_commitments
    }
}

impl<P: Preset> PostDenebBeaconBlockBody<P> for DenebBlindedBeaconBlockBody<P> {
    fn blob_kzg_commitments(
        &self,
    ) -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock> {
        &self.blob_kzg_commitments
    }
}

pub trait ExecutionPayload<P: Preset>: SszHash<PackingFactor = U1> {
    fn block_hash(&self) -> ExecutionBlockHash;
    fn parent_hash(&self) -> ExecutionBlockHash;

    fn is_default_payload(&self) -> bool;
    fn to_header(&self) -> CombinedExecutionPayloadHeader<P>;
}

impl<P: Preset> ExecutionPayload<P> for BellatrixExecutionPayload<P> {
    fn block_hash(&self) -> ExecutionBlockHash {
        self.block_hash
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.parent_hash
    }

    fn is_default_payload(&self) -> bool {
        self.is_default()
    }

    fn to_header(&self) -> CombinedExecutionPayloadHeader<P> {
        BellatrixExecutionPayloadHeader::from(self).into()
    }
}

impl<P: Preset> ExecutionPayload<P> for BellatrixExecutionPayloadHeader<P> {
    fn block_hash(&self) -> ExecutionBlockHash {
        self.block_hash
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.parent_hash
    }

    fn is_default_payload(&self) -> bool {
        self.is_default()
    }

    fn to_header(&self) -> CombinedExecutionPayloadHeader<P> {
        self.clone().into()
    }
}

impl<P: Preset> ExecutionPayload<P> for CapellaExecutionPayload<P> {
    fn block_hash(&self) -> ExecutionBlockHash {
        self.block_hash
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.parent_hash
    }

    fn is_default_payload(&self) -> bool {
        self.is_default()
    }

    fn to_header(&self) -> CombinedExecutionPayloadHeader<P> {
        CapellaExecutionPayloadHeader::from(self).into()
    }
}

impl<P: Preset> ExecutionPayload<P> for CapellaExecutionPayloadHeader<P> {
    fn block_hash(&self) -> ExecutionBlockHash {
        self.block_hash
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.parent_hash
    }

    fn is_default_payload(&self) -> bool {
        self.is_default()
    }

    fn to_header(&self) -> CombinedExecutionPayloadHeader<P> {
        self.clone().into()
    }
}

impl<P: Preset> ExecutionPayload<P> for DenebExecutionPayload<P> {
    fn block_hash(&self) -> ExecutionBlockHash {
        self.block_hash
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.parent_hash
    }

    fn is_default_payload(&self) -> bool {
        self.is_default()
    }

    fn to_header(&self) -> CombinedExecutionPayloadHeader<P> {
        DenebExecutionPayloadHeader::from(self).into()
    }
}

impl<P: Preset> ExecutionPayload<P> for DenebExecutionPayloadHeader<P> {
    fn block_hash(&self) -> ExecutionBlockHash {
        self.block_hash
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.parent_hash
    }

    fn is_default_payload(&self) -> bool {
        self.is_default()
    }

    fn to_header(&self) -> CombinedExecutionPayloadHeader<P> {
        self.clone().into()
    }
}

pub trait PostCapellaExecutionPayload<P: Preset>: ExecutionPayload<P> {
    fn withdrawals(&self) -> &ContiguousList<Withdrawal, P::MaxWithdrawalsPerPayload>;
}

impl<P: Preset> PostCapellaExecutionPayload<P> for CapellaExecutionPayload<P> {
    fn withdrawals(&self) -> &ContiguousList<Withdrawal, P::MaxWithdrawalsPerPayload> {
        &self.withdrawals
    }
}

impl<P: Preset> PostCapellaExecutionPayload<P> for DenebExecutionPayload<P> {
    fn withdrawals(&self) -> &ContiguousList<Withdrawal, P::MaxWithdrawalsPerPayload> {
        &self.withdrawals
    }
}

pub trait PostCapellaExecutionPayloadHeader<P: Preset>: ExecutionPayload<P> {
    fn withdrawals_root(&self) -> H256;
}

impl<P: Preset> PostCapellaExecutionPayloadHeader<P> for CapellaExecutionPayloadHeader<P> {
    fn withdrawals_root(&self) -> H256 {
        self.withdrawals_root
    }
}

impl<P: Preset> PostCapellaExecutionPayloadHeader<P> for DenebExecutionPayloadHeader<P> {
    fn withdrawals_root(&self) -> H256 {
        self.withdrawals_root
    }
}
