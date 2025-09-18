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

use bls::{AggregateSignatureBytes, SignatureBytes};
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
        PendingConsolidations, PendingDeposits, PendingPartialWithdrawals, ProposerLookahead,
        RandaoMixes, RecentRoots, Slashings, Validators,
    },
    combined::{
        Attestation as CombinedAtteststation, AttesterSlashing as CombinedAttesterSlashing,
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
    electra::{
        beacon_state::BeaconState as ElectraBeaconState,
        containers::{
            Attestation as ElectraAttestation, AttesterSlashing as ElectraAttesterSlashing,
            BeaconBlock as ElectraBeaconBlock, BeaconBlockBody as ElectraBeaconBlockBody,
            BlindedBeaconBlock as ElectraBlindedBeaconBlock,
            BlindedBeaconBlockBody as ElectraBlindedBeaconBlockBody, ExecutionRequests,
            IndexedAttestation as ElectraIndexedAttestation,
        },
    },
    fulu::{
        beacon_state::BeaconState as FuluBeaconState,
        containers::{
            BeaconBlock as FuluBeaconBlock, BeaconBlockBody as FuluBeaconBlockBody,
            BlindedBeaconBlock as FuluBlindedBeaconBlock,
            BlindedBeaconBlockBody as FuluBlindedBeaconBlockBody,
        },
    },
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        containers::{BeaconBlock as GloasBeaconBlock, BeaconBlockBody as GloasBeaconBlockBody},
    },
    nonstandard::Phase,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::JustificationBitsLength,
        containers::{
            Attestation as Phase0Attestation, AttestationData,
            AttesterSlashing as Phase0AttesterSlashing, BeaconBlock as Phase0BeaconBlock,
            BeaconBlockBody as Phase0BeaconBlockBody, BeaconBlockHeader, Checkpoint, Deposit,
            Eth1Data, Fork, IndexedAttestation as Phase0IndexedAttestation, ProposerSlashing,
            SignedVoluntaryExit,
        },
        primitives::{
            DepositIndex, Epoch, ExecutionBlockHash, ExecutionBlockNumber, Gwei, Slot, UnixSeconds,
            ValidatorIndex, H256,
        },
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

    fn post_fulu(&self) -> Option<&dyn PostFuluBeaconState<P>>;

    // TODO(feature/deneb): Try to come up with some other solution.
    //                      See the TODO in `types::combined`.
    fn is_post_deneb(&self) -> bool;
    fn is_post_electra(&self) -> bool;
    fn is_post_fulu(&self) -> bool;
    fn is_post_gloas(&self) -> bool;
}

#[duplicate_item(
    parameters
    implementor
    get_copy(field)
    get_ref(field)
    get_ref_mut(field, method)
    validators_mut_with_balances_body
    balances_mut_with_slashings_body
    post_fulu_body
    is_post_deneb_body
    is_post_electra_body
    is_post_fulu_body
    is_post_gloas_body;

    [P: Preset, S: BeaconState<P> + Clone]
    [Arc<S>]
    [self.as_ref().field()]
    [self.as_ref().field()]
    [self.make_mut().method()]
    [self.make_mut().validators_mut_with_balances()]
    [self.make_mut().balances_mut_with_slashings()]
    [self.as_ref().post_fulu()]
    [self.as_ref().is_post_deneb()]
    [self.as_ref().is_post_electra()]
    [self.as_ref().is_post_fulu()]
    [self.as_ref().is_post_gloas()];

    [P: Preset, S: BeaconState<P>]
    [Hc<S>]
    [self.as_ref().field()]
    [self.as_ref().field()]
    [self.as_mut().method()]
    [self.as_mut().validators_mut_with_balances()]
    [self.as_mut().balances_mut_with_slashings()]
    [self.as_ref().post_fulu()]
    [self.as_ref().is_post_deneb()]
    [self.as_ref().is_post_electra()]
    [self.as_ref().is_post_fulu()]
    [self.as_ref().is_post_gloas()];

    [P: Preset]
    [Phase0BeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [None]
    [false]
    [false]
    [false]
    [false];

    [P: Preset]
    [AltairBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [None]
    [false]
    [false]
    [false]
    [false];

    [P: Preset]
    [BellatrixBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [None]
    [false]
    [false]
    [false]
    [false];

    [P: Preset]
    [CapellaBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [None]
    [false]
    [false]
    [false]
    [false];

    [P: Preset]
    [DenebBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [None]
    [true]
    [false]
    [false]
    [false];

    [P: Preset]
    [ElectraBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [None]
    [true]
    [true]
    [false]
    [false];

    [P: Preset]
    [FuluBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [Some(self)]
    [true]
    [true]
    [true]
    [false];

    [P: Preset]
    [GloasBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field]
    [(&mut self.validators, &self.balances)]
    [(&mut self.balances, &self.slashings)]
    [Some(self)]
    [true]
    [true]
    [true]
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
            Self::Electra(state) => state.field,
            Self::Fulu(state) => state.field,
            Self::Gloas(state) => state.field,
        }
    ]
    [
        match self {
            Self::Phase0(state) => &state.field,
            Self::Altair(state) => &state.field,
            Self::Bellatrix(state) => &state.field,
            Self::Capella(state) => &state.field,
            Self::Deneb(state) => &state.field,
            Self::Electra(state) => &state.field,
            Self::Fulu(state) => &state.field,
            Self::Gloas(state) => &state.field,
        }
    ]
    [
        match self {
            Self::Phase0(state) => &mut state.field,
            Self::Altair(state) => &mut state.field,
            Self::Bellatrix(state) => &mut state.field,
            Self::Capella(state) => &mut state.field,
            Self::Deneb(state) => &mut state.field,
            Self::Electra(state) => &mut state.field,
            Self::Fulu(state) => &mut state.field,
            Self::Gloas(state) => &mut state.field,
        }
    ]
    [
        match self {
            Self::Phase0(state) => state.validators_mut_with_balances(),
            Self::Altair(state) => state.validators_mut_with_balances(),
            Self::Bellatrix(state) => state.validators_mut_with_balances(),
            Self::Capella(state) => state.validators_mut_with_balances(),
            Self::Deneb(state) => state.validators_mut_with_balances(),
            Self::Electra(state) => state.validators_mut_with_balances(),
            Self::Fulu(state) => state.validators_mut_with_balances(),
            Self::Gloas(state) => state.validators_mut_with_balances(),
        }
    ]
    [
        match self {
            Self::Phase0(state) => state.balances_mut_with_slashings(),
            Self::Altair(state) => state.balances_mut_with_slashings(),
            Self::Bellatrix(state) => state.balances_mut_with_slashings(),
            Self::Capella(state) => state.balances_mut_with_slashings(),
            Self::Deneb(state) => state.balances_mut_with_slashings(),
            Self::Electra(state) => state.balances_mut_with_slashings(),
            Self::Fulu(state) => state.balances_mut_with_slashings(),
            Self::Gloas(state) => state.balances_mut_with_slashings(),
        }
    ]
    [self.post_fulu()]
    [
        self.phase() >= Phase::Deneb
    ]
    [
        self.phase() >= Phase::Electra
    ]
    [
        self.phase() >= Phase::Fulu
    ]
    [
        self.phase() >= Phase::Gloas
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

    fn post_fulu(&self) -> Option<&dyn PostFuluBeaconState<P>> {
        post_fulu_body
    }

    fn is_post_deneb(&self) -> bool {
        is_post_deneb_body
    }

    fn is_post_electra(&self) -> bool {
        is_post_electra_body
    }

    fn is_post_fulu(&self) -> bool {
        is_post_fulu_body
    }

    fn is_post_gloas(&self) -> bool {
        is_post_gloas_body
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

    [P: Preset]
    [ElectraBeaconState<P>]
    [&self.field]
    [&mut self.field];

    [P: Preset]
    [FuluBeaconState<P>]
    [&self.field]
    [&mut self.field];

    [P: Preset]
    [GloasBeaconState<P>]
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

impl<P: Preset> PostBellatrixBeaconState<P> for ElectraBeaconState<P> {
    fn latest_execution_payload_header(&self) -> &dyn ExecutionPayload<P> {
        &self.latest_execution_payload_header
    }

    fn latest_execution_payload_header_mut(&mut self) -> &mut dyn ExecutionPayload<P> {
        &mut self.latest_execution_payload_header
    }
}

impl<P: Preset> PostBellatrixBeaconState<P> for FuluBeaconState<P> {
    fn latest_execution_payload_header(&self) -> &dyn ExecutionPayload<P> {
        &self.latest_execution_payload_header
    }

    fn latest_execution_payload_header_mut(&mut self) -> &mut dyn ExecutionPayload<P> {
        &mut self.latest_execution_payload_header
    }
}

impl<P: Preset> PostBellatrixBeaconState<P> for GloasBeaconState<P> {
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

impl<P: Preset> PostCapellaBeaconState<P> for ElectraBeaconState<P> {
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

impl<P: Preset> PostCapellaBeaconState<P> for FuluBeaconState<P> {
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

impl<P: Preset> PostCapellaBeaconState<P> for GloasBeaconState<P> {
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

pub trait PostElectraBeaconState<P: Preset>: PostCapellaBeaconState<P> {
    fn deposit_requests_start_index(&self) -> u64;
    fn deposit_balance_to_consume(&self) -> Gwei;
    fn exit_balance_to_consume(&self) -> Gwei;
    fn earliest_exit_epoch(&self) -> Epoch;
    fn consolidation_balance_to_consume(&self) -> Gwei;
    fn earliest_consolidation_epoch(&self) -> Epoch;
    fn pending_deposits(&self) -> &PendingDeposits<P>;
    fn pending_partial_withdrawals(&self) -> &PendingPartialWithdrawals<P>;
    fn pending_consolidations(&self) -> &PendingConsolidations<P>;

    fn deposit_requests_start_index_mut(&mut self) -> &mut u64;
    fn deposit_balance_to_consume_mut(&mut self) -> &mut Gwei;
    fn exit_balance_to_consume_mut(&mut self) -> &mut Gwei;
    fn earliest_exit_epoch_mut(&mut self) -> &mut Epoch;
    fn consolidation_balance_to_consume_mut(&mut self) -> &mut Gwei;
    fn earliest_consolidation_epoch_mut(&mut self) -> &mut Epoch;
    fn pending_deposits_mut(&mut self) -> &mut PendingDeposits<P>;
    fn pending_partial_withdrawals_mut(&mut self) -> &mut PendingPartialWithdrawals<P>;
    fn pending_consolidations_mut(&mut self) -> &mut PendingConsolidations<P>;
}

#[duplicate_item(
    parameters
    implementor
    get_copy(field)
    get_ref(field)
    get_ref_mut(field, method);

    [P: Preset, S: PostElectraBeaconState<P>]
    [Hc<S>]
    [self.as_ref().field()]
    [self.as_ref().field()]
    [self.as_mut().method()];

    [P: Preset]
    [ElectraBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field];

    [P: Preset]
    [FuluBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field];

    [P: Preset]
    [GloasBeaconState<P>]
    [self.field]
    [&self.field]
    [&mut self.field];
)]
impl<parameters> PostElectraBeaconState<P> for implementor {
    #[duplicate_item(
        field                              return_type;
        [deposit_requests_start_index]     [u64];
        [deposit_balance_to_consume]       [Gwei];
        [exit_balance_to_consume]          [Gwei];
        [earliest_exit_epoch]              [Epoch];
        [consolidation_balance_to_consume] [Gwei];
        [earliest_consolidation_epoch]     [Epoch];
    )]
    fn field(&self) -> return_type {
        get_copy([field])
    }

    #[duplicate_item(
        field                         return_type;
        [pending_deposits]            [PendingDeposits<P>];
        [pending_partial_withdrawals] [PendingPartialWithdrawals<P>];
        [pending_consolidations]      [PendingConsolidations<P>];
    )]
    fn field(&self) -> &return_type {
        get_ref([field])
    }

    #[duplicate_item(
        field                              method                                 return_type;
        [deposit_requests_start_index]     [deposit_requests_start_index_mut]     [u64];
        [deposit_balance_to_consume]       [deposit_balance_to_consume_mut]       [Gwei];
        [exit_balance_to_consume]          [exit_balance_to_consume_mut]          [Gwei];
        [earliest_exit_epoch]              [earliest_exit_epoch_mut]              [Epoch];
        [consolidation_balance_to_consume] [consolidation_balance_to_consume_mut] [Gwei];
        [earliest_consolidation_epoch]     [earliest_consolidation_epoch_mut]     [Epoch];
        [pending_deposits]                 [pending_deposits_mut]                 [PendingDeposits<P>];
        [pending_partial_withdrawals]      [pending_partial_withdrawals_mut]      [PendingPartialWithdrawals<P>];
        [pending_consolidations]           [pending_consolidations_mut]           [PendingConsolidations<P>];
    )]
    fn method(&mut self) -> &mut return_type {
        get_ref_mut([field], [method])
    }
}

pub trait PostFuluBeaconState<P: Preset>: PostElectraBeaconState<P> {
    fn proposer_lookahead(&self) -> &ProposerLookahead<P>;
    fn proposer_lookahead_mut(&mut self) -> &mut ProposerLookahead<P>;
}

impl<P: Preset, S: PostFuluBeaconState<P>> PostFuluBeaconState<P> for Hc<S> {
    fn proposer_lookahead(&self) -> &ProposerLookahead<P> {
        self.as_ref().proposer_lookahead()
    }

    fn proposer_lookahead_mut(&mut self) -> &mut ProposerLookahead<P> {
        self.as_mut().proposer_lookahead_mut()
    }
}

impl<P: Preset> PostFuluBeaconState<P> for FuluBeaconState<P> {
    fn proposer_lookahead(&self) -> &ProposerLookahead<P> {
        &self.proposer_lookahead
    }

    fn proposer_lookahead_mut(&mut self) -> &mut ProposerLookahead<P> {
        &mut self.proposer_lookahead
    }
}

impl<P: Preset> PostFuluBeaconState<P> for GloasBeaconState<P> {
    fn proposer_lookahead(&self) -> &ProposerLookahead<P> {
        &self.proposer_lookahead
    }

    fn proposer_lookahead_mut(&mut self) -> &mut ProposerLookahead<P> {
        &mut self.proposer_lookahead
    }
}

// TODO(gloas): PostGloasBeaconState trait for new added fields

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
            Self::Electra(block) => &block.message,
            Self::Fulu(block) => &block.message,
            Self::Gloas(block) => &block.message,
        }
    }

    fn signature(&self) -> SignatureBytes {
        match self {
            Self::Phase0(block) => block.signature,
            Self::Altair(block) => block.signature,
            Self::Bellatrix(block) => block.signature,
            Self::Capella(block) => block.signature,
            Self::Deneb(block) => block.signature,
            Self::Electra(block) => block.signature,
            Self::Fulu(block) => block.signature,
            Self::Gloas(block) => block.signature,
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
            Self::Electra(block) => &block.message,
            Self::Fulu(block) => &block.message,
        }
    }

    fn signature(&self) -> SignatureBytes {
        match self {
            Self::Bellatrix(block) => block.signature,
            Self::Capella(block) => block.signature,
            Self::Deneb(block) => block.signature,
            Self::Electra(block) => block.signature,
            Self::Fulu(block) => block.signature,
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
    [ElectraBeaconBlock<P>]          [self.field]    [&self.field];
    [FuluBeaconBlock<P>]             [self.field]    [&self.field];
    [GloasBeaconBlock<P>]            [self.field]    [&self.field];

    [BellatrixBlindedBeaconBlock<P>] [self.field]    [&self.field];
    [CapellaBlindedBeaconBlock<P>]   [self.field]    [&self.field];
    [DenebBlindedBeaconBlock<P>]     [self.field]    [&self.field];
    [ElectraBlindedBeaconBlock<P>]   [self.field]    [&self.field];
    [FuluBlindedBeaconBlock<P>]      [self.field]    [&self.field];

    [CombinedBeaconBlock<P>]
    [
        match self {
            Self::Phase0(block) => block.field,
            Self::Altair(block) => block.field,
            Self::Bellatrix(block) => block.field,
            Self::Capella(block) => block.field,
            Self::Deneb(block) => block.field,
            Self::Electra(block) => block.field,
            Self::Fulu(block) => block.field,
            Self::Gloas(block) => block.field,
        }
    ]
    [
        match self {
            Self::Phase0(block) => &block.field,
            Self::Altair(block) => &block.field,
            Self::Bellatrix(block) => &block.field,
            Self::Capella(block) => &block.field,
            Self::Deneb(block) => &block.field,
            Self::Electra(block) => &block.field,
            Self::Fulu(block) => &block.field,
            Self::Gloas(block) => &block.field,
        }
    ];

    [CombinedBlindedBeaconBlock<P>]
    [
        match self {
            Self::Bellatrix(block) => block.field,
            Self::Capella(block) => block.field,
            Self::Deneb(block) => block.field,
            Self::Electra(block) => block.field,
            Self::Fulu(block) => block.field,
        }
    ]
    [
        match self {
            Self::Bellatrix(block) => &block.field,
            Self::Capella(block) => &block.field,
            Self::Deneb(block) => &block.field,
            Self::Electra(block) => &block.field,
            Self::Fulu(block) => &block.field,
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
    fn deposits(&self) -> &ContiguousList<Deposit, P::MaxDeposits>;
    fn voluntary_exits(&self) -> &ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits>;

    fn attester_slashings_len(&self) -> usize;
    fn attester_slashings_root(&self) -> H256;
    fn attestations_len(&self) -> usize;
    fn attestations_root(&self) -> H256;

    fn pre_electra(&self) -> Option<&dyn PreElectraBeaconBlockBody<P>>;
    // TODO(gloas): fn pre_gloas()

    fn post_altair(&self) -> Option<&dyn PostAltairBeaconBlockBody<P>>;
    fn post_bellatrix(&self) -> Option<&dyn PostBellatrixBeaconBlockBody<P>>;
    fn post_deneb(&self) -> Option<&dyn PostDenebBeaconBlockBody<P>>;
    fn post_electra(&self) -> Option<&dyn PostElectraBeaconBlockBody<P>>;
    fn post_fulu(&self) -> Option<&dyn PostFuluBeaconBlockBody<P>>;
    // TODO(gloas): fn post_gloas()

    fn combined_attester_slashings(
        &self,
    ) -> Box<dyn Iterator<Item = CombinedAttesterSlashing<P>> + '_>;

    fn combined_attestations(&self) -> Box<dyn Iterator<Item = CombinedAtteststation<P>> + '_>;
}

// TODO(gloas): add `pre_gloas` and `post_gloas` columns
#[duplicate_item(
    implementor                          pre_electra_body post_altair_body post_bellatrix_body post_deneb_body post_electra_body post_fulu_body;

    [Phase0BeaconBlockBody<P>]           [Some(self)]     [None]           [None]              [None]          [None]            [None];
    [AltairBeaconBlockBody<P>]           [Some(self)]     [Some(self)]     [None]              [None]          [None]            [None];
    [BellatrixBeaconBlockBody<P>]        [Some(self)]     [Some(self)]     [Some(self)]        [None]          [None]            [None];
    [CapellaBeaconBlockBody<P>]          [Some(self)]     [Some(self)]     [Some(self)]        [None]          [None]            [None];
    [DenebBeaconBlockBody<P>]            [Some(self)]     [Some(self)]     [Some(self)]        [Some(self)]    [None]            [None];
    [ElectraBeaconBlockBody<P>]          [None]           [Some(self)]     [Some(self)]        [Some(self)]    [Some(self)]      [None];
    [FuluBeaconBlockBody<P>]             [None]           [Some(self)]     [Some(self)]        [Some(self)]    [Some(self)]      [Some(self)];
    [GloasBeaconBlockBody<P>]            [None]           [Some(self)]     [None]              [None]          [None]            [None];

    // `BlindedBeaconBlockBody` does not implement `PostBellatrixBeaconBlockBody`
    // because it does not have an `execution_payload` field.
    [BellatrixBlindedBeaconBlockBody<P>] [Some(self)]     [Some(self)]     [None]              [None]          [None]            [None];
    [CapellaBlindedBeaconBlockBody<P>]   [Some(self)]     [Some(self)]     [None]              [None]          [None]            [None];
    [DenebBlindedBeaconBlockBody<P>]     [Some(self)]     [Some(self)]     [None]              [Some(self)]    [None]            [None];
    [ElectraBlindedBeaconBlockBody<P>]   [None]           [Some(self)]     [None]              [Some(self)]    [Some(self)]      [None];
    [FuluBlindedBeaconBlockBody<P>]      [None]           [Some(self)]     [None]              [Some(self)]    [Some(self)]      [Some(self)];
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

    fn deposits(&self) -> &ContiguousList<Deposit, P::MaxDeposits> {
        &self.deposits
    }

    fn voluntary_exits(&self) -> &ContiguousList<SignedVoluntaryExit, P::MaxVoluntaryExits> {
        &self.voluntary_exits
    }

    fn attester_slashings_len(&self) -> usize {
        self.attester_slashings.len()
    }

    fn attester_slashings_root(&self) -> H256 {
        self.attester_slashings.hash_tree_root()
    }

    fn attestations_len(&self) -> usize {
        self.attestations.len()
    }

    fn attestations_root(&self) -> H256 {
        self.attestations.hash_tree_root()
    }

    fn pre_electra(&self) -> Option<&dyn PreElectraBeaconBlockBody<P>> {
        pre_electra_body
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

    fn post_electra(&self) -> Option<&dyn PostElectraBeaconBlockBody<P>> {
        post_electra_body
    }

    fn post_fulu(&self) -> Option<&dyn PostFuluBeaconBlockBody<P>> {
        post_fulu_body
    }

    fn combined_attester_slashings(
        &self,
    ) -> Box<dyn Iterator<Item = CombinedAttesterSlashing<P>> + '_> {
        Box::new(self.attester_slashings.iter().cloned().map(Into::into))
    }

    // TODO(feature/electra): avoid clone
    fn combined_attestations(&self) -> Box<dyn Iterator<Item = CombinedAtteststation<P>> + '_> {
        Box::new(self.attestations.iter().cloned().map(Into::into))
    }
}

pub trait PreElectraBeaconBlockBody<P: Preset>: BeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations>;
    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings>;
}

impl<P: Preset> PreElectraBeaconBlockBody<P> for Phase0BeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }
}

impl<P: Preset> PreElectraBeaconBlockBody<P> for AltairBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }
}

impl<P: Preset> PreElectraBeaconBlockBody<P> for BellatrixBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }
}

impl<P: Preset> PreElectraBeaconBlockBody<P> for CapellaBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }
}

impl<P: Preset> PreElectraBeaconBlockBody<P> for DenebBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }
}

impl<P: Preset> PreElectraBeaconBlockBody<P> for BellatrixBlindedBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }
}

impl<P: Preset> PreElectraBeaconBlockBody<P> for CapellaBlindedBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }
}

impl<P: Preset> PreElectraBeaconBlockBody<P> for DenebBlindedBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<Phase0Attestation<P>, P::MaxAttestations> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<Phase0AttesterSlashing<P>, P::MaxAttesterSlashings> {
        &self.attester_slashings
    }
}

// TODO(gloas): PreGloasBeaconBlockBody trait for those removing fields

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

impl<P: Preset> PostAltairBeaconBlockBody<P> for ElectraBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for FuluBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for GloasBeaconBlockBody<P> {
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

impl<P: Preset> PostAltairBeaconBlockBody<P> for ElectraBlindedBeaconBlockBody<P> {
    fn sync_aggregate(&self) -> SyncAggregate<P> {
        self.sync_aggregate
    }
}

impl<P: Preset> PostAltairBeaconBlockBody<P> for FuluBlindedBeaconBlockBody<P> {
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

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for ElectraBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P> {
        &self.execution_payload
    }
}

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for ElectraBlindedBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P> {
        &self.execution_payload_header
    }
}

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for FuluBeaconBlockBody<P> {
    fn execution_payload(&self) -> &dyn ExecutionPayload<P> {
        &self.execution_payload
    }
}

impl<P: Preset> PostBellatrixBeaconBlockBody<P> for FuluBlindedBeaconBlockBody<P> {
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

impl<P: Preset> PostCapellaBeaconBlockBody<P> for ElectraBeaconBlockBody<P> {
    fn bls_to_execution_changes(
        &self,
    ) -> &ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges> {
        &self.bls_to_execution_changes
    }
}

impl<P: Preset> PostCapellaBeaconBlockBody<P> for ElectraBlindedBeaconBlockBody<P> {
    fn bls_to_execution_changes(
        &self,
    ) -> &ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges> {
        &self.bls_to_execution_changes
    }
}

impl<P: Preset> PostCapellaBeaconBlockBody<P> for FuluBeaconBlockBody<P> {
    fn bls_to_execution_changes(
        &self,
    ) -> &ContiguousList<SignedBlsToExecutionChange, P::MaxBlsToExecutionChanges> {
        &self.bls_to_execution_changes
    }
}

impl<P: Preset> PostCapellaBeaconBlockBody<P> for FuluBlindedBeaconBlockBody<P> {
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

impl<P: Preset> PostDenebBeaconBlockBody<P> for ElectraBeaconBlockBody<P> {
    fn blob_kzg_commitments(
        &self,
    ) -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock> {
        &self.blob_kzg_commitments
    }
}

impl<P: Preset> PostDenebBeaconBlockBody<P> for ElectraBlindedBeaconBlockBody<P> {
    fn blob_kzg_commitments(
        &self,
    ) -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock> {
        &self.blob_kzg_commitments
    }
}

impl<P: Preset> PostDenebBeaconBlockBody<P> for FuluBeaconBlockBody<P> {
    fn blob_kzg_commitments(
        &self,
    ) -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock> {
        &self.blob_kzg_commitments
    }
}

impl<P: Preset> PostDenebBeaconBlockBody<P> for FuluBlindedBeaconBlockBody<P> {
    fn blob_kzg_commitments(
        &self,
    ) -> &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock> {
        &self.blob_kzg_commitments
    }
}

// TODO(gloas): move `execution_requests` into its own trait
pub trait PostElectraBeaconBlockBody<P: Preset>: PostDenebBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<ElectraAttestation<P>, P::MaxAttestationsElectra>;
    fn attester_slashings(
        &self,
    ) -> &ContiguousList<ElectraAttesterSlashing<P>, P::MaxAttesterSlashingsElectra>;
    fn execution_requests(&self) -> &ExecutionRequests<P>;
}

impl<P: Preset> PostElectraBeaconBlockBody<P> for ElectraBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<ElectraAttestation<P>, P::MaxAttestationsElectra> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<ElectraAttesterSlashing<P>, P::MaxAttesterSlashingsElectra> {
        &self.attester_slashings
    }

    fn execution_requests(&self) -> &ExecutionRequests<P> {
        &self.execution_requests
    }
}

impl<P: Preset> PostElectraBeaconBlockBody<P> for ElectraBlindedBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<ElectraAttestation<P>, P::MaxAttestationsElectra> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<ElectraAttesterSlashing<P>, P::MaxAttesterSlashingsElectra> {
        &self.attester_slashings
    }

    fn execution_requests(&self) -> &ExecutionRequests<P> {
        &self.execution_requests
    }
}

impl<P: Preset> PostElectraBeaconBlockBody<P> for FuluBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<ElectraAttestation<P>, P::MaxAttestationsElectra> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<ElectraAttesterSlashing<P>, P::MaxAttesterSlashingsElectra> {
        &self.attester_slashings
    }

    fn execution_requests(&self) -> &ExecutionRequests<P> {
        &self.execution_requests
    }
}

impl<P: Preset> PostElectraBeaconBlockBody<P> for FuluBlindedBeaconBlockBody<P> {
    fn attestations(&self) -> &ContiguousList<ElectraAttestation<P>, P::MaxAttestationsElectra> {
        &self.attestations
    }

    fn attester_slashings(
        &self,
    ) -> &ContiguousList<ElectraAttesterSlashing<P>, P::MaxAttesterSlashingsElectra> {
        &self.attester_slashings
    }

    fn execution_requests(&self) -> &ExecutionRequests<P> {
        &self.execution_requests
    }
}

pub trait PostFuluBeaconBlockBody<P: Preset>: PostElectraBeaconBlockBody<P> {}

impl<P: Preset> PostFuluBeaconBlockBody<P> for FuluBeaconBlockBody<P> {}

impl<P: Preset> PostFuluBeaconBlockBody<P> for FuluBlindedBeaconBlockBody<P> {}

// TODO(gloas): PostGloasBeaconBlockBody trait for those added fields and
// some fields from previous fork that still relevant in Gloas, derive from `PostAltairBeaconBlockBody`

pub trait ExecutionPayload<P: Preset>: SszHash<PackingFactor = U1> {
    fn block_hash(&self) -> ExecutionBlockHash;
    fn block_number(&self) -> ExecutionBlockNumber;
    fn parent_hash(&self) -> ExecutionBlockHash;

    fn is_default_payload(&self) -> bool;
    fn to_header(&self) -> CombinedExecutionPayloadHeader<P>;
}

impl<P: Preset> ExecutionPayload<P> for BellatrixExecutionPayload<P> {
    fn block_hash(&self) -> ExecutionBlockHash {
        self.block_hash
    }

    fn block_number(&self) -> ExecutionBlockNumber {
        self.block_number
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

    fn block_number(&self) -> ExecutionBlockNumber {
        self.block_number
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

    fn block_number(&self) -> ExecutionBlockNumber {
        self.block_number
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

    fn block_number(&self) -> ExecutionBlockNumber {
        self.block_number
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

    fn block_number(&self) -> ExecutionBlockNumber {
        self.block_number
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

    fn block_number(&self) -> ExecutionBlockNumber {
        self.block_number
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

pub trait Attestation<P: Preset> {
    fn data(&self) -> AttestationData;
    fn signature(&self) -> AggregateSignatureBytes;
}

impl<P: Preset> Attestation<P> for Phase0Attestation<P> {
    fn data(&self) -> AttestationData {
        self.data
    }

    fn signature(&self) -> AggregateSignatureBytes {
        self.signature
    }
}

impl<P: Preset> Attestation<P> for ElectraAttestation<P> {
    fn data(&self) -> AttestationData {
        self.data
    }

    fn signature(&self) -> AggregateSignatureBytes {
        self.signature
    }
}

pub trait AttesterSlashing<P: Preset> {
    fn attestation_1(&self) -> &impl IndexedAttestation<P>;
    fn attestation_2(&self) -> &impl IndexedAttestation<P>;
}

impl<P: Preset> AttesterSlashing<P> for Phase0AttesterSlashing<P> {
    fn attestation_1(&self) -> &impl IndexedAttestation<P> {
        &self.attestation_1
    }

    fn attestation_2(&self) -> &impl IndexedAttestation<P> {
        &self.attestation_2
    }
}

impl<P: Preset> AttesterSlashing<P> for ElectraAttesterSlashing<P> {
    fn attestation_1(&self) -> &impl IndexedAttestation<P> {
        &self.attestation_1
    }

    fn attestation_2(&self) -> &impl IndexedAttestation<P> {
        &self.attestation_2
    }
}

pub trait IndexedAttestation<P: Preset> {
    fn attesting_indices(&self) -> impl Iterator<Item = ValidatorIndex> + Send;
    fn data(&self) -> AttestationData;
    fn signature(&self) -> AggregateSignatureBytes;
}

impl<P: Preset> IndexedAttestation<P> for Phase0IndexedAttestation<P> {
    fn attesting_indices(&self) -> impl Iterator<Item = ValidatorIndex> + Send {
        self.attesting_indices.iter().copied()
    }

    fn data(&self) -> AttestationData {
        self.data
    }

    fn signature(&self) -> AggregateSignatureBytes {
        self.signature
    }
}

impl<P: Preset> IndexedAttestation<P> for ElectraIndexedAttestation<P> {
    fn attesting_indices(&self) -> impl Iterator<Item = ValidatorIndex> + Send {
        self.attesting_indices.iter().copied()
    }

    fn data(&self) -> AttestationData {
        self.data
    }

    fn signature(&self) -> AggregateSignatureBytes {
        self.signature
    }
}
