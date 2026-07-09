//! Collections used in `BeaconState`.
//!
//! Persistent SSZ collections are optimized for fast state transitions and low memory usage when
//! multiple consecutive states exist. This comes at the cost of slower (de)serialization with both
//! Serde and SSZ. If there is a need for fast (de)serialization in the future, it could be achieved
//! by defining alternate `BeaconState` structs containing contiguous collections.
//!
//! All bundle sizes are currently set to minimize rehashing at the cost of higher memory usage.

use std::collections::HashMap;

use bls::SignatureBytes;
use ssz::{
    ContiguousVector, IncompletePersistentVector, PersistentList, PersistentProgressiveList,
    PersistentVector, UnhashedBundleSize,
};

use crate::{
    altair::primitives::ParticipationFlags,
    capella::containers::{HistoricalSummary, Withdrawal},
    electra::containers::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
    gloas::containers::{Builder, BuilderPendingPayment, BuilderPendingWithdrawal},
    phase0::{
        containers::{DepositMessage, Eth1Data, PendingAttestation, Validator},
        primitives::{Gwei, H256, ValidatorIndex},
    },
    preset::{
        BuilderPendingPaymentsLength, MaxAttestationsPerEpoch, Preset, ProposerLookaheadLength,
        PtcWindowLength, SlotsPerEth1VotingPeriod, SlotsPerHistoricalRoot,
    },
};

pub type RecentRoots<P> =
    PersistentVector<H256, SlotsPerHistoricalRoot<P>, UnhashedBundleSize<H256>>;

pub type HistoricalRoots<P> =
    PersistentList<H256, <P as Preset>::HistoricalRootsLimit, UnhashedBundleSize<H256>>;

pub type Eth1DataVotes<P> = PersistentList<Eth1Data, SlotsPerEth1VotingPeriod<P>>;

pub type Validators<P> = PersistentList<Validator, <P as Preset>::ValidatorRegistryLimit>;

// Progressive counterparts of collections whose SSZ type changes to `ProgressiveList` in Gloas
// (EIP-7688). Pre-Gloas forks keep the bounded `PersistentList` versions above.
pub type ProgressiveValidators<P> =
    PersistentProgressiveList<Validator, <P as Preset>::ValidatorRegistryLimit>;

pub type Balances<P> =
    PersistentList<Gwei, <P as Preset>::ValidatorRegistryLimit, UnhashedBundleSize<Gwei>>;

pub type ProgressiveBalances<P> =
    PersistentProgressiveList<Gwei, <P as Preset>::ValidatorRegistryLimit>;

pub type RandaoMixes<P> =
    PersistentVector<H256, <P as Preset>::EpochsPerHistoricalVector, UnhashedBundleSize<H256>>;

pub type Slashings<P> =
    PersistentVector<Gwei, <P as Preset>::EpochsPerSlashingsVector, UnhashedBundleSize<Gwei>>;

pub type Attestations<P> = PersistentList<PendingAttestation<P>, MaxAttestationsPerEpoch<P>>;

pub type EpochParticipation<P> = PersistentList<
    ParticipationFlags,
    <P as Preset>::ValidatorRegistryLimit,
    UnhashedBundleSize<ParticipationFlags>,
>;

pub type ProgressiveEpochParticipation<P> =
    PersistentProgressiveList<ParticipationFlags, <P as Preset>::ValidatorRegistryLimit>;

pub type InactivityScores<P> =
    PersistentList<u64, <P as Preset>::ValidatorRegistryLimit, UnhashedBundleSize<u64>>;

pub type ProgressiveInactivityScores<P> =
    PersistentProgressiveList<u64, <P as Preset>::ValidatorRegistryLimit>;

pub type HistoricalSummaries<P> =
    PersistentList<HistoricalSummary, <P as Preset>::HistoricalRootsLimit>;

pub type PendingDeposits<P> = PersistentList<PendingDeposit, <P as Preset>::PendingDepositsLimit>;

pub type ProgressivePendingDeposits<P> =
    PersistentProgressiveList<PendingDeposit, <P as Preset>::PendingDepositsLimit>;

pub type PendingPartialWithdrawals<P> =
    PersistentList<PendingPartialWithdrawal, <P as Preset>::PendingPartialWithdrawalsLimit>;

pub type ProgressivePendingPartialWithdrawals<P> = PersistentProgressiveList<
    PendingPartialWithdrawal,
    <P as Preset>::PendingPartialWithdrawalsLimit,
>;

pub type PendingConsolidations<P> =
    PersistentList<PendingConsolidation, <P as Preset>::PendingConsolidationsLimit>;

pub type ProgressivePendingConsolidations<P> =
    PersistentProgressiveList<PendingConsolidation, <P as Preset>::PendingConsolidationsLimit>;

pub type ProposerLookahead<P> = PersistentVector<
    ValidatorIndex,
    ProposerLookaheadLength<P>,
    UnhashedBundleSize<ValidatorIndex>,
>;

pub type Builders<P> = PersistentProgressiveList<Builder, <P as Preset>::BuilderRegistryLimit>;

pub type BuilderPendingPayments<P> = PersistentVector<
    BuilderPendingPayment,
    BuilderPendingPaymentsLength<P>,
    UnhashedBundleSize<BuilderPendingPayment>,
>;

pub type BuilderPendingWithdrawals<P> = PersistentProgressiveList<
    BuilderPendingWithdrawal,
    <P as Preset>::BuilderPendingWithdrawalsLimit,
>;

pub type DepositSignatureCache = HashMap<(DepositMessage, SignatureBytes), bool>;

pub type PayloadExpectedWithdrawals<P> =
    PersistentProgressiveList<Withdrawal, <P as Preset>::MaxWithdrawalsPerPayload>;

pub type Ptc<P> = ContiguousVector<ValidatorIndex, <P as Preset>::PtcSize>;

pub type PtcWindow<P> =
    IncompletePersistentVector<Ptc<P>, PtcWindowLength<P>, UnhashedBundleSize<Ptc<P>>>;
