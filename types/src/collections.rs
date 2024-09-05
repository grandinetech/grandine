//! Collections used in `BeaconState`.
//!
//! Persistent SSZ collections are optimized for fast state transitions and low memory usage when
//! multiple consecutive states exist. This comes at the cost of slower (de)serialization with both
//! Serde and SSZ. If there is a need for fast (de)serialization in the future, it could be achieved
//! by defining alternate `BeaconState` structs containing contiguous collections.
//!
//! All bundle sizes are currently set to minimize rehashing at the cost of higher memory usage.

use ssz::{PersistentList, PersistentVector, UnhashedBundleSize};

use crate::{
    altair::primitives::ParticipationFlags,
    capella::containers::HistoricalSummary,
    phase0::{
        containers::{Eth1Data, PendingAttestation, Validator},
        primitives::{Gwei, H256},
    },
    preset::{MaxAttestationsPerEpoch, Preset, SlotsPerEth1VotingPeriod, SlotsPerHistoricalRoot},
};

pub type RecentRoots<P> =
    PersistentVector<H256, SlotsPerHistoricalRoot<P>, UnhashedBundleSize<H256>>;

pub type HistoricalRoots<P> =
    PersistentList<H256, <P as Preset>::HistoricalRootsLimit, UnhashedBundleSize<H256>>;

pub type Eth1DataVotes<P> = PersistentList<Eth1Data, SlotsPerEth1VotingPeriod<P>>;

pub type Validators<P> = PersistentList<Validator, <P as Preset>::ValidatorRegistryLimit>;

pub type Balances<P> =
    PersistentList<Gwei, <P as Preset>::ValidatorRegistryLimit, UnhashedBundleSize<Gwei>>;

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

pub type InactivityScores<P> =
    PersistentList<u64, <P as Preset>::ValidatorRegistryLimit, UnhashedBundleSize<u64>>;

pub type HistoricalSummaries<P> =
    PersistentList<HistoricalSummary, <P as Preset>::HistoricalRootsLimit>;
