use anyhow::Result;
use bls::{CachedPublicKey, SecretKey, Signature, SignatureBytes};
use derive_more::From;
use ssz::{Ssz, SszHash};
use types::{
    altair::{
        consts::{
            DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SYNC_COMMITTEE,
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        },
        containers::{
            BeaconBlock as AltairBeaconBlock, ContributionAndProof, SyncAggregatorSelectionData,
        },
    },
    bellatrix::containers::BeaconBlock as BellatrixBeaconBlock,
    capella::{
        consts::DOMAIN_BLS_TO_EXECUTION_CHANGE,
        containers::{BeaconBlock as CapellaBeaconBlock, BlsToExecutionChange},
    },
    combined::{
        AggregateAndProof as CombinedAggregateAndProof, BeaconBlock as CombinedBeaconBlock,
        BlindedBeaconBlock,
    },
    config::Config,
    deneb::containers::BeaconBlock as DenebBeaconBlock,
    electra::{
        consts::DOMAIN_CONSOLIDATION,
        containers::{
            AggregateAndProof as ElectraAggregateAndProof, BeaconBlock as ElectraBeaconBlock,
            Consolidation,
        },
    },
    phase0::{
        consts::{
            DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
            DOMAIN_DEPOSIT, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
        },
        containers::{
            AggregateAndProof as Phase0AggregateAndProof, AttestationData,
            BeaconBlock as Phase0BeaconBlock, BeaconBlockHeader, DepositMessage, VoluntaryExit,
        },
        primitives::{DomainType, Epoch, Slot, H256},
    },
    preset::Preset,
    traits::{BeaconBlock, BeaconState},
};

use crate::{
    accessors,
    error::SignatureKind,
    misc,
    verifier::{SingleVerifier, Verifier as _},
};

// This wrapper is needed to differentiate between `Epoch` and `Slot`.
// They are aliased to the same type and thus cannot have different trait implementations.
#[derive(From, Ssz)]
#[ssz(
    derive_read = false,
    derive_size = false,
    derive_write = false,
    transparent
)]
pub struct RandaoEpoch(Epoch);

pub trait SignForAllForks: SszHash {
    const DOMAIN_TYPE: DomainType;
    const SIGNATURE_KIND: SignatureKind;

    fn signing_root(&self, config: &Config) -> H256 {
        let domain = misc::compute_domain(config, Self::DOMAIN_TYPE, None, None);
        misc::compute_signing_root(self, domain)
    }

    fn sign(&self, config: &Config, secret_key: &SecretKey) -> Signature {
        secret_key.sign(self.signing_root(config))
    }

    fn verify(
        &self,
        config: &Config,
        signature_bytes: SignatureBytes,
        cached_public_key: &CachedPublicKey,
    ) -> Result<()> {
        SingleVerifier.verify_singular(
            self.signing_root(config),
            signature_bytes,
            cached_public_key,
            Self::SIGNATURE_KIND,
        )
    }
}

pub trait SignForAllForksWithGenesis<P: Preset>: SszHash {
    const DOMAIN_TYPE: DomainType;
    const SIGNATURE_KIND: SignatureKind;

    fn signing_root(&self, config: &Config, beacon_state: &(impl BeaconState<P> + ?Sized)) -> H256 {
        let genesis_validators_root = Some(beacon_state.genesis_validators_root());
        let domain = misc::compute_domain(config, Self::DOMAIN_TYPE, None, genesis_validators_root);
        misc::compute_signing_root(self, domain)
    }

    fn sign(
        &self,
        config: &Config,
        beacon_state: &impl BeaconState<P>,
        secret_key: &SecretKey,
    ) -> Signature {
        secret_key.sign(self.signing_root(config, beacon_state))
    }

    fn verify(
        &self,
        config: &Config,
        beacon_state: &(impl BeaconState<P> + ?Sized),
        signature_bytes: SignatureBytes,
        cached_public_key: &CachedPublicKey,
    ) -> Result<()> {
        SingleVerifier.verify_singular(
            self.signing_root(config, beacon_state),
            signature_bytes,
            cached_public_key,
            Self::SIGNATURE_KIND,
        )
    }
}

pub trait SignForSingleFork<P: Preset>: SszHash {
    const DOMAIN_TYPE: DomainType;
    const SIGNATURE_KIND: SignatureKind;

    fn epoch(&self) -> Epoch;

    fn signing_root(&self, config: &Config, beacon_state: &(impl BeaconState<P> + ?Sized)) -> H256 {
        let epoch = Some(self.epoch());
        let domain = accessors::get_domain(config, beacon_state, Self::DOMAIN_TYPE, epoch);
        misc::compute_signing_root(self, domain)
    }

    fn sign(
        &self,
        config: &Config,
        beacon_state: &impl BeaconState<P>,
        secret_key: &SecretKey,
    ) -> Signature {
        secret_key.sign(self.signing_root(config, beacon_state))
    }

    fn verify(
        &self,
        config: &Config,
        beacon_state: &(impl BeaconState<P> + ?Sized),
        signature_bytes: SignatureBytes,
        cached_public_key: &CachedPublicKey,
    ) -> Result<()> {
        SingleVerifier.verify_singular(
            self.signing_root(config, beacon_state),
            signature_bytes,
            cached_public_key,
            Self::SIGNATURE_KIND,
        )
    }
}

pub trait SignForSingleForkAtSlot<P: Preset>: SszHash {
    const DOMAIN_TYPE: DomainType;
    const SIGNATURE_KIND: SignatureKind;

    fn signing_root(
        &self,
        config: &Config,
        beacon_state: &(impl BeaconState<P> + ?Sized),
        slot: Slot,
    ) -> H256 {
        let epoch = misc::compute_epoch_at_slot::<P>(slot);
        let domain = accessors::get_domain(config, beacon_state, Self::DOMAIN_TYPE, Some(epoch));
        misc::compute_signing_root(self, domain)
    }

    fn sign(
        &self,
        config: &Config,
        beacon_state: &impl BeaconState<P>,
        slot: Slot,
        secret_key: &SecretKey,
    ) -> Signature {
        secret_key.sign(self.signing_root(config, beacon_state, slot))
    }

    fn verify(
        &self,
        config: &Config,
        beacon_state: &(impl BeaconState<P> + ?Sized),
        slot: Slot,
        signature_bytes: SignatureBytes,
        cached_public_key: &CachedPublicKey,
    ) -> Result<()> {
        SingleVerifier.verify_singular(
            self.signing_root(config, beacon_state, slot),
            signature_bytes,
            cached_public_key,
            Self::SIGNATURE_KIND,
        )
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#submit-deposit>
impl SignForAllForks for DepositMessage {
    const DOMAIN_TYPE: DomainType = DOMAIN_DEPOSIT;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Deposit;
}

/// <https://github.com/ethereum/consensus-specs/blob/0f2d25d919bf19d3421df791533d553af679a54f/specs/capella/beacon-chain.md#new-process_bls_to_execution_change>
impl<P: Preset> SignForAllForksWithGenesis<P> for BlsToExecutionChange {
    const DOMAIN_TYPE: DomainType = DOMAIN_BLS_TO_EXECUTION_CHANGE;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::BlsToExecutionChange;
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa01/specs/phase0/validator.md#broadcast-aggregate>
impl<P: Preset> SignForSingleFork<P> for Phase0AggregateAndProof<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_AGGREGATE_AND_PROOF;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::AggregateAndProof;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.aggregate.data.slot)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa01/specs/phase0/validator.md#broadcast-aggregate>
impl<P: Preset> SignForSingleFork<P> for ElectraAggregateAndProof<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_AGGREGATE_AND_PROOF;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::AggregateAndProof;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.aggregate.data.slot)
    }
}

impl<P: Preset> SignForSingleFork<P> for CombinedAggregateAndProof<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_AGGREGATE_AND_PROOF;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::AggregateAndProof;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot())
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#aggregate-signature>
impl<P: Preset> SignForSingleFork<P> for AttestationData {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_ATTESTER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Attestation;

    fn epoch(&self) -> Epoch {
        self.target.epoch
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#signature>
impl<P: Preset> SignForSingleFork<P> for Phase0BeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#signature>
impl<P: Preset> SignForSingleFork<P> for AltairBeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#signature>
impl<P: Preset> SignForSingleFork<P> for BellatrixBeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#signature>
impl<P: Preset> SignForSingleFork<P> for CapellaBeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#signature>
impl<P: Preset> SignForSingleFork<P> for DenebBeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#signature>
impl<P: Preset> SignForSingleFork<P> for ElectraBeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }
}

impl<P: Preset> SignForSingleFork<P> for CombinedBeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot())
    }
}

impl<P: Preset> SignForSingleFork<P> for dyn BeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot())
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#signature>
impl<P: Preset> SignForSingleFork<P> for BeaconBlockHeader {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }
}

impl<P: Preset> SignForSingleFork<P> for BlindedBeaconBlock<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BEACON_PROPOSER;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Block;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot())
    }
}

// <https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.1/specs/electra/beacon-chain.md#new-process_consolidation>
impl<P: Preset> SignForAllForksWithGenesis<P> for Consolidation {
    const DOMAIN_TYPE: DomainType = DOMAIN_CONSOLIDATION;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Consolidation;
}

/// <https://github.com/ethereum/consensus-specs/blob/v1.1.1/specs/altair/validator.md#broadcast-sync-committee-contribution>
impl<P: Preset> SignForSingleFork<P> for ContributionAndProof<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_CONTRIBUTION_AND_PROOF;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::ContributionAndProof;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.contribution.slot)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#randao-reveal>
impl<P: Preset> SignForSingleFork<P> for RandaoEpoch {
    const DOMAIN_TYPE: DomainType = DOMAIN_RANDAO;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::Randao;

    fn epoch(&self) -> Epoch {
        self.0
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/99934ee16c7e990c8c39bc66e1aa58845057faa0/specs/phase0/validator.md#aggregation-selection>
impl<P: Preset> SignForSingleFork<P> for Slot {
    const DOMAIN_TYPE: DomainType = DOMAIN_SELECTION_PROOF;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::SelectionProof;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(*self)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/v1.1.1/specs/altair/validator.md#aggregation-selection>
impl<P: Preset> SignForSingleFork<P> for SyncAggregatorSelectionData {
    const DOMAIN_TYPE: DomainType = DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::SyncCommitteeSelectionProof;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }
}

// TODO(feature/deneb): Consider duplicating `process_voluntary_exit` for Deneb.
//                      The fork version check in this impl will break starting with the next phase.
impl<P: Preset> SignForSingleFork<P> for VoluntaryExit {
    const DOMAIN_TYPE: DomainType = DOMAIN_VOLUNTARY_EXIT;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::VoluntaryExit;

    fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn signing_root(&self, config: &Config, beacon_state: &(impl BeaconState<P> + ?Sized)) -> H256 {
        let domain_type = <Self as SignForSingleFork<P>>::DOMAIN_TYPE;
        let current_fork_version = beacon_state.fork().current_version;

        let domain = if current_fork_version == config.deneb_fork_version
            || current_fork_version == config.electra_fork_version
        {
            let fork_version = Some(config.capella_fork_version);
            let genesis_validators_root = Some(beacon_state.genesis_validators_root());
            misc::compute_domain(config, domain_type, fork_version, genesis_validators_root)
        } else {
            let epoch = <Self as SignForSingleFork<P>>::epoch(self);
            accessors::get_domain(config, beacon_state, domain_type, Some(epoch))
        };

        misc::compute_signing_root(self, domain)
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/ac911558acb9e4f1a1e7274a520c6182b1fe2146/specs/altair/beacon-chain.md#sync-aggregate-processing>
impl<P: Preset> SignForSingleForkAtSlot<P> for H256 {
    const DOMAIN_TYPE: DomainType = DOMAIN_SYNC_COMMITTEE;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::SyncCommitteeMessage;
}
