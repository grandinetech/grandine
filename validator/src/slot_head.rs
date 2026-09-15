use core::{fmt::Debug, marker::PhantomData};
use std::sync::Arc;

use anyhow::Result;
use bls::{PublicKeyBytes, SignatureBytes};
use eth1_api::ApiController;
use fork_choice_control::Wait;
use futures::lock::Mutex;
use helper_functions::{
    accessors, misc, predicates,
    signing::{SignForSingleFork, SignForSingleForkAtSlot},
};
use itertools::Itertools as _;
use logging::warn_with_peers;
use signer::{Signer, SigningMessage, SigningTriple};
use slashing_protection::SlashingProtector;
use tap::Pipe as _;
use types::{
    altair::{
        containers::{SyncAggregatorSelectionData, SyncCommitteeMessage},
        primitives::SubcommitteeIndex,
    },
    combined::BeaconState,
    config::Config,
    nonstandard::{ForkInfo, Phase},
    phase0::primitives::{Epoch, H256, Slot, ValidatorIndex},
    preset::Preset,
};

#[derive(Clone)]
pub struct SlotHead<P: Preset> {
    pub config: Arc<Config>,
    pub slot: Slot,
    pub beacon_block_root: H256,
    /// All of a state that signing needs, so that it does not depend on holding one.
    pub fork_info: ForkInfo,
    pub optimistic: bool,
    /// The preset the slot's epoch and phase are computed with; no field depends on it.
    pub phantom: PhantomData<P>,
}

impl<P: Preset> SlotHead<P> {
    #[must_use]
    pub fn from_state(
        config: Arc<Config>,
        slot: Slot,
        beacon_block_root: H256,
        state: &BeaconState<P>,
        optimistic: bool,
    ) -> Self {
        Self {
            config,
            slot,
            beacon_block_root,
            fork_info: ForkInfo::from_state(state),
            optimistic,
            phantom: PhantomData,
        }
    }

    #[must_use]
    pub const fn slot(&self) -> Slot {
        self.slot
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        self.config.phase_at_slot::<P>(self.slot)
    }

    #[must_use]
    pub fn current_epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }

    pub fn proposer_index(&self, beacon_state: &BeaconState<P>) -> Result<ValidatorIndex> {
        accessors::get_beacon_proposer_index(&self.config, beacon_state)
    }

    pub fn next_proposer_index(&self, beacon_state: &BeaconState<P>) -> Result<ValidatorIndex> {
        accessors::get_beacon_proposer_index_at_slot(
            &self.config,
            beacon_state,
            self.slot().saturating_add(1),
        )
    }

    #[must_use]
    pub fn has_sync_committee(&self) -> bool {
        self.phase() >= Phase::Altair
    }

    pub fn is_optimistic<W: Wait>(&self, controller: &ApiController<P, W>) -> Result<bool> {
        if !self.optimistic {
            return Ok(false);
        }

        controller
            .block_by_root(self.beacon_block_root)?
            .is_none_or(|block| block.status.is_optimistic())
            .pipe(Ok)
    }

    /// <https://github.com/ethereum/consensus-specs/blob/dc14b79a521fb621f0d2b9da9410f6e7ffaa7df5/specs/altair/validator.md#prepare-sync-committee-message>
    pub async fn sync_committee_messages<I>(
        &self,
        slot: Slot,
        beacon_block_root: H256,
        validator_indices_with_pubkeys: I,
        signer: &Signer,
    ) -> Result<Vec<SyncCommitteeMessage>>
    where
        I: IntoIterator<Item = (ValidatorIndex, PublicKeyBytes)> + Send,
    {
        // The head of the node the duty is performed against, not necessarily `self`'s.
        let (triples, validator_indices): (Vec<_>, Vec<_>) = validator_indices_with_pubkeys
            .into_iter()
            .map(|(validator_index, public_key)| {
                let triple = SigningTriple::<P> {
                    message: SigningMessage::SyncCommitteeMessage {
                        beacon_block_root,
                        slot,
                    },
                    signing_root: SignForSingleForkAtSlot::<P>::signing_root_from_fork_info(
                        &beacon_block_root,
                        &self.config,
                        self.fork_info,
                        self.slot(),
                    ),
                    public_key,
                };

                (triple, validator_index)
            })
            .unzip();

        let signer_snapshot = signer.load();

        let messages = signer_snapshot
            .sign_triples_without_slashing_protection(triples, Some(self.fork_info))
            .await?
            .zip(validator_indices)
            .map(move |(signature, validator_index)| SyncCommitteeMessage {
                slot,
                beacon_block_root,
                validator_index,
                signature: signature.into(),
            })
            .collect();

        Ok(messages)
    }

    /// <https://github.com/ethereum/consensus-specs/blob/dc14b79a521fb621f0d2b9da9410f6e7ffaa7df5/specs/altair/validator.md#aggregation-selection>
    pub async fn sync_committee_selection_proofs(
        &self,
        subcommittee_indices_with_pubkeys: impl Iterator<Item = (SubcommitteeIndex, PublicKeyBytes)>
        + Send,
        signer: &Signer,
    ) -> Result<Vec<Option<SignatureBytes>>> {
        let triples = subcommittee_indices_with_pubkeys.map(|(subcommittee_index, public_key)| {
            let selection_data = SyncAggregatorSelectionData {
                slot: self.slot(),
                subcommittee_index,
            };

            SigningTriple::<P> {
                message: SigningMessage::SyncAggregatorSelectionData(selection_data),
                signing_root: SignForSingleFork::<P>::signing_root_from_fork_info(
                    &selection_data,
                    &self.config,
                    self.fork_info,
                ),
                public_key,
            }
        });

        signer
            .load()
            .sign_triples_without_slashing_protection(triples, Some(self.fork_info))
            .await?
            .map(|signature| {
                let selection_proof = signature.into();
                let aggregator = predicates::is_sync_committee_aggregator::<P>(selection_proof);
                Ok(aggregator.then_some(selection_proof))
            })
            .collect()
    }

    pub async fn sign_beacon_block(
        &self,
        signer: &Signer,
        block: &(impl SignForSingleFork<P> + Debug + Send + Sync),
        message: SigningMessage<'_, P>,
        public_key: PublicKeyBytes,
        slashing_protector: Arc<Mutex<SlashingProtector>>,
    ) -> Option<SignatureBytes> {
        match signer
            .load()
            .sign_triples(
                core::iter::once(SigningTriple {
                    message,
                    signing_root: block.signing_root_from_fork_info(&self.config, self.fork_info),
                    public_key,
                }),
                self.fork_info,
                self.current_epoch(),
                slashing_protector,
            )
            .await
        {
            Ok(signatures) => match signatures.into_iter().exactly_one() {
                Ok(signature_option) => match signature_option {
                    Some(signature) => Some(signature.into()),
                    None => {
                        warn_with_peers!(
                            "failed to sign beacon block due to slashing protection \
                                (block: {block:?}, public_key: {public_key:?})",
                        );
                        None
                    }
                },
                Err(_) => {
                    warn_with_peers!(
                        "Slashing protection returned iterator with different number of elements",
                    );
                    None
                }
            },
            Err(error) => {
                warn_with_peers!(
                    "error while signing beacon block \
                     (error: {error:?}, block: {block:?}, public_key: {public_key:?})",
                );
                None
            }
        }
    }
}
