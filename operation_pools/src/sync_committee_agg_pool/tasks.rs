use std::sync::Arc;

use anyhow::{ensure, Result};
use eth1_api::ApiController;
use fork_choice_control::Wait;
use futures::channel::mpsc::UnboundedSender;
use helper_functions::{
    accessors,
    error::SignatureKind,
    misc, predicates,
    signing::{SignForSingleFork as _, SignForSingleForkAtSlot as _},
    verifier::{MultiVerifier, Verifier as _},
};
use tracing::{debug, warn};
use prometheus_metrics::Metrics;
use typenum::Unsigned as _;
use types::{
    altair::{
        consts::SyncCommitteeSubnetCount,
        containers::{
            SignedContributionAndProof, SyncAggregatorSelectionData, SyncCommitteeContribution,
            SyncCommitteeMessage,
        },
    },
    combined::BeaconState,
    config::Config,
    nonstandard::ValidationOutcome,
    phase0::primitives::{Slot, SubnetId, ValidatorIndex},
    preset::Preset,
    traits::BeaconState as _,
};

use crate::{
    messages::{PoolToLivenessMessage, PoolToP2pMessage},
    misc::{Origin, PoolRejectionReason, PoolTask},
    sync_committee_agg_pool::{pool::Pool, types::ContributionData},
};

pub struct AddOwnContributionTask<P: Preset> {
    pub pool: Arc<Pool<P>>,
    pub aggregator_index: ValidatorIndex,
    pub contribution: SyncCommitteeContribution<P>,
    pub beacon_state: Arc<BeaconState<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset> PoolTask for AddOwnContributionTask<P> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            aggregator_index,
            contribution,
            beacon_state,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.sync_pool_add_own_contribution_times.start_timer());

        if let Err(error) = pool
            .add_sync_committee_contribution(aggregator_index, contribution, &beacon_state)
            .await
        {
            warn!(
                "failed to add own contribution to sync committee pool ({error}, contribution: {contribution:?}",
            );
        }

        Ok(())
    }
}

pub struct AggregateOwnMessagesTask<P: Preset, W> {
    pub wait_group: W,
    pub pool: Arc<Pool<P>>,
    pub contribution_data: ContributionData,
    pub messages: Vec<SyncCommitteeMessage>,
    pub beacon_state: Arc<BeaconState<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Send + 'static> PoolTask for AggregateOwnMessagesTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            wait_group,
            pool,
            contribution_data,
            messages,
            beacon_state,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.sync_pool_aggregate_own_messages_times.start_timer());

        if let Err(error) = pool
            .aggregate_messages(contribution_data, messages.iter().copied(), &beacon_state)
            .await
        {
            warn!(
                "failed to aggregate subcommittee {} sync committee messages: {error}",
                contribution_data.subcommittee_index,
            );
        }

        pool.add_sync_committee_messages(contribution_data, messages)
            .await;

        drop(wait_group);

        Ok(())
    }
}

pub struct HandleExternalContributionTask<P: Preset, W: Wait> {
    pub controller: ApiController<P, W>,
    pub pool: Arc<Pool<P>>,
    pub signed_contribution_and_proof: SignedContributionAndProof<P>,
    pub origin: Origin,
    pub pool_to_p2p_tx: UnboundedSender<PoolToP2pMessage>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> PoolTask for HandleExternalContributionTask<P, W> {
    type Output = ValidationOutcome;

    async fn run(self) -> Result<Self::Output> {
        let result = self.handle_external_contribution().await;

        let Self {
            signed_contribution_and_proof,
            origin,
            metrics,
            ref pool_to_p2p_tx,
            ..
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .sync_pool_handle_external_contribution_times
                .start_timer()
        });

        if let Origin::Gossip(gossip_id) = origin {
            let message = match &result {
                Ok(ValidationOutcome::Accept) => PoolToP2pMessage::Accept(gossip_id),
                Ok(ValidationOutcome::Ignore(_)) => PoolToP2pMessage::Ignore(gossip_id),
                Err(error) => {
                    debug!(
                        "gossip contribution and proof rejected \
                        (error: {error}, contribution and proof: {signed_contribution_and_proof:?})",
                    );
                    PoolToP2pMessage::Reject(
                        gossip_id,
                        PoolRejectionReason::InvalidContributionAndProof,
                    )
                }
            };

            message.send(pool_to_p2p_tx);
        }

        result
    }
}

impl<P: Preset, W: Wait> HandleExternalContributionTask<P, W> {
    async fn handle_external_contribution(&self) -> Result<ValidationOutcome> {
        let Self {
            ref controller,
            ref pool,
            signed_contribution_and_proof,
            ..
        } = *self;

        let contribution_and_proof = signed_contribution_and_proof.message;

        if pool.is_subset(contribution_and_proof.contribution).await {
            debug!(
                "sync committee contribution is a known subset: {signed_contribution_and_proof:?}"
            );

            return Ok(ValidationOutcome::Ignore(false));
        }

        let already_exists = pool
            .contribution_and_proof_exists(contribution_and_proof)
            .await;

        if already_exists {
            return Ok(ValidationOutcome::Ignore(false));
        }

        let beacon_state = controller.preprocessed_state_at_current_slot()?;

        let is_valid = validate_external_contribution_and_proof(
            controller.chain_config(),
            signed_contribution_and_proof,
            &beacon_state,
        )?;

        if is_valid {
            pool.add_sync_committee_contribution(
                contribution_and_proof.aggregator_index,
                contribution_and_proof.contribution,
                &beacon_state,
            )
            .await?;
            Ok(ValidationOutcome::Accept)
        } else {
            Ok(ValidationOutcome::Ignore(false))
        }
    }
}

pub struct HandleExternalMessageTask<P: Preset, W: Wait> {
    pub controller: ApiController<P, W>,
    pub pool: Arc<Pool<P>>,
    pub message: SyncCommitteeMessage,
    pub subnet_id: SubnetId,
    pub origin: Origin,
    pub pool_to_p2p_tx: UnboundedSender<PoolToP2pMessage>,
    pub pool_to_liveness_tx: Option<UnboundedSender<PoolToLivenessMessage>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> PoolTask for HandleExternalMessageTask<P, W> {
    type Output = ValidationOutcome;

    async fn run(self) -> Result<Self::Output> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            metrics
                .sync_pool_handle_external_message_times
                .start_timer()
        });

        let result = self.handle_external_message().await;

        let Self {
            message,
            subnet_id,
            origin,
            ref pool_to_liveness_tx,
            ref pool_to_p2p_tx,
            ..
        } = self;

        if let Origin::Gossip(gossip_id) = origin {
            let message = match &result {
                Ok(ValidationOutcome::Accept) => {
                    if let Some(pool_to_liveness_tx) = pool_to_liveness_tx {
                        PoolToLivenessMessage::SyncCommitteeMessage(message)
                            .send(pool_to_liveness_tx);
                    }

                    PoolToP2pMessage::Accept(gossip_id)
                }
                Ok(ValidationOutcome::Ignore(_)) => PoolToP2pMessage::Ignore(gossip_id),
                Err(error) => {
                    debug!(
                        "gossip sync committee message rejected \
                         (error: {error}, message: {message:?}, subnet_id: {subnet_id})",
                    );
                    PoolToP2pMessage::Reject(
                        gossip_id,
                        PoolRejectionReason::InvalidSyncCommitteeMessage,
                    )
                }
            };

            message.send(pool_to_p2p_tx);
        }

        result
    }
}

impl<P: Preset, W: Wait> HandleExternalMessageTask<P, W> {
    async fn handle_external_message(&self) -> Result<ValidationOutcome> {
        let Self {
            ref controller,
            ref pool,
            message,
            subnet_id,
            ..
        } = *self;

        let contribution_data = ContributionData::from_message(message, subnet_id);

        let already_exists = pool
            .sync_committee_message_exists(contribution_data, message)
            .await;

        if already_exists {
            return Ok(ValidationOutcome::Ignore(false));
        }

        let beacon_state = controller.preprocessed_state_at_current_slot()?;

        let is_valid = validate_external_message(
            controller.chain_config(),
            message,
            subnet_id,
            &beacon_state,
        )?;

        if is_valid {
            pool.add_sync_committee_messages(contribution_data, vec![message])
                .await;
            pool.aggregate_messages(contribution_data, vec![message], &beacon_state)
                .await?;
            Ok(ValidationOutcome::Accept)
        } else {
            Ok(ValidationOutcome::Ignore(false))
        }
    }
}

pub struct HandleSlotTask<P: Preset> {
    pub pool: Arc<Pool<P>>,
    pub slot: Slot,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset> PoolTask for HandleSlotTask<P> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            slot,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.sync_pool_handle_slot_times.start_timer());

        pool.on_slot(slot, metrics).await;

        Ok(())
    }
}

fn validate_external_contribution_and_proof<P: Preset>(
    config: &Config,
    signed_contribution_and_proof: SignedContributionAndProof<P>,
    beacon_state: &BeaconState<P>,
) -> Result<bool> {
    if signed_contribution_and_proof.message.contribution.slot != beacon_state.slot() {
        return Ok(false);
    }

    let Some(state) = beacon_state.post_altair() else {
        // Publishing sync committee contributions in Phase 0 is unusual but allowed.
        // It may be done in the last slot of Phase 0.
        // The Altair Honest Validator specification says it's not expected (i.e., optional).
        warn!(
            "sync committee contribution received during a Phase 0 slot \
             (signed_contribution_and_proof: {:?}, slot: {})",
            signed_contribution_and_proof,
            beacon_state.slot(),
        );

        return Ok(false);
    };

    let contribution_and_proof = signed_contribution_and_proof.message;
    let contribution = contribution_and_proof.contribution;

    ensure!(
        contribution.subcommittee_index < SyncCommitteeSubnetCount::U64,
        "subcommittee index is not in allowed range",
    );

    ensure!(
        contribution.aggregation_bits.any(),
        "contribution does not have participants",
    );

    ensure!(
        predicates::is_sync_committee_aggregator::<P>(contribution_and_proof.selection_proof),
        "validator is not an aggregator for the slot",
    );

    let aggregator_index = contribution_and_proof.aggregator_index;
    let aggregator = state.validators().get(aggregator_index)?;
    let subcommittee_pubkeys =
        accessors::get_sync_subcommittee_pubkeys(state, contribution.subcommittee_index)?;

    ensure!(
        subcommittee_pubkeys.contains(&aggregator.pubkey),
        "aggregator is not in the declared subcommittee",
    );

    let mut verifier = MultiVerifier::default();

    verifier.verify_singular(
        SyncAggregatorSelectionData {
            slot: contribution.slot,
            subcommittee_index: contribution.subcommittee_index,
        }
        .signing_root(config, beacon_state),
        contribution_and_proof.selection_proof,
        &aggregator.pubkey,
        SignatureKind::SyncCommitteeSelectionProof,
    )?;

    verifier.verify_singular(
        contribution_and_proof.signing_root(config, beacon_state),
        signed_contribution_and_proof.signature,
        &aggregator.pubkey,
        SignatureKind::ContributionAndProof,
    )?;

    let participant_pubkeys = subcommittee_pubkeys
        .iter()
        .zip(contribution.aggregation_bits)
        .filter(|(_, bit)| *bit)
        .map(|(pubkey, _)| pubkey.decompress());

    let signing_root =
        contribution
            .beacon_block_root
            .signing_root(config, state, contribution.slot);

    itertools::process_results(participant_pubkeys, |public_keys| {
        verifier.verify_aggregate(
            signing_root,
            contribution.signature,
            public_keys,
            SignatureKind::SyncCommitteeContribution,
        )
    })??;

    verifier.finish()?;

    Ok(true)
}

fn validate_external_message<P: Preset>(
    config: &Config,
    message: SyncCommitteeMessage,
    subnet_id: SubnetId,
    beacon_state: &BeaconState<P>,
) -> Result<bool> {
    if message.slot != beacon_state.slot() {
        return Ok(false);
    }

    let Some(state) = beacon_state.post_altair() else {
        // Publishing sync committee messages in Phase 0 is unusual but allowed.
        // It may be done in the last slot of Phase 0.
        // The Altair Honest Validator specification says it's not expected (i.e., optional).
        warn!(
            "sync committee message received during a Phase 0 slot \
             (message: {message:?}, slot: {})",
            beacon_state.slot(),
        );

        return Ok(false);
    };

    let validator_index = message.validator_index;
    let subnets = misc::compute_subnets_for_sync_committee(state, validator_index)?;

    ensure!(
        subnets.get(subnet_id.try_into()?).unwrap_or_default(),
        "subnet ID is invalid",
    );

    let validator_pubkey = &state.validators().get(validator_index)?.pubkey;

    message.beacon_block_root.verify(
        config,
        state,
        message.slot,
        message.signature,
        validator_pubkey,
    )?;

    Ok(true)
}
