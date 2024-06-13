use core::time::Duration;
use std::sync::Arc;

use anyhow::Result;
use bls::PublicKeyBytes;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::accessors;
use prometheus_metrics::Metrics;
use ssz::ContiguousList;
use std_ext::ArcExt as _;
use types::{
    combined::BeaconState, phase0::containers::Attestation, phase0::primitives::ValidatorIndex,
    preset::Preset, traits::BeaconState as _,
};

use crate::{
    attestation_agg_pool::{
        attestation_packer::{AttestationPacker, PackOutcome},
        pool::Pool,
        types::Aggregate,
    },
    misc::PoolTask,
};

pub struct BestProposableAttestationsTask<P: Preset, W: Wait> {
    pub pool: Arc<Pool<P>>,
    pub controller: ApiController<P, W>,
    pub beacon_state: Arc<BeaconState<P>>,
}

impl<P: Preset, W: Wait> PoolTask for BestProposableAttestationsTask<P, W> {
    type Output = ContiguousList<Attestation<P>, P::MaxAttestations>;

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            controller,
            beacon_state,
        } = self;

        let attestations = pool.best_proposable_attestations(beacon_state.slot()).await;

        if !attestations.is_empty() {
            return Ok(attestations);
        }

        let attestation_packer = AttestationPacker::new(
            controller.chain_config().clone_arc(),
            controller.head_block_root().value,
            beacon_state.clone_arc(),
            true,
        )?;

        Ok(
            pack_attestations_greedily(&attestation_packer, &pool, &beacon_state)
                .await
                .attestations,
        )
    }
}

pub struct ComputeProposerIndicesTask<P: Preset> {
    pub pool: Arc<Pool<P>>,
    pub beacon_state: Arc<BeaconState<P>>,
}

impl<P: Preset> PoolTask for ComputeProposerIndicesTask<P> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self { pool, beacon_state } = self;
        let current_epoch = accessors::get_current_epoch(&beacon_state);

        pool.compute_proposer_indices_for_epoch(&beacon_state, current_epoch)
            .await?;
        pool.compute_proposer_indices_for_epoch(&beacon_state, current_epoch + 1)
            .await?;

        Ok(())
    }
}

pub struct PackProposableAttestationsTask<P: Preset, W: Wait> {
    pub pool: Arc<Pool<P>>,
    pub controller: ApiController<P, W>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> PoolTask for PackProposableAttestationsTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            controller,
            metrics,
        } = self;

        let beacon_state = controller.preprocessed_state_at_next_slot()?;

        let mut attestation_packer = AttestationPacker::new(
            controller.chain_config().clone_arc(),
            controller.head_block_root().value,
            beacon_state.clone_arc(),
            false,
        )?;

        let mut is_empty = true;

        loop {
            let PackOutcome {
                attestations,
                deadline_reached,
            } = {
                let _timer = metrics.as_ref().map(|metrics| {
                    metrics
                        .att_pool_pack_proposable_attestation_task_times
                        .start_timer()
                });

                pack_attestations_optimally(&attestation_packer, &pool, &beacon_state).await
            };

            if is_empty || !deadline_reached {
                pool.set_best_proposable_attestations(attestations, beacon_state.slot())
                    .await;
                is_empty = false;
            }

            if deadline_reached {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;

            let head_block_root = controller.head_block_root().value;

            if attestation_packer.should_update_current_participation(head_block_root) {
                attestation_packer.update_current_participation(
                    head_block_root,
                    controller.preprocessed_state_at_next_slot()?,
                )?;
            }
        }

        Ok(())
    }
}

pub struct InsertAttestationTask<P: Preset, W> {
    pub wait_group: W,
    pub pool: Arc<Pool<P>>,
    pub attestation: Arc<Attestation<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Send + 'static> PoolTask for InsertAttestationTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            wait_group,
            pool,
            attestation,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.att_pool_insert_attestation_task_times.start_timer());

        let Attestation {
            ref aggregation_bits,
            data,
            signature,
        } = *attestation;

        let singular_attestations = pool.singular_attestations(data).await;
        let aggregates = pool.aggregates(data).await;
        let mut aggregates = aggregates.lock().await;

        if aggregation_bits.count_ones() > 1 || aggregates.is_empty() {
            let mut aggregate = Aggregate {
                aggregation_bits: aggregation_bits.clone(),
                signature: signature.try_into()?,
            };

            for existing_attestation in singular_attestations.read().await.iter() {
                aggregate_attestation(existing_attestation, &mut aggregate)?;
            }

            aggregates.push(aggregate);
        } else {
            for aggregate in aggregates.iter_mut() {
                aggregate_attestation(&attestation, aggregate)?;
            }
        }

        pool.add_data_root_to_data_entry(data).await;

        if aggregation_bits.count_ones() == 1 {
            singular_attestations.write().await.insert(attestation);
        }

        drop(wait_group);

        Ok(())
    }
}

pub struct SetRegisteredValidatorsTask<P: Preset, W: Wait> {
    pub pool: Arc<Pool<P>>,
    pub controller: ApiController<P, W>,
    pub pubkeys: Vec<PublicKeyBytes>,
    pub prepared_proposer_indices: Vec<ValidatorIndex>,
}

impl<P: Preset, W: Wait> PoolTask for SetRegisteredValidatorsTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            pool,
            controller,
            pubkeys,
            prepared_proposer_indices,
        } = self;

        let beacon_state = controller.preprocessed_state_at_current_slot()?;

        let validator_indices = pubkeys
            .into_iter()
            .filter_map(|pubkey| accessors::index_of_public_key(&beacon_state, pubkey))
            .chain(prepared_proposer_indices)
            .collect();

        pool.set_registered_validator_indices(validator_indices)
            .await;

        Ok(())
    }
}

fn aggregate_attestation<P: Preset>(
    attestation: &Attestation<P>,
    aggregate: &mut Aggregate<P>,
) -> Result<()> {
    if attestation
        .aggregation_bits
        .any_not_in(&aggregate.aggregation_bits)
    {
        aggregate.aggregation_bits |= &attestation.aggregation_bits;
        aggregate
            .signature
            .aggregate_in_place(attestation.signature.try_into()?);
    }

    Ok(())
}

async fn pack_attestations_optimally<P: Preset>(
    attestation_packer: &AttestationPacker<P>,
    pool: &Pool<P>,
    state: &BeaconState<P>,
) -> PackOutcome<P> {
    let previous_epoch = accessors::get_previous_epoch(state);
    let current_epoch = accessors::get_current_epoch(state);

    attestation_packer.pack_proposable_attestations_optimally(
        &pool.aggregate_attestations_by_epoch(previous_epoch).await,
        &pool.aggregate_attestations_by_epoch(current_epoch).await,
    )
}

async fn pack_attestations_greedily<P: Preset>(
    attestation_packer: &AttestationPacker<P>,
    pool: &Pool<P>,
    state: &BeaconState<P>,
) -> PackOutcome<P> {
    let previous_epoch = accessors::get_previous_epoch(state);
    let current_epoch = accessors::get_current_epoch(state);

    attestation_packer.pack_proposable_attestations_greedily(
        &pool.aggregate_attestations_by_epoch(previous_epoch).await,
        &pool.aggregate_attestations_by_epoch(current_epoch).await,
    )
}
