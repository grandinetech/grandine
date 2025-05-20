use std::sync::Arc;

use anyhow::Result;
use dedicated_executor::DedicatedExecutor;
use eth1_api::ApiController;
use eth2_libp2p::GossipId;
use fork_choice_control::{
    AttestationVerifierMessage, Snapshot, VerifyAggregateAndProofResult, VerifyAttestationResult,
    Wait,
};
use fork_choice_store::{
    AggregateAndProofAction, AggregateAndProofOrigin, AttestationAction, AttestationItem,
};
use futures::{
    channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
    select, StreamExt,
};
use helper_functions::{
    accessors, electra,
    error::SignatureKind,
    phase0, predicates,
    signing::SignForSingleFork,
    verifier::{MultiVerifier, Triple, Verifier},
};
use itertools::Either;
use log::{debug, warn};
use prometheus_metrics::Metrics;
use rayon::iter::{IntoParallelIterator as _, ParallelBridge as _, ParallelIterator as _};
use std_ext::ArcExt as _;
use types::{
    combined::{Attestation, BeaconState, SignedAggregateAndProof},
    config::Config,
    electra::containers::IndexedAttestation as ElectraIndexedAttestation,
    preset::Preset,
};

const MAX_BATCH_SIZE: usize = 64;

pub struct AttestationVerifier<P: Preset, W: Wait> {
    attestations: Vec<AttestationItem<P, GossipId>>,
    batch_attestations: Vec<AttestationItem<P, GossipId>>,
    aggregates: Vec<AggregateWithOrigin<P>>,
    controller: ApiController<P, W>,
    dedicated_executor: Arc<DedicatedExecutor>,
    active_aggregates_task_count: usize,
    active_attestations_task_count: usize,
    active_batch_attestations_task_count: usize,
    max_aggregates_active_tasks: usize,
    max_attestations_active_tasks: usize,
    max_batch_attestations_active_tasks: usize,
    metrics: Option<Arc<Metrics>>,
    fc_to_verifier_rx: UnboundedReceiver<AttestationVerifierMessage<P, W>>,
    aggregates_task_to_verifier_rx: UnboundedReceiver<TaskMessage<W>>,
    aggregates_task_to_verifier_tx: UnboundedSender<TaskMessage<W>>,
    attestations_task_to_verifier_rx: UnboundedReceiver<TaskMessage<W>>,
    attestations_task_to_verifier_tx: UnboundedSender<TaskMessage<W>>,
    batch_attestations_task_to_verifier_rx: UnboundedReceiver<TaskMessage<W>>,
    batch_attestations_task_to_verifier_tx: UnboundedSender<TaskMessage<W>>,
}

impl<P: Preset, W: Wait> AttestationVerifier<P, W> {
    #[must_use]
    pub fn new(
        controller: ApiController<P, W>,
        dedicated_executor: Arc<DedicatedExecutor>,
        metrics: Option<Arc<Metrics>>,
        fc_to_verifier_rx: UnboundedReceiver<AttestationVerifierMessage<P, W>>,
    ) -> Self {
        let (aggregates_task_to_verifier_tx, aggregates_task_to_verifier_rx) = mpsc::unbounded();
        let (attestations_task_to_verifier_tx, attestations_task_to_verifier_rx) =
            mpsc::unbounded();
        let (batch_attestations_task_to_verifier_tx, batch_attestations_task_to_verifier_rx) =
            mpsc::unbounded();

        Self {
            attestations: vec![],
            batch_attestations: vec![],
            aggregates: vec![],
            controller,
            dedicated_executor,
            active_aggregates_task_count: 0,
            active_attestations_task_count: 0,
            active_batch_attestations_task_count: 0,
            // `blst` already parallelizes signature verification. For non parallelized BLS
            // libraries use `num_cpus::get()`
            max_aggregates_active_tasks: 1,
            max_attestations_active_tasks: 1,
            max_batch_attestations_active_tasks: 1,
            metrics,
            fc_to_verifier_rx,
            aggregates_task_to_verifier_rx,
            aggregates_task_to_verifier_tx,
            attestations_task_to_verifier_rx,
            attestations_task_to_verifier_tx,
            batch_attestations_task_to_verifier_rx,
            batch_attestations_task_to_verifier_tx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            select! {
                message = self.aggregates_task_to_verifier_rx.select_next_some() => {
                    match message {
                        TaskMessage::Finished(wait_group) => {
                            self.active_aggregates_task_count -= 1;
                            self.spawn_verify_aggregate_batch_task(&wait_group);
                            self.track_active_task_count();
                        }
                    }
                }
                message = self.attestations_task_to_verifier_rx.select_next_some() => {
                    match message {
                        TaskMessage::Finished(wait_group) => {
                            self.active_attestations_task_count -= 1;
                            self.spawn_verify_attestation_batch_task(&wait_group);
                            self.track_active_task_count();
                        }
                    }
                }
                message = self.batch_attestations_task_to_verifier_rx.select_next_some() => {
                    match message {
                        TaskMessage::Finished(wait_group) => {
                            self.active_batch_attestations_task_count -= 1;
                            self.spawn_verify_batch_attestation_task(&wait_group);
                            self.track_active_task_count();
                        }
                    }
                }
                message = self.fc_to_verifier_rx.select_next_some() => {
                    match message {
                        AttestationVerifierMessage::AggregateAndProof {
                            wait_group,
                            aggregate_and_proof,
                            origin,
                        } => {
                            self.aggregates.push(AggregateWithOrigin {
                                aggregate: aggregate_and_proof,
                                origin,
                            });

                            self.spawn_verify_aggregate_batch_task(&wait_group);
                        }
                        AttestationVerifierMessage::Attestation {
                            wait_group,
                            attestation,
                        } => {
                            self.attestations.push(attestation);
                            self.spawn_verify_attestation_batch_task(&wait_group);
                        }
                        AttestationVerifierMessage::AttestationBatch {
                            wait_group,
                            mut attestations,
                        } => {
                            debug!(
                                "received attestation batch with {} attestations, existing batch attestations: {}",
                                attestations.len(),
                                self.batch_attestations.len()
                            );

                            self.batch_attestations.append(&mut attestations);
                            self.spawn_verify_batch_attestation_task(&wait_group);
                        }
                        AttestationVerifierMessage::Stop => break Ok(()),
                    }
                }
            }
        }
    }

    fn spawn_verify_aggregate_batch_task(&mut self, wait_group: &W) {
        if self.active_aggregates_task_count >= self.max_aggregates_active_tasks
            || self.aggregates.is_empty()
        {
            return;
        }

        self.active_aggregates_task_count += 1;
        self.track_active_task_count();

        let split_at = self.aggregates.len().saturating_sub(MAX_BATCH_SIZE);
        let aggregates = self.aggregates.split_off(split_at);

        VerifyAggregateBatchTask::spawn(
            wait_group.clone(),
            aggregates,
            self.controller.clone_arc(),
            &self.dedicated_executor,
            self.metrics.clone(),
            self.aggregates_task_to_verifier_tx.clone(),
        );
    }

    fn spawn_verify_attestation_batch_task(&mut self, wait_group: &W) {
        if self.active_attestations_task_count >= self.max_attestations_active_tasks
            || self.attestations.is_empty()
        {
            return;
        }

        self.active_attestations_task_count += 1;
        self.track_active_task_count();

        debug!(
            "spawn verify attestation batch task: attestation_len: {}",
            self.attestations.len(),
        );

        let split_at = self.attestations.len().saturating_sub(MAX_BATCH_SIZE);
        let attestations = self.attestations.split_off(split_at);

        VerifyAttestationBatchTask::spawn(
            wait_group.clone(),
            attestations,
            self.controller.clone_arc(),
            &self.dedicated_executor,
            self.metrics.clone(),
            self.attestations_task_to_verifier_tx.clone(),
        );
    }

    fn spawn_verify_batch_attestation_task(&mut self, wait_group: &W) {
        if self.active_batch_attestations_task_count >= self.max_batch_attestations_active_tasks
            || self.batch_attestations.is_empty()
        {
            return;
        }

        self.active_batch_attestations_task_count += 1;
        self.track_active_task_count();

        debug!(
            "spawn verify batch attestation task: batch_attestation_len: {}",
            self.batch_attestations.len()
        );

        let mut attestations = vec![];
        core::mem::swap(&mut self.batch_attestations, &mut attestations);

        VerifyAttestationBatchTask::spawn(
            wait_group.clone(),
            attestations,
            self.controller.clone_arc(),
            &self.dedicated_executor,
            self.metrics.clone(),
            self.batch_attestations_task_to_verifier_tx.clone(),
        );
    }

    fn track_active_task_count(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.set_attestation_verifier_active_task_count(
                self.active_aggregates_task_count
                    + self.active_attestations_task_count
                    + self.active_batch_attestations_task_count,
            );
        }
    }
}

struct VerifyAggregateBatchTask<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
}

impl<P: Preset, W: Wait> VerifyAggregateBatchTask<P, W> {
    fn spawn(
        wait_group: W,
        aggregates: Vec<AggregateWithOrigin<P>>,
        controller: ApiController<P, W>,
        dedicated_executor: &DedicatedExecutor,
        metrics: Option<Arc<Metrics>>,
        task_to_verifier_tx: UnboundedSender<TaskMessage<W>>,
    ) {
        dedicated_executor
            .spawn(async move {
                Self { controller }.process_aggregate_batch(aggregates, metrics.as_ref());

                TaskMessage::Finished(wait_group).send(&task_to_verifier_tx);
            })
            .detach();
    }

    fn current_state(&self, snapshot: &Snapshot<P>) -> Arc<BeaconState<P>> {
        if !self.controller.is_forward_synced() {
            return snapshot.head_state();
        }

        match self.controller.preprocessed_state_at_current_slot() {
            Ok(state) => state,
            Err(error) => {
                debug!(
                    "failed to get state at current slot for aggregate and proof batch signature verification: {error}. \
                     Using head state instead",
                );

                snapshot.head_state()
            }
        }
    }

    fn process_aggregate_batch(
        &self,
        aggregates_with_origins: Vec<AggregateWithOrigin<P>>,
        metrics: Option<&Arc<Metrics>>,
    ) {
        let _timer = metrics.map(|metrics| {
            // metrics.set_attestation_verifier_aggregate_batch_len(aggregates_with_origins.len());
            metrics
                .attestation_verifier_process_aggregate_batch_times
                .start_timer()
        });

        let snapshot = self.controller.snapshot();

        // let ((accepted_aggregates, accepted), other): ((Vec<_>, Vec<_>), Vec<_>) =
        let (accepted, other): (Vec<_>, Vec<_>) = aggregates_with_origins
            .into_par_iter()
            .map(|aggregate_wo| {
                let AggregateWithOrigin { aggregate, origin } = aggregate_wo;
                snapshot.prevalidate_verifier_aggregate_and_proof(aggregate, origin)
            })
            .partition_map(|result| match result.result {
                Ok(AggregateAndProofAction::Accept { .. }) => Either::Left(result),
                _ => Either::Right(result),
            });

        self.send_results_to_fork_choice(other);

        match self.verify_aggregate_batch_signatures(
            &accepted,
            &self.current_state(&snapshot),
            metrics,
        ) {
            Ok(()) => {
                self.send_results_to_fork_choice(accepted);
            }
            Err(error) => {
                warn!(
                    "signature verification for gossip aggregate and proof batch failed: {error}",
                );

                for accepted_aggregate in accepted {
                    let VerifyAggregateAndProofResult { result, origin } = accepted_aggregate;

                    if let Ok(AggregateAndProofAction::Accept {
                        aggregate_and_proof,
                        ..
                    }) = result
                    {
                        self.process_singular_aggregate(AggregateWithOrigin {
                            aggregate: aggregate_and_proof,
                            origin,
                        });
                    }
                }
            }
        }
    }

    fn send_results_to_fork_choice(&self, results: Vec<VerifyAggregateAndProofResult<P>>) {
        if results.is_empty() {
            return;
        }

        self.controller.on_aggregate_and_proof_batch(results);
    }

    fn verify_aggregate_batch_signatures(
        &self,
        aggregates: &[VerifyAggregateAndProofResult<P>],
        state: &BeaconState<P>,
        metrics: Option<&Arc<Metrics>>,
    ) -> Result<()> {
        let _timer = metrics.map(|metrics| {
            // metrics.set_attestation_verifier_aggregate_batch_signature_len(aggregates_wo.len());
            metrics
                .attestation_verifier_verify_agg_batch_signature_times
                .start_timer()
        });

        let config = self.controller.chain_config().as_ref();
        let mut verifier = MultiVerifier::default();

        verifier.reserve(aggregates.len() * 3);

        let mut messages = vec![];

        for aggregate in aggregates {
            let VerifyAggregateAndProofResult {
                ref result,
                origin: _,
            } = aggregate;

            if let Ok(AggregateAndProofAction::Accept {
                ref aggregate_and_proof,
                ..
            }) = result
            {
                let message = aggregate_and_proof.message();
                let signature = aggregate_and_proof.signature();

                let aggregator_index = message.aggregator_index();
                let selection_proof = message.selection_proof();

                let public_key = accessors::public_key(state, aggregator_index)?;

                verifier.verify_singular(
                    message.slot().signing_root(config, state),
                    selection_proof,
                    public_key,
                    SignatureKind::SelectionProof,
                )?;

                verifier.verify_singular(
                    message.signing_root(config, state),
                    signature,
                    public_key,
                    SignatureKind::AggregateAndProof,
                )?;

                messages.push(message.aggregate());
            }
        }

        let attestation_triples = attestation_batch_triples(config, messages.iter(), state)?;

        verifier.extend(attestation_triples, SignatureKind::Attestation)?;

        verifier.finish()
    }

    fn process_singular_aggregate(&self, aggregate_with_origin: AggregateWithOrigin<P>) {
        let AggregateWithOrigin { aggregate, origin } = aggregate_with_origin;

        self.controller.on_aggregate_and_proof(aggregate, origin);
    }
}

struct VerifyAttestationBatchTask<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
}

impl<P: Preset, W: Wait> VerifyAttestationBatchTask<P, W> {
    fn spawn(
        wait_group: W,
        attestations: Vec<AttestationItem<P, GossipId>>,
        controller: ApiController<P, W>,
        dedicated_executor: &DedicatedExecutor,
        metrics: Option<Arc<Metrics>>,
        task_to_verifier_tx: UnboundedSender<TaskMessage<W>>,
    ) {
        dedicated_executor
            .spawn(async move {
                let _timer = metrics.as_ref().map(|metrics| {
                    metrics
                        .attestation_verifier_process_attestation_batch_times
                        .start_timer()
                });

                Self { controller }.process_attestation_batch(attestations);

                TaskMessage::Finished(wait_group).send(&task_to_verifier_tx);
            })
            .detach();
    }

    fn current_state(&self, snapshot: &Snapshot<P>) -> Arc<BeaconState<P>> {
        if !self.controller.is_forward_synced() {
            return snapshot.head_state();
        }

        match self.controller.preprocessed_state_at_current_slot() {
            Ok(state) => state,
            Err(error) => {
                debug!(
                    "failed to get state at current slot for attestation batch signature verification: {error}. \
                     Using head state instead",
                );

                snapshot.head_state()
            }
        }
    }

    fn process_attestation_batch(&self, attestations: Vec<AttestationItem<P, GossipId>>) {
        let snapshot = self.controller.snapshot();

        // if let Some(metrics) = metrics.as_ref() {
        //     metrics.set_attestation_verifier_attestation_batch_len(attestations_with_origins.len());
        // }

        let (accepted, other): (Vec<_>, Vec<_>) = attestations
            .into_par_iter()
            .map(|attestation| snapshot.prevalidate_verifier_attestation(attestation))
            .partition_map(|result| match result {
                Ok(AttestationAction::Accept { .. }) => Either::Left(result),
                _ => Either::Right(result),
            });

        self.send_results_to_fork_choice(other);

        // if let Some(metrics) = metrics.as_ref() {
        //     metrics.set_attestation_verifier_attestation_batch_signature_len(accepted_attestations_wo.len());
        // }

        match self.verify_attestation_batch_signatures(&accepted, &self.current_state(&snapshot)) {
            Ok(()) => {
                let accepted = accepted
                    .into_iter()
                    .map(|action| action.map(AttestationAction::into_verified))
                    .collect();

                self.send_results_to_fork_choice(accepted);
            }
            Err(error) => {
                warn!("signature verification for gossip attestation batch failed: {error}");

                for accepted_attestation in accepted.into_iter().flatten() {
                    if let AttestationAction::Accept { attestation, .. } = accepted_attestation {
                        self.controller.on_singular_attestation(attestation);
                    }
                }
            }
        }
    }

    fn send_results_to_fork_choice(&self, results: Vec<VerifyAttestationResult<P>>) {
        if results.is_empty() {
            return;
        }

        self.controller.on_attestation_batch(results);
    }

    fn verify_attestation_batch_signatures(
        &self,
        results: &[VerifyAttestationResult<P>],
        state: &BeaconState<P>,
    ) -> Result<()> {
        let mut verifier = MultiVerifier::default();

        verifier.reserve(results.len());

        let triples = attestation_batch_triples(
            self.controller.chain_config(),
            results.iter().filter_map(|result| {
                if let Ok(AttestationAction::Accept {
                    ref attestation, ..
                }) = result
                {
                    Some(attestation.item.as_ref())
                } else {
                    None
                }
            }),
            state,
        )?;

        verifier.extend(triples, SignatureKind::Attestation)?;

        verifier.finish()
    }
}

fn attestation_batch_triples<'a, P: Preset>(
    config: &Config,
    attestations: impl IntoIterator<IntoIter = impl Iterator<Item = &'a Attestation<P>> + Send>,
    state: &BeaconState<P>,
) -> Result<Vec<Triple>> {
    attestations
        .into_iter()
        .par_bridge()
        .map(|attestation| {
            let triple = match attestation {
                Attestation::Phase0(attestation) => {
                    let indexed_attestation = phase0::get_indexed_attestation(state, attestation)?;

                    let mut triple = Triple::default();

                    predicates::validate_constructed_indexed_attestation(
                        config,
                        state,
                        &indexed_attestation,
                        &mut triple,
                    )?;

                    triple
                }
                Attestation::Electra(attestation) => {
                    let indexed_attestation = electra::get_indexed_attestation(state, attestation)?;

                    let mut triple = Triple::default();

                    predicates::validate_constructed_indexed_attestation(
                        config,
                        state,
                        &indexed_attestation,
                        &mut triple,
                    )?;

                    triple
                }
                Attestation::Single(attestation) => {
                    let indexed_attestation: ElectraIndexedAttestation<P> =
                        (*attestation).try_into()?;

                    let mut triple = Triple::default();

                    predicates::validate_constructed_indexed_attestation(
                        config,
                        state,
                        &indexed_attestation,
                        &mut triple,
                    )?;

                    triple
                }
            };

            Ok(triple)
        })
        .collect()
}

struct AggregateWithOrigin<P: Preset> {
    aggregate: Arc<SignedAggregateAndProof<P>>,
    origin: AggregateAndProofOrigin<GossipId>,
}
enum TaskMessage<W> {
    Finished(W),
}

impl<W> TaskMessage<W> {
    fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!(
                "send from verification task to attestation verifier failed because the receiver was dropped"
            );
        }
    }
}
