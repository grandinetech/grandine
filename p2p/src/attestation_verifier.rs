use std::sync::Arc;

use anyhow::Result;
use dedicated_executor::DedicatedExecutor;
use eth1_api::RealController;
use eth2_libp2p::GossipId;
use fork_choice_control::{VerifyAggregateAndProofResult, VerifyAttestationResult};
use fork_choice_store::{AggregateAndProofAction, AttestationAction};
use futures::{
    channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
    select, StreamExt,
};
use helper_functions::{
    accessors,
    error::SignatureKind,
    predicates,
    signing::SignForSingleFork,
    verifier::{MultiVerifier, Triple, Verifier},
};
use itertools::Either;
use log::{debug, warn};
use prometheus_metrics::Metrics;
use rayon::iter::{IntoParallelIterator as _, ParallelBridge as _, ParallelIterator as _};
use std_ext::ArcExt as _;
use types::{
    combined::BeaconState,
    config::Config,
    phase0::{
        containers::{AggregateAndProof, Attestation, SignedAggregateAndProof},
        primitives::SubnetId,
    },
    preset::Preset,
};

use crate::messages::P2pToAttestationVerifier;

const MAX_BATCH_SIZE: usize = 64;

pub struct AttestationVerifier<P: Preset> {
    attestations: Vec<AttestationWithOrigin<P>>,
    aggregates: Vec<AggregateWithOrigin<P>>,
    controller: RealController<P>,
    dedicated_executor: DedicatedExecutor,
    active_task_count: usize,
    max_active_tasks: usize,
    metrics: Option<Arc<Metrics>>,
    p2p_to_verifier_rx: UnboundedReceiver<P2pToAttestationVerifier<P>>,
    task_to_verifier_rx: UnboundedReceiver<TaskMessage>,
    task_to_verifier_tx: UnboundedSender<TaskMessage>,
}

impl<P: Preset> AttestationVerifier<P> {
    #[must_use]
    pub fn new(
        controller: RealController<P>,
        dedicated_executor: DedicatedExecutor,
        metrics: Option<Arc<Metrics>>,
        p2p_to_verifier_rx: UnboundedReceiver<P2pToAttestationVerifier<P>>,
    ) -> Self {
        let (task_to_verifier_tx, task_to_verifier_rx) = mpsc::unbounded();

        Self {
            attestations: vec![],
            aggregates: vec![],
            controller,
            dedicated_executor,
            active_task_count: 0,
            // `blst` already parallelizes signature verification. For non parallelized BLS
            // libraries use `num_cpus::get()`
            max_active_tasks: 1,
            metrics,
            p2p_to_verifier_rx,
            task_to_verifier_rx,
            task_to_verifier_tx,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            select! {
                message = self.task_to_verifier_rx.select_next_some() => {
                    match message {
                        TaskMessage::Finished => {
                            self.active_task_count -= 1;
                            self.spawn_verify_batch_tasks();

                            if let Some(metrics) = self.metrics.as_ref() {
                                metrics.set_attestation_verifier_active_task_count(self.active_task_count);
                            }
                        }
                    }
                }
                message = self.p2p_to_verifier_rx.select_next_some() => {
                    match message {
                        P2pToAttestationVerifier::GossipAggregateAndProof(aggregate, gossip_id) => {
                            self.aggregates.push(AggregateWithOrigin {
                                aggregate,
                                gossip_id,
                            });
                            self.spawn_verify_batch_tasks();
                        }
                        P2pToAttestationVerifier::GossipAttestation(attestation, subnet_id, gossip_id) => {
                            self.attestations.push(AttestationWithOrigin {
                                attestation,
                                subnet_id,
                                gossip_id,
                            });
                            self.spawn_verify_batch_tasks();
                        }
                    }
                }
            }
        }
    }

    fn spawn_verify_batch_tasks(&mut self) {
        self.spawn_verify_attestation_batch_task();
        self.spawn_verify_aggregate_batch_task();
    }

    fn spawn_verify_aggregate_batch_task(&mut self) {
        if self.aggregates.is_empty() || self.active_task_count >= self.max_active_tasks {
            return;
        }

        self.active_task_count += 1;

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.set_attestation_verifier_active_task_count(self.active_task_count);
        }

        let split_at = self.aggregates.len().saturating_sub(MAX_BATCH_SIZE);
        let aggregates = self.aggregates.split_off(split_at);

        VerifyAggregateBatchTask::spawn(
            aggregates,
            self.controller.clone_arc(),
            &self.dedicated_executor,
            self.metrics.clone(),
            self.task_to_verifier_tx.clone(),
        );
    }

    fn spawn_verify_attestation_batch_task(&mut self) {
        if self.attestations.is_empty() || self.active_task_count >= self.max_active_tasks {
            return;
        }

        self.active_task_count += 1;

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.set_attestation_verifier_active_task_count(self.active_task_count);
        }

        let split_at = self.attestations.len().saturating_sub(MAX_BATCH_SIZE);
        let attestations = self.attestations.split_off(split_at);

        VerifyAttestationBatchTask::spawn(
            attestations,
            self.controller.clone_arc(),
            &self.dedicated_executor,
            self.metrics.clone(),
            self.task_to_verifier_tx.clone(),
        );
    }
}

struct VerifyAggregateBatchTask<P: Preset> {
    controller: RealController<P>,
}

impl<P: Preset> VerifyAggregateBatchTask<P> {
    fn spawn(
        aggregates: Vec<AggregateWithOrigin<P>>,
        controller: RealController<P>,
        dedicated_executor: &DedicatedExecutor,
        metrics: Option<Arc<Metrics>>,
        task_to_verifier_tx: UnboundedSender<TaskMessage>,
    ) {
        dedicated_executor
            .spawn(async move {
                Self { controller }.process_aggregate_batch(aggregates, metrics.as_ref());

                TaskMessage::Finished.send(&task_to_verifier_tx);
            })
            .detach();
    }

    fn process_aggregate_batch(
        &self,
        aggregates_with_origins: Vec<AggregateWithOrigin<P>>,
        metrics: Option<&Arc<Metrics>>,
    ) {
        let _timer = metrics.map(|metrics| {
            metrics
                .attestation_verifier_processs_aggregate_batch_times
                .start_timer()
        });

        let snapshot = self.controller.snapshot();

        let ((accepted_aggregates_wo, accepted), other): ((Vec<_>, Vec<_>), Vec<_>) =
            aggregates_with_origins
                .into_par_iter()
                .map(|aggregate_wo| {
                    let AggregateWithOrigin {
                        aggregate,
                        gossip_id,
                    } = aggregate_wo.clone();

                    let result =
                        snapshot.prevalidate_gossip_aggregate_and_proof(aggregate, gossip_id);

                    (aggregate_wo, result)
                })
                .partition_map(|(aggregate_wo, result)| match result.result {
                    Ok(AggregateAndProofAction::Accept { .. }) => {
                        Either::Left((aggregate_wo, result))
                    }
                    _ => Either::Right(result),
                });

        self.send_results_to_fork_choice(other);

        match self.verify_aggregate_batch_signatures(
            &accepted_aggregates_wo,
            &snapshot.head_state(),
            metrics,
        ) {
            Ok(()) => {
                self.send_results_to_fork_choice(accepted);
            }
            Err(error) => {
                warn!(
                    "signature verification for gossip aggregate and proof batch failed: {error}",
                );

                for aggregate_wo in accepted_aggregates_wo {
                    self.process_singular_aggregate(aggregate_wo);
                }
            }
        }
    }

    fn send_results_to_fork_choice(&self, results: Vec<VerifyAggregateAndProofResult<P>>) {
        if results.is_empty() {
            return;
        }

        self.controller.on_gossip_aggregate_and_proof_batch(results);
    }

    fn verify_aggregate_batch_signatures(
        &self,
        aggregates_wo: &[AggregateWithOrigin<P>],
        state: &BeaconState<P>,
        metrics: Option<&Arc<Metrics>>,
    ) -> Result<()> {
        let _timer = metrics.map(|metrics| {
            metrics
                .attestation_verifier_verify_agg_batch_signature_times
                .start_timer()
        });

        let config = self.controller.chain_config().as_ref();
        let mut verifier = MultiVerifier::default();

        verifier.reserve(aggregates_wo.len() * 3);

        for aggregate_wo in aggregates_wo {
            let SignedAggregateAndProof {
                ref message,
                signature,
            } = *aggregate_wo.aggregate;

            let AggregateAndProof {
                aggregator_index,
                ref aggregate,
                selection_proof,
            } = *message;

            let public_key = accessors::public_key(state, aggregator_index)?;

            verifier.verify_singular(
                aggregate.data.slot.signing_root(config, state),
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
        }

        let attestation_triples = attestation_batch_triples(
            config,
            aggregates_wo
                .iter()
                .map(|aggregate_wo| &aggregate_wo.aggregate.message.aggregate),
            state,
        )?;

        verifier.extend(attestation_triples, SignatureKind::Attestation)?;

        verifier.finish()
    }

    fn process_singular_aggregate(&self, aggregate_with_origin: AggregateWithOrigin<P>) {
        let AggregateWithOrigin {
            aggregate,
            gossip_id,
        } = aggregate_with_origin;

        self.controller
            .on_gossip_aggregate_and_proof(aggregate, gossip_id);
    }
}

struct VerifyAttestationBatchTask<P: Preset> {
    controller: RealController<P>,
}

impl<P: Preset> VerifyAttestationBatchTask<P> {
    fn spawn(
        attestations: Vec<AttestationWithOrigin<P>>,
        controller: RealController<P>,
        dedicated_executor: &DedicatedExecutor,
        metrics: Option<Arc<Metrics>>,
        task_to_verifier_tx: UnboundedSender<TaskMessage>,
    ) {
        dedicated_executor
            .spawn(async move {
                let _timer = metrics.as_ref().map(|metrics| {
                    metrics
                        .attestation_verifier_process_attestation_batch_times
                        .start_timer()
                });

                Self { controller }.process_attestation_batch(attestations);

                TaskMessage::Finished.send(&task_to_verifier_tx);
            })
            .detach();
    }

    fn process_attestation_batch(&self, attestations_with_origins: Vec<AttestationWithOrigin<P>>) {
        let snapshot = self.controller.snapshot();

        let ((accepted_attestations_wo, accepted), other): ((Vec<_>, Vec<_>), Vec<_>) =
            attestations_with_origins
                .into_par_iter()
                .map(|attestation_wo| {
                    let AttestationWithOrigin {
                        attestation,
                        subnet_id,
                        gossip_id,
                    } = attestation_wo.clone();

                    let result =
                        snapshot.prevalidate_gossip_attestation(attestation, subnet_id, gossip_id);

                    (attestation_wo, result)
                })
                .partition_map(|(attestation_wo, result)| match result.result {
                    Ok(AttestationAction::Accept { .. }) => Either::Left((attestation_wo, result)),
                    _ => Either::Right(result),
                });

        self.send_results_to_fork_choice(other);

        match self
            .verify_attestation_batch_signatures(&accepted_attestations_wo, &snapshot.head_state())
        {
            Ok(()) => {
                self.send_results_to_fork_choice(accepted);
            }
            Err(error) => {
                warn!("signature verification for gossip attestation batch failed: {error}");

                for attestation_wo in accepted_attestations_wo {
                    self.process_singular_attestation(attestation_wo);
                }
            }
        }
    }

    fn send_results_to_fork_choice(&self, results: Vec<VerifyAttestationResult<P>>) {
        if results.is_empty() {
            return;
        }

        self.controller.on_gossip_attestation_batch(results);
    }

    fn verify_attestation_batch_signatures(
        &self,
        attestations_wo: &[AttestationWithOrigin<P>],
        state: &BeaconState<P>,
    ) -> Result<()> {
        let mut verifier = MultiVerifier::default();

        verifier.reserve(attestations_wo.len());

        let triples = attestation_batch_triples(
            self.controller.chain_config(),
            attestations_wo
                .iter()
                .map(|attestation_wo| attestation_wo.attestation.as_ref()),
            state,
        )?;

        verifier.extend(triples, SignatureKind::Attestation)?;

        verifier.finish()
    }

    fn process_singular_attestation(&self, attestation_with_origin: AttestationWithOrigin<P>) {
        let AttestationWithOrigin {
            attestation,
            subnet_id,
            gossip_id,
        } = attestation_with_origin;

        self.controller
            .on_gossip_singular_attestation(attestation, subnet_id, gossip_id);
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
            let indexed_attestation = accessors::get_indexed_attestation(state, attestation)?;

            let mut triple = Triple::default();

            predicates::validate_constructed_indexed_attestation(
                config,
                state,
                &indexed_attestation,
                &mut triple,
            )?;

            Ok(triple)
        })
        .collect()
}

#[derive(Clone)]
struct AggregateWithOrigin<P: Preset> {
    aggregate: Box<SignedAggregateAndProof<P>>,
    gossip_id: GossipId,
}

#[derive(Clone)]
struct AttestationWithOrigin<P: Preset> {
    attestation: Arc<Attestation<P>>,
    subnet_id: SubnetId,
    gossip_id: GossipId,
}

enum TaskMessage {
    Finished,
}

impl TaskMessage {
    fn send(self, tx: &UnboundedSender<Self>) {
        if tx.unbounded_send(self).is_err() {
            debug!(
                "send from verification task to attestation verifier failed because the receiver was dropped"
            );
        }
    }
}
