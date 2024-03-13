use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use futures::{
    channel::{
        mpsc::{UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender},
    },
    stream::StreamExt as _,
};
use helper_functions::predicates;
use itertools::Itertools as _;
use log::{debug, warn};
use prometheus_metrics::Metrics;
use transition_functions::capella;
use types::{
    capella::containers::SignedBlsToExecutionChange, nonstandard::ValidationOutcome,
    phase0::primitives::ValidatorIndex, preset::Preset, traits::BeaconState as _,
};

use crate::{
    messages::{PoolToApiMessage, PoolToP2pMessage},
    misc::{Origin, PoolAdditionOutcome, PoolRejectionReason},
};

pub struct BlsToExecutionChangePool {
    tx: UnboundedSender<PoolMessage>,
}

impl BlsToExecutionChangePool {
    #[must_use]
    pub fn new<P: Preset, W: Wait>(
        controller: ApiController<P, W>,
        pool_to_api_tx: UnboundedSender<PoolToApiMessage>,
        pool_to_p2p_tx: UnboundedSender<PoolToP2pMessage>,
        metrics: Option<Arc<Metrics>>,
    ) -> (Arc<Self>, Service<P, W>) {
        let (tx, rx) = futures::channel::mpsc::unbounded();

        let pool = Arc::new(Self { tx });

        let service = Service {
            controller,
            bls_to_execution_changes: HashMap::new(),
            metrics,
            pool_to_api_tx,
            pool_to_p2p_tx,
            rx,
        };

        (pool, service)
    }

    pub fn discard_old_bls_to_execution_changes(&self) {
        PoolMessage::DiscardOldBlsToExecutionChanges.send(&self.tx)
    }

    pub async fn handle_external_signed_bls_to_execution_change(
        &self,
        signed_bls_to_execution_change: Box<SignedBlsToExecutionChange>,
        origin: Origin,
    ) -> Result<PoolAdditionOutcome> {
        let (sender, receiver) = oneshot::channel();

        PoolMessage::HandleExternalBlsToExecutionChange(
            signed_bls_to_execution_change,
            origin,
            Some(sender),
        )
        .send(&self.tx);

        receiver.await.map_err(Into::into)
    }

    pub fn notify_external_signed_bls_to_execution_change(
        &self,
        signed_bls_to_execution_change: Box<SignedBlsToExecutionChange>,
        origin: Origin,
    ) {
        PoolMessage::HandleExternalBlsToExecutionChange(
            signed_bls_to_execution_change,
            origin,
            None,
        )
        .send(&self.tx)
    }

    pub async fn signed_bls_to_execution_changes(&self) -> Result<Vec<SignedBlsToExecutionChange>> {
        let (sender, receiver) = oneshot::channel();
        PoolMessage::RequestSignedBlsToExecutionChanges(sender).send(&self.tx);
        receiver.await.map_err(Into::into)
    }
}

pub struct Service<P: Preset, W: Wait> {
    controller: ApiController<P, W>,
    bls_to_execution_changes: HashMap<ValidatorIndex, SignedBlsToExecutionChange>,
    metrics: Option<Arc<Metrics>>,
    pool_to_api_tx: UnboundedSender<PoolToApiMessage>,
    pool_to_p2p_tx: UnboundedSender<PoolToP2pMessage>,
    rx: UnboundedReceiver<PoolMessage>,
}

impl<P: Preset, W: Wait> Service<P, W> {
    pub async fn run(mut self) -> Result<()> {
        while let Some(message) = self.rx.next().await {
            let success =
                match message {
                    PoolMessage::DiscardOldBlsToExecutionChanges => {
                        let _timer = self.metrics.as_ref().map(|metrics| {
                            metrics.bls_pool_discard_old_changes_times.start_timer()
                        });

                        self.discard_old_bls_to_execution_changes();
                        true
                    }
                    PoolMessage::HandleExternalBlsToExecutionChange(
                        signed_bls_to_execution_change,
                        origin,
                        sender,
                    ) => {
                        let _timer = self.metrics.as_ref().map(|metrics| {
                            metrics.bls_pool_handle_external_change_times.start_timer()
                        });

                        let outcome = self.handle_external_signed_bls_to_execution_change(
                            *signed_bls_to_execution_change,
                            origin,
                        );

                        sender
                            .map(|sender| sender.send(outcome).is_ok())
                            .unwrap_or(true)
                    }
                    PoolMessage::RequestSignedBlsToExecutionChanges(sender) => sender
                        .send(
                            self.bls_to_execution_changes
                                .values()
                                .copied()
                                .collect_vec(),
                        )
                        .is_ok(),
                };

            if !success {
                warn!("failed to send response because the receiver was dropped");
            }
        }

        Ok(())
    }

    fn handle_external_signed_bls_to_execution_change(
        &mut self,
        signed_bls_to_execution_change: SignedBlsToExecutionChange,
        origin: Origin,
    ) -> PoolAdditionOutcome {
        match self.validate_signed_bls_to_execution_change(signed_bls_to_execution_change) {
            Ok(outcome) => match outcome {
                ValidationOutcome::Accept => {
                    match origin {
                        Origin::Api => {
                            PoolToP2pMessage::PublishSignedBlsToExecutionChange(Box::new(
                                signed_bls_to_execution_change,
                            ))
                            .send(&self.pool_to_p2p_tx);
                        }
                        Origin::Gossip(gossip_id) => {
                            PoolToP2pMessage::Accept(gossip_id).send(&self.pool_to_p2p_tx);
                        }
                    }

                    PoolToApiMessage::SignedBlsToExecutionChange(Box::new(
                        signed_bls_to_execution_change,
                    ))
                    .send(&self.pool_to_api_tx);

                    PoolAdditionOutcome::Accept
                }
                ValidationOutcome::Ignore => {
                    if let Origin::Gossip(gossip_id) = origin {
                        PoolToP2pMessage::Ignore(gossip_id).send(&self.pool_to_p2p_tx);
                    }

                    PoolAdditionOutcome::Ignore
                }
            },
            Err(error) => {
                if let Origin::Gossip(gossip_id) = origin {
                    PoolToP2pMessage::Reject(
                        gossip_id,
                        PoolRejectionReason::InvalidBlsToExecutionChange,
                    )
                    .send(&self.pool_to_p2p_tx);
                }

                warn!(
                    "external signed BLS to execution change rejected \
                     (error: {error}, message: {signed_bls_to_execution_change:?})",
                );
                PoolAdditionOutcome::Reject(PoolRejectionReason::InvalidBlsToExecutionChange, error)
            }
        }
    }

    fn validate_signed_bls_to_execution_change(
        &mut self,
        signed_bls_to_execution_change: SignedBlsToExecutionChange,
    ) -> Result<ValidationOutcome> {
        let state = self.controller.preprocessed_state_at_current_slot()?;

        let Some(state) = state.post_capella() else {
            warn!(
                "signed BLS to execution change received before Capella fork \
                 (signed_bls_to_execution_change: {:?}, slot: {})",
                signed_bls_to_execution_change,
                state.slot(),
            );

            return Ok(ValidationOutcome::Ignore);
        };

        let validator_index = signed_bls_to_execution_change.message.validator_index;

        if self.bls_to_execution_changes.contains_key(&validator_index) {
            return Ok(ValidationOutcome::Ignore);
        }

        capella::validate_bls_to_execution_change(
            self.controller.chain_config(),
            state,
            signed_bls_to_execution_change,
        )?;

        self.bls_to_execution_changes
            .insert(validator_index, signed_bls_to_execution_change);

        Ok(ValidationOutcome::Accept)
    }

    fn discard_old_bls_to_execution_changes(&mut self) {
        let finalized_state = self.controller.last_finalized_state().value;

        self.bls_to_execution_changes.retain(|validator_index, _| {
            let validator = match finalized_state.validators().get(*validator_index) {
                Ok(validator) => validator,
                Err(error) => {
                    debug!("BLS to execution change is too recent to discard: {error}");
                    return true;
                }
            };

            !predicates::has_eth1_withdrawal_credential(validator)
        })
    }
}

enum PoolMessage {
    DiscardOldBlsToExecutionChanges,
    HandleExternalBlsToExecutionChange(
        Box<SignedBlsToExecutionChange>,
        Origin,
        Option<Sender<PoolAdditionOutcome>>,
    ),
    RequestSignedBlsToExecutionChanges(Sender<Vec<SignedBlsToExecutionChange>>),
}

impl PoolMessage {
    pub fn send(self, tx: &UnboundedSender<Self>) {
        if let Err(message) = tx.unbounded_send(self) {
            debug!("internal send failed because the receiver was dropped: {message:?}");
        }
    }
}
