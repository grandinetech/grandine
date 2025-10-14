use std::sync::Arc;

use anyhow::Result;
use derive_more::Constructor;
use either::Either;
use execution_engine::{
    EngineGetBlobsParams, ExecutionEngine, ExecutionServiceMessage, PayloadAttributes, PayloadId,
    PayloadStatusV1,
};
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use logging::{info_with_peers, warn_with_peers};
use tokio::runtime::{Builder, Handle};
use types::{
    combined::{ExecutionPayload, ExecutionPayloadParams},
    config::Config,
    nonstandard::{Phase, TimedPowBlock, WithBlobsAndMev},
    phase0::primitives::{ExecutionBlockHash, H256},
    preset::Preset,
};
use web3::types::U64;

use crate::{eth1_api::Eth1Api, WithClientVersions};

#[derive(Constructor)]
pub struct Eth1ExecutionEngine<P: Preset> {
    config: Arc<Config>,
    eth1_api: Arc<Eth1Api>,
    execution_service_tx: UnboundedSender<ExecutionServiceMessage<P>>,
}

impl<P: Preset> ExecutionEngine<P> for Eth1ExecutionEngine<P> {
    const IS_NULL: bool = false;

    fn allow_optimistic_merge_block_validation(&self) -> bool {
        true
    }

    fn exchange_capabilities(&self) {
        ExecutionServiceMessage::ExchangeCapabilities.send(&self.execution_service_tx);
    }

    fn get_blobs(&self, params: EngineGetBlobsParams<P>) {
        ExecutionServiceMessage::GetBlobs(params).send(&self.execution_service_tx);
    }

    fn notify_forkchoice_updated(
        &self,
        head_eth1_block_hash: ExecutionBlockHash,
        safe_eth1_block_hash: ExecutionBlockHash,
        finalized_eth1_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
        sender: Option<Sender<Option<PayloadId>>>,
    ) {
        ExecutionServiceMessage::NotifyForkchoiceUpdated {
            head_eth1_block_hash,
            safe_eth1_block_hash,
            finalized_eth1_block_hash,
            payload_attributes,
            sender,
        }
        .send(&self.execution_service_tx);
    }

    fn notify_new_payload(
        &self,
        beacon_block_root: H256,
        payload: ExecutionPayload<P>,
        params: Option<ExecutionPayloadParams<P>>,
        sender: Option<Sender<Result<PayloadStatusV1>>>,
    ) -> Result<()> {
        ExecutionServiceMessage::NotifyNewPayload {
            beacon_block_root,
            payload: Box::new(payload),
            params,
            sender,
        }
        .send(&self.execution_service_tx);

        Ok(())
    }

    fn pow_block(&self, block_hash: ExecutionBlockHash) -> Option<TimedPowBlock> {
        // `ExecutionEngine::pow_block` is not `async` because it is called from non-`async` code.
        // We need some way to run the future returned by `Eth1Api::get_block_by_hash`.
        // `futures::executor::block_on` is not enough because `web3` uses Tokio for IO.
        // `tokio::runtime::Handle::current` panics when called outside a Tokio runtime.
        // Tokio runtimes (including the one created by `tokio::main`) are thread-local rather than
        // global, so there is no way to obtain a handle to the "current" one from outside it.
        let run_on_new_runtime = || {
            Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()?
                .block_on(self.eth1_api.get_block_by_hash(block_hash))
        };

        // Start the new runtime in a scoped thread if called from a Tokio thread.
        // This should no longer be necessary after the latest batch of fixes to `http_api`,
        // but it costs little to keep the extra logic around.
        //
        // Starting a new Tokio runtime from a Tokio thread causes a panic.
        // `Handle::try_current` may be used to obtain a handle to the current Tokio runtime,
        // but `Handle::block_on` also panics when called from a Tokio thread.
        // Starting a new runtime in a scoped thread appears to be the only reliable way.
        let result = if Handle::try_current().is_ok() {
            std::thread::scope(|scope| {
                scope
                    .spawn(run_on_new_runtime)
                    .join()
                    .map_err(panics::payload_into_error)?
            })
        } else {
            run_on_new_runtime()
        };

        match result {
            Ok(Some(pow_block)) => {
                info_with_peers!("request for Eth1 block {block_hash:?} returned {pow_block:?}");
                Some(pow_block.into())
            }
            Ok(None) => {
                warn_with_peers!("Eth1 block {block_hash:?} not found");
                None
            }
            Err(error) => {
                warn_with_peers!("request for Eth1 block {block_hash:?} failed: {error:?}");
                None
            }
        }
    }

    fn stop(&self) {
        ExecutionServiceMessage::Stop.send(&self.execution_service_tx);
    }
}

impl<P: Preset> Eth1ExecutionEngine<P> {
    pub async fn get_execution_payload(
        &self,
        payload_id: PayloadId,
    ) -> Result<WithClientVersions<WithBlobsAndMev<ExecutionPayload<P>, P>>> {
        self.eth1_api.get_payload::<P>(payload_id).await
    }

    pub async fn get_terminal_pow_block(&self) -> Result<Option<TimedPowBlock>> {
        let api = &self.eth1_api;

        if !self.config.terminal_block_hash.is_zero() {
            return api
                .get_block_by_hash(self.config.terminal_block_hash)
                .await
                .map(|option| option.map(Into::into));
        }

        let mut block_id = U64::from(api.current_head_number().await?).into();

        while let Some(block) = api.get_block(block_id).await? {
            let block_reached_ttd = block.total_difficulty >= self.config.terminal_total_difficulty;

            if block_reached_ttd {
                // > If genesis block, no parent exists so reaching
                // > TTD alone qualifies as valid terminal block
                if block.parent_hash.is_zero() {
                    return Ok(Some(block.into()));
                }

                if let Some(parent) = api.get_block_by_hash(block.parent_hash).await? {
                    let parent_reached_ttd =
                        parent.total_difficulty >= self.config.terminal_total_difficulty;

                    if !parent_reached_ttd {
                        return Ok(Some(block.into()));
                    }
                }
            } else {
                break;
            }

            block_id = block.parent_hash.into();
        }

        Ok(None)
    }
}
