use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{Result, ensure};
use either::Either;
use futures::channel::{mpsc::UnboundedSender, oneshot::Sender};
use thiserror::Error;
use types::{
    combined::{ExecutionPayload, ExecutionPayloadParams},
    nonstandard::{Phase, TimedPowBlock},
    phase0::primitives::{ExecutionBlockHash, H256},
    preset::Preset,
};

use crate::{
    EngineGetBlobsParams, ExecutionServiceMessage,
    types::{PayloadAttributes, PayloadId, PayloadStatusV1},
};

pub trait ExecutionEngine<P: Preset> {
    const IS_NULL: bool;

    fn allow_optimistic_merge_block_validation(&self) -> bool;

    /// [`engine_exchangeCapabilities`](https://github.com/ethereum/execution-apis/blob/9707339bc8222f6d43b3bf0a7a91623f7ce52213/src/engine/common.md#engine_exchangecapabilities)
    fn exchange_capabilities(&self);

    /// [`engine_getBlobsV1`](https://github.com/ethereum/execution-apis/blob/9707339bc8222f6d43b3bf0a7a91623f7ce52213/src/engine/cancun.md#engine_getblobsv1)
    fn get_blobs(&self, params: EngineGetBlobsParams<P>);

    /// [`notify_forkchoice_updated`](https://github.com/ethereum/consensus-specs/blob/1bfefe301da592375e2e02f65849a96aadec1936/specs/bellatrix/fork-choice.md#notify_forkchoice_updated)
    fn notify_forkchoice_updated(
        &self,
        head_eth1_block_hash: ExecutionBlockHash,
        safe_eth1_block_hash: ExecutionBlockHash,
        finalized_eth1_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
        sender: Option<Sender<Option<PayloadId>>>,
    );

    /// [`notify_new_payload`](https://github.com/ethereum/consensus-specs/blob/1bfefe301da592375e2e02f65849a96aadec1936/specs/bellatrix/beacon-chain.md#notify_new_payload)
    fn notify_new_payload(
        &self,
        block_root: H256,
        payload: ExecutionPayload<P>,
        params: Option<ExecutionPayloadParams<P>>,
        sender: Option<Sender<Result<PayloadStatusV1>>>,
    ) -> Result<()>;

    /// [`get_pow_block`](https://github.com/ethereum/consensus-specs/blob/1bfefe301da592375e2e02f65849a96aadec1936/specs/bellatrix/fork-choice.md#get_pow_block)
    fn pow_block(&self, block_hash: ExecutionBlockHash) -> Option<TimedPowBlock>;

    fn stop(&self);
}

impl<P: Preset, E: ExecutionEngine<P>> ExecutionEngine<P> for &E {
    const IS_NULL: bool = E::IS_NULL;

    fn allow_optimistic_merge_block_validation(&self) -> bool {
        (*self).allow_optimistic_merge_block_validation()
    }

    fn exchange_capabilities(&self) {
        (*self).exchange_capabilities();
    }

    fn get_blobs(&self, params: EngineGetBlobsParams<P>) {
        (*self).get_blobs(params)
    }

    fn notify_forkchoice_updated(
        &self,
        head_eth1_block_hash: ExecutionBlockHash,
        safe_eth1_block_hash: ExecutionBlockHash,
        finalized_eth1_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
        sender: Option<Sender<Option<PayloadId>>>,
    ) {
        (*self).notify_forkchoice_updated(
            head_eth1_block_hash,
            safe_eth1_block_hash,
            finalized_eth1_block_hash,
            payload_attributes,
            sender,
        )
    }

    fn notify_new_payload(
        &self,
        beacon_block_root: H256,
        payload: ExecutionPayload<P>,
        params: Option<ExecutionPayloadParams<P>>,
        sender: Option<Sender<Result<PayloadStatusV1>>>,
    ) -> Result<()> {
        (*self).notify_new_payload(beacon_block_root, payload, params, sender)
    }

    fn pow_block(&self, block_hash: ExecutionBlockHash) -> Option<TimedPowBlock> {
        (*self).pow_block(block_hash)
    }

    fn stop(&self) {
        (*self).stop()
    }
}

impl<P: Preset, E: ExecutionEngine<P>> ExecutionEngine<P> for Arc<E> {
    const IS_NULL: bool = E::IS_NULL;

    fn allow_optimistic_merge_block_validation(&self) -> bool {
        self.as_ref().allow_optimistic_merge_block_validation()
    }

    fn exchange_capabilities(&self) {
        self.as_ref().exchange_capabilities()
    }

    fn get_blobs(&self, params: EngineGetBlobsParams<P>) {
        self.as_ref().get_blobs(params)
    }

    fn notify_forkchoice_updated(
        &self,
        head_eth1_block_hash: ExecutionBlockHash,
        safe_eth1_block_hash: ExecutionBlockHash,
        finalized_eth1_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
        sender: Option<Sender<Option<PayloadId>>>,
    ) {
        self.as_ref().notify_forkchoice_updated(
            head_eth1_block_hash,
            safe_eth1_block_hash,
            finalized_eth1_block_hash,
            payload_attributes,
            sender,
        )
    }

    fn notify_new_payload(
        &self,
        beacon_block_root: H256,
        payload: ExecutionPayload<P>,
        params: Option<ExecutionPayloadParams<P>>,
        sender: Option<Sender<Result<PayloadStatusV1>>>,
    ) -> Result<()> {
        self.as_ref()
            .notify_new_payload(beacon_block_root, payload, params, sender)
    }

    fn pow_block(&self, block_hash: ExecutionBlockHash) -> Option<TimedPowBlock> {
        self.as_ref().pow_block(block_hash)
    }

    fn stop(&self) {
        self.as_ref().stop()
    }
}

impl<P: Preset, E: ExecutionEngine<P>> ExecutionEngine<P> for Mutex<E> {
    const IS_NULL: bool = E::IS_NULL;

    fn allow_optimistic_merge_block_validation(&self) -> bool {
        self.lock()
            .expect("execution engine mutex is poisoned")
            .allow_optimistic_merge_block_validation()
    }

    fn exchange_capabilities(&self) {
        self.lock()
            .expect("execution engine mutex is poisoned")
            .exchange_capabilities()
    }

    fn get_blobs(&self, params: EngineGetBlobsParams<P>) {
        self.lock()
            .expect("execution engine mutex is poisoned")
            .get_blobs(params)
    }

    fn notify_forkchoice_updated(
        &self,
        head_eth1_block_hash: ExecutionBlockHash,
        safe_eth1_block_hash: ExecutionBlockHash,
        finalized_eth1_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
        sender: Option<Sender<Option<PayloadId>>>,
    ) {
        self.lock()
            .expect("execution engine mutex is poisoned")
            .notify_forkchoice_updated(
                head_eth1_block_hash,
                safe_eth1_block_hash,
                finalized_eth1_block_hash,
                payload_attributes,
                sender,
            )
    }

    fn notify_new_payload(
        &self,
        beacon_block_root: H256,
        payload: ExecutionPayload<P>,
        params: Option<ExecutionPayloadParams<P>>,
        sender: Option<Sender<Result<PayloadStatusV1>>>,
    ) -> Result<()> {
        self.lock()
            .expect("execution engine mutex is poisoned")
            .notify_new_payload(beacon_block_root, payload, params, sender)
    }

    fn pow_block(&self, block_hash: ExecutionBlockHash) -> Option<TimedPowBlock> {
        self.lock()
            .expect("execution engine mutex is poisoned")
            .pow_block(block_hash)
    }

    fn stop(&self) {
        self.lock()
            .expect("execution engine mutex is poisoned")
            .stop()
    }
}

#[derive(Clone, Copy)]
pub struct NullExecutionEngine;

impl<P: Preset> ExecutionEngine<P> for NullExecutionEngine {
    const IS_NULL: bool = true;

    fn allow_optimistic_merge_block_validation(&self) -> bool {
        false
    }

    fn exchange_capabilities(&self) {}

    fn get_blobs(&self, _params: EngineGetBlobsParams<P>) {}

    fn notify_forkchoice_updated(
        &self,
        _head_eth1_block_hash: ExecutionBlockHash,
        _safe_eth1_block_hash: ExecutionBlockHash,
        _finalized_eth1_block_hash: ExecutionBlockHash,
        _payload_attributes: Either<Phase, PayloadAttributes<P>>,
        _sender: Option<Sender<Option<PayloadId>>>,
    ) {
    }

    fn notify_new_payload(
        &self,
        _beacon_block_root: H256,
        _payload: ExecutionPayload<P>,
        _params: Option<ExecutionPayloadParams<P>>,
        _sender: Option<Sender<Result<PayloadStatusV1>>>,
    ) -> Result<()> {
        Ok(())
    }

    fn pow_block(&self, _block_hash: ExecutionBlockHash) -> Option<TimedPowBlock> {
        None
    }

    fn stop(&self) {}
}

pub struct MockExecutionEngine<P: Preset> {
    execution_valid: bool,
    optimistic_merge_block_validation: bool,
    pow_blocks: HashMap<ExecutionBlockHash, TimedPowBlock>,
    execution_service_tx: Option<UnboundedSender<ExecutionServiceMessage<P>>>,
}

impl<P: Preset> ExecutionEngine<P> for MockExecutionEngine<P> {
    const IS_NULL: bool = false;

    fn allow_optimistic_merge_block_validation(&self) -> bool {
        self.optimistic_merge_block_validation
    }

    fn exchange_capabilities(&self) {}

    fn get_blobs(&self, params: EngineGetBlobsParams<P>) {
        if let Some(sender) = self.execution_service_tx.as_ref() {
            ExecutionServiceMessage::GetBlobs(params).send(sender);
        }
    }

    fn notify_forkchoice_updated(
        &self,
        _head_eth1_block_hash: ExecutionBlockHash,
        _safe_eth1_block_hash: ExecutionBlockHash,
        _finalized_eth1_block_hash: ExecutionBlockHash,
        _payload_attributes: Either<Phase, PayloadAttributes<P>>,
        _sender: Option<Sender<Option<PayloadId>>>,
    ) {
    }

    fn notify_new_payload(
        &self,
        _beacon_block_root: H256,
        _payload: ExecutionPayload<P>,
        _params: Option<ExecutionPayloadParams<P>>,
        _sender: Option<Sender<Result<PayloadStatusV1>>>,
    ) -> Result<()> {
        ensure!(self.execution_valid, Error);
        Ok(())
    }

    fn pow_block(&self, block_hash: ExecutionBlockHash) -> Option<TimedPowBlock> {
        self.pow_blocks.get(&block_hash).copied()
    }

    fn stop(&self) {}
}

impl<P: Preset> MockExecutionEngine<P> {
    #[must_use]
    pub fn new(
        execution_valid: bool,
        optimistic_merge_block_validation: bool,
        execution_service_tx: Option<UnboundedSender<ExecutionServiceMessage<P>>>,
    ) -> Self {
        Self {
            optimistic_merge_block_validation,
            execution_valid,
            pow_blocks: HashMap::new(),
            execution_service_tx,
        }
    }

    pub fn insert_pow_block(&mut self, block_hash: ExecutionBlockHash, pow_block: TimedPowBlock) {
        self.pow_blocks.insert(block_hash, pow_block);
    }
}

#[derive(Debug, Error)]
#[error("execution payload not valid")]
struct Error;
