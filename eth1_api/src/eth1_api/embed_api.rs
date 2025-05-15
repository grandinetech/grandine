use anyhow::{bail, Result};
use core::ops::RangeInclusive;
use either::Either;
use enum_iterator::Sequence as _;
use ethereum_types::H64;
use execution_engine::{
    BlobAndProofV1, BlobAndProofV2, EngineGetPayloadV1Response, EngineGetPayloadV2Response,
    EngineGetPayloadV3Response, EngineGetPayloadV4Response, EngineGetPayloadV5Response,
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, ForkChoiceStateV1,
    ForkChoiceUpdatedResponse, PayloadAttributes, PayloadAttributesV1, PayloadAttributesV2,
    PayloadAttributesV3, PayloadId, PayloadStatusV1,
};
use futures::channel::mpsc::UnboundedSender;
use prometheus_metrics::Metrics;
use reqwest::Client;
use serde::Deserialize;
use ssz::H256;
use static_assertions::const_assert_eq;
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock},
};
use std_ext::CopyExt;
use thiserror::Error;
use types::{
    combined::{ExecutionPayload, ExecutionPayloadParams},
    config::Config,
    deneb::primitives::VersionedHash,
    electra::containers::ExecutionRequests,
    nonstandard::{Phase, WithBlobsAndMev},
    phase0::primitives::{ExecutionBlockHash, ExecutionBlockNumber},
    preset::{Mainnet, Preset},
    redacting_url::RedactingUrl,
};
use web3::types::{BlockId, BlockNumber, Filter, FilterBuilder, Log, U64};

use crate::{
    auth::Auth,
    deposit_event::DepositEvent,
    endpoints::Endpoint,
    eth1_api::{
        ENGINE_FORKCHOICE_UPDATED_V1, ENGINE_FORKCHOICE_UPDATED_V2, ENGINE_FORKCHOICE_UPDATED_V3,
        ENGINE_GET_EL_BLOBS_V1, ENGINE_GET_EL_BLOBS_V2, ENGINE_GET_PAYLOAD_V1,
        ENGINE_GET_PAYLOAD_V2, ENGINE_GET_PAYLOAD_V3, ENGINE_GET_PAYLOAD_V4, ENGINE_GET_PAYLOAD_V5,
        ENGINE_NEW_PAYLOAD_V1, ENGINE_NEW_PAYLOAD_V2, ENGINE_NEW_PAYLOAD_V3, ENGINE_NEW_PAYLOAD_V4,
    },
    eth1_block::Eth1Block,
    Eth1ApiToMetrics, WithClientVersions,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawForkChoiceUpdatedResponse {
    pub payload_status: PayloadStatusV1,
    pub payload_id: Option<H64>,
}

pub trait EmbedAdapter: Send + Sync {
    fn eth_block_number(&self) -> Result<ExecutionBlockNumber>;
    fn eth_get_block_by_hash(&self, hash: H256) -> Result<Option<Eth1Block>>;
    fn eth_get_block_by_number(&self, number: BlockNumber) -> Result<Option<Eth1Block>>;
    fn eth_logs(&self, filter: Filter) -> Result<Vec<Log>>;

    fn engine_new_payload_v1(
        &self,
        payload: ExecutionPayloadV1<Mainnet>,
    ) -> Result<PayloadStatusV1>;
    fn engine_new_payload_v2(
        &self,
        payload: ExecutionPayloadV2<Mainnet>,
    ) -> Result<PayloadStatusV1>;
    fn engine_new_payload_v3(
        &self,
        payload: ExecutionPayloadV3<Mainnet>,
        versioned_hashes: Vec<H256>,
        parent_beacon_block_root: H256,
    ) -> Result<PayloadStatusV1>;
    fn engine_new_payload_v4(
        &self,
        payload: ExecutionPayloadV3<Mainnet>,
        versioned_hashes: Vec<H256>,
        parent_beacon_block_root: H256,
        execution_requests: ExecutionRequests<Mainnet>,
    ) -> Result<PayloadStatusV1>;

    fn engine_forkchoice_updated_v1(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV1>,
    ) -> Result<RawForkChoiceUpdatedResponse>;
    fn engine_forkchoice_updated_v2(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV2<Mainnet>>,
    ) -> Result<RawForkChoiceUpdatedResponse>;
    fn engine_forkchoice_updated_v3(
        &self,
        state: ForkChoiceStateV1,
        payload: Option<PayloadAttributesV3<Mainnet>>,
    ) -> Result<RawForkChoiceUpdatedResponse>;

    fn engine_get_payload_v1(&self, payload_id: H64)
        -> Result<EngineGetPayloadV1Response<Mainnet>>;
    fn engine_get_payload_v2(&self, payload_id: H64)
        -> Result<EngineGetPayloadV2Response<Mainnet>>;
    fn engine_get_payload_v3(&self, payload_id: H64)
        -> Result<EngineGetPayloadV3Response<Mainnet>>;
    fn engine_get_payload_v4(&self, payload_id: H64)
        -> Result<EngineGetPayloadV4Response<Mainnet>>;
    fn engine_get_payload_v5(&self, payload_id: H64)
        -> Result<EngineGetPayloadV5Response<Mainnet>>;

    fn engine_get_blobs_v1(
        &self,
        versioned_hashes: Vec<VersionedHash>,
    ) -> Result<Vec<Option<BlobAndProofV1<Mainnet>>>>;
    fn engine_get_blobs_v2(
        &self,
        versioned_hashes: Vec<VersionedHash>,
    ) -> Result<Option<Vec<BlobAndProofV2<Mainnet>>>>;
}

static CURRENT_ADAPTER: OnceLock<Arc<Box<dyn EmbedAdapter>>> = OnceLock::new();

#[derive(Debug, Error)]
enum Error {
    #[error("Adapter already set")]
    AdapterAlreadySet,
    #[error("Adapter is not initialized")]
    AdapterNotInitialized,
    #[error("attempted to call Eth1 RPC endpoint with misconfigured parameters")]
    InvalidParameters,
    #[error("only mainnet preset supported for embedded client")]
    InvalidPreset,
    #[error("pre-Bellatrix phase passed to Eth1Api::forkchoice_updated")]
    PhasePreBellatrix,
}

pub fn set_adapter(adapter: Box<dyn EmbedAdapter>) -> Result<()> {
    CURRENT_ADAPTER
        .set(Arc::new(adapter))
        .map_err(|_| Error::AdapterAlreadySet.into())
}

pub struct Eth1Api {
    config: Arc<Config>,
    pub(crate) metrics: Option<Arc<Metrics>>,
}

impl Eth1Api {
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        _client: Client,
        _auth: Arc<Auth>,
        _eth1_rpc_urls: Vec<RedactingUrl>,
        _eth1_api_to_metrics_tx: Option<UnboundedSender<Eth1ApiToMetrics>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self { config, metrics }
    }

    async fn exec<T: Send + Sync + 'static>(
        &self,
        fun: impl FnOnce(&Box<dyn EmbedAdapter>) -> Result<T> + Send + Sync + 'static,
    ) -> Result<T> {
        let adapter = CURRENT_ADAPTER
            .get()
            .cloned()
            .ok_or(Error::AdapterNotInitialized)?;
        let res = tokio::task::spawn_blocking(move || fun(&adapter));

        res.await.map_err(Into::into).flatten()
    }

    pub async fn current_head_number(&self) -> Result<ExecutionBlockNumber> {
        self.exec(|adapter| adapter.eth_block_number()).await
    }

    pub async fn get_block(&self, block_id: BlockId) -> Result<Option<Eth1Block>> {
        match block_id {
            BlockId::Hash(hash) => {
                self.exec(move |adapter| adapter.eth_get_block_by_hash(hash))
                    .await
            }
            BlockId::Number(number) => {
                self.exec(move |adapter| adapter.eth_get_block_by_number(number))
                    .await
            }
        }
    }

    pub async fn get_block_by_number(
        &self,
        block_number: ExecutionBlockNumber,
    ) -> Result<Option<Eth1Block>> {
        self.get_block(U64::from(block_number).into()).await
    }

    pub async fn get_block_by_hash(
        &self,
        block_hash: ExecutionBlockHash,
    ) -> Result<Option<Eth1Block>> {
        self.get_block(block_hash.into()).await
    }

    pub async fn get_first_deposit_contract_block_number(
        &self,
    ) -> Result<Option<ExecutionBlockNumber>> {
        // `BlockNumber::Earliest` is necessary to get all logs.
        // `BlockNumber::Latest` is the default (in the JSON RPC, not in `web3`). See:
        // - <https://github.com/ethereum/wiki/wiki/JSON-RPC/b729c267fd71d9ba92ce6b90023caabc486ca5ae#eth_getlogs>
        // - <https://github.com/paritytech/wiki/blob/bc0952d26528de087993049fc72e4f6f003e688f/JSONRPC-eth-module.md#eth_newfilter>
        let filter = FilterBuilder::default()
            .from_block(BlockNumber::Earliest)
            .address(vec![self.config.deposit_contract_address])
            .limit(1)
            .build();

        let logs = self.exec(|adapter| adapter.eth_logs(filter)).await?;

        if let Some(log) = logs.first() {
            if let Some(block_number) = log.block_number {
                return Ok(Some(block_number.as_u64()));
            }
        }

        Ok(None)
    }

    pub async fn get_blocks(
        &self,
        block_number_range: RangeInclusive<ExecutionBlockNumber>,
    ) -> Result<Vec<Eth1Block>> {
        let mut deposit_data = self.get_deposit_events(block_number_range.clone()).await?;
        let mut blocks = vec![];

        for block_number in block_number_range {
            match self.get_block_by_number(block_number).await? {
                Some(block) => {
                    let deposit_events = deposit_data.remove(&block_number).unwrap_or_default();
                    let eth1_block = Eth1Block {
                        deposit_events: deposit_events.try_into()?,
                        ..block
                    };
                    blocks.push(eth1_block);
                }
                None => continue,
            }
        }

        Ok(blocks)
    }

    pub async fn get_deposit_events(
        &self,
        block_number_range: RangeInclusive<ExecutionBlockNumber>,
    ) -> Result<BTreeMap<ExecutionBlockNumber, Vec<DepositEvent>>> {
        // Sepolia uses a custom contract that emits events other than `DepositEvent`. See:
        // - <https://github.com/ethereum/pm/issues/526>
        // - <https://github.com/protolambda/testnet-dep-contract/blob/8df70175dca186b74197ec830450c4b988861746/deposit_contract.sol>
        // - <https://notes.ethereum.org/zvkfSmYnT0-uxwwEegbCqg>
        // - <https://sepolia.etherscan.io/address/0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D#events>
        // - <https://sepolia.etherscan.io/token/0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D>
        let filter = FilterBuilder::default()
            .from_block(block_number_range.start().copy().into())
            .to_block(block_number_range.end().copy().into())
            .address(vec![self.config.deposit_contract_address])
            .topics(Some(vec![DepositEvent::TOPIC]), None, None, None)
            .build();

        let mut deposit_events = BTreeMap::<_, Vec<_>>::new();

        for log in self
            .exec(move |adapter| adapter.eth_logs(filter.clone()))
            .await?
        {
            let block_number = match log.block_number {
                Some(block_number) => block_number.as_u64(),
                None => continue,
            };

            let deposit_event = DepositEvent::try_from(log)?;

            deposit_events
                .entry(block_number)
                .or_default()
                .push(deposit_event);
        }

        Ok(deposit_events)
    }

    /// Calls [`engine_newPayloadV1`] or [`engine_newPayloadV2`] or [`engine_newPayloadV3`] or [`engine_newPayloadV4`] depending on `payload`.
    ///
    /// Later versions of `engine_newPayload` accept parameters of all prior versions,
    /// but using the earlier versions allows the application to work with old execution clients.
    ///
    /// [`engine_newPayloadV1`]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#engine_newpayloadv1
    /// [`engine_newPayloadV2`]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/shanghai.md#engine_newpayloadv2
    /// [`engine_newPayloadV3`]: https://github.com/ethereum/execution-apis/blob/a0d03086564ab1838b462befbc083f873dcf0c0f/src/engine/cancun.md#engine_newpayloadv3
    /// [`engine_newPayloadV4`]: https://github.com/ethereum/execution-apis/blob/4140e528360fea53c34a766d86a000c6c039100e/src/engine/prague.md#engine_newpayloadv4
    pub async fn new_payload<P: Preset>(
        &self,
        payload: ExecutionPayload<P>,
        params: Option<ExecutionPayloadParams<P>>,
    ) -> Result<PayloadStatusV1> {
        let payload: &dyn std::any::Any = &payload;
        let payload: &ExecutionPayload<Mainnet> =
            payload.downcast_ref().ok_or(Error::InvalidPreset)?;
        let payload = payload.clone();

        let params: Option<ExecutionPayloadParams<Mainnet>> = params
            .map(|value| -> Result<ExecutionPayloadParams<Mainnet>> {
                let value: &dyn std::any::Any = &value;
                let value: &ExecutionPayloadParams<Mainnet> =
                    value.downcast_ref().ok_or(Error::InvalidPreset)?;

                Ok(value.clone())
            })
            .transpose()?;

        match (payload, params) {
            (ExecutionPayload::Bellatrix(payload), None) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_NEW_PAYLOAD_V1,
                    )
                });

                let payload_v1 = ExecutionPayloadV1::from(payload);

                self.exec(move |adapter| adapter.engine_new_payload_v1(payload_v1))
                    .await
            }
            (ExecutionPayload::Capella(payload), None) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_NEW_PAYLOAD_V2,
                    )
                });

                let payload_v2 = ExecutionPayloadV2::from(payload);

                self.exec(move |adapter| adapter.engine_new_payload_v2(payload_v2))
                    .await
            }
            (
                ExecutionPayload::Deneb(payload),
                Some(ExecutionPayloadParams::Deneb {
                    versioned_hashes,
                    parent_beacon_block_root,
                }),
            ) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_NEW_PAYLOAD_V3,
                    )
                });

                let payload_v3 = ExecutionPayloadV3::from(payload);

                self.exec(move |adapter| {
                    adapter.engine_new_payload_v3(
                        payload_v3,
                        versioned_hashes,
                        parent_beacon_block_root,
                    )
                })
                .await
            }
            (
                ExecutionPayload::Deneb(payload),
                Some(ExecutionPayloadParams::Electra {
                    versioned_hashes,
                    parent_beacon_block_root,
                    execution_requests,
                }),
            ) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_NEW_PAYLOAD_V4,
                    )
                });

                let payload_v3 = ExecutionPayloadV3::from(payload);

                self.exec(move |adapter| {
                    adapter.engine_new_payload_v4(
                        payload_v3,
                        versioned_hashes,
                        parent_beacon_block_root,
                        execution_requests,
                    )
                })
                .await
            }
            _ => bail!(Error::InvalidParameters),
        }
    }

    /// Calls [`engine_forkchoiceUpdatedV1`] or [`engine_forkchoiceUpdatedV2`] or [`engine_forkchoiceUpdatedV3`] depending on `payload_attributes`.
    ///
    /// Later versions of `engine_forkchoiceUpdated` accept parameters of all prior versions,
    /// but using the earlier versions allows the application to work with old execution clients.
    ///
    /// [`engine_forkchoiceUpdatedV1`]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#engine_forkchoiceupdatedv1
    /// [`engine_forkchoiceUpdatedV2`]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/shanghai.md#engine_forkchoiceupdatedv2
    /// [`engine_forkchoiceUpdatedV3`]: https://github.com/ethereum/execution-apis/blob/a0d03086564ab1838b462befbc083f873dcf0c0f/src/engine/cancun.md#engine_forkchoiceupdatedv3
    pub async fn forkchoice_updated<P: Preset>(
        &self,
        head_block_hash: ExecutionBlockHash,
        safe_block_hash: ExecutionBlockHash,
        finalized_block_hash: ExecutionBlockHash,
        payload_attributes: Either<Phase, PayloadAttributes<P>>,
    ) -> Result<ForkChoiceUpdatedResponse> {
        let fork_choice_state = ForkChoiceStateV1 {
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
        };

        let phase = payload_attributes
            .as_ref()
            .either(CopyExt::copy, PayloadAttributes::phase);

        let payload_attributes = payload_attributes.right();
        let payload_attributes = payload_attributes
            .map(|value| -> Result<PayloadAttributes<Mainnet>> {
                let value: &dyn std::any::Any = &value;
                let value: &PayloadAttributes<Mainnet> =
                    value.downcast_ref().ok_or(Error::InvalidPreset)?;

                Ok(value.clone())
            })
            .transpose()?;

        let RawForkChoiceUpdatedResponse {
            payload_id,
            payload_status,
        } = match phase {
            Phase::Bellatrix => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_FORKCHOICE_UPDATED_V1,
                    )
                });

                let payload_attributes = payload_attributes
                    .map(|value| {
                        if let PayloadAttributes::Bellatrix(value) = value {
                            Ok(value)
                        } else {
                            Err(Error::InvalidParameters)
                        }
                    })
                    .transpose()?
                    .clone();

                self.exec(move |adapter| {
                    adapter.engine_forkchoice_updated_v1(fork_choice_state, payload_attributes)
                })
                .await?
            }
            Phase::Capella => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_FORKCHOICE_UPDATED_V2,
                    )
                });

                let payload_attributes = payload_attributes
                    .map(|value| {
                        if let PayloadAttributes::Capella(value) = value {
                            Ok(value)
                        } else {
                            Err(Error::InvalidParameters)
                        }
                    })
                    .transpose()?
                    .clone();

                self.exec(move |adapter| {
                    adapter.engine_forkchoice_updated_v2(fork_choice_state, payload_attributes)
                })
                .await?
            }
            Phase::Deneb | Phase::Electra | Phase::Fulu => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_FORKCHOICE_UPDATED_V3,
                    )
                });

                let payload_attributes = payload_attributes
                    .map(|value| {
                        if let PayloadAttributes::Deneb(value)
                        | PayloadAttributes::Electra(value)
                        | PayloadAttributes::Fulu(value) = value
                        {
                            Ok(value)
                        } else {
                            Err(Error::InvalidParameters)
                        }
                    })
                    .transpose()?
                    .clone();

                self.exec(move |adapter| {
                    adapter.engine_forkchoice_updated_v3(fork_choice_state, payload_attributes)
                })
                .await?
            }
            _ => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 7);

                bail!(Error::PhasePreBellatrix)
            }
        };

        let payload_id = match phase {
            Phase::Bellatrix => payload_id.map(PayloadId::Bellatrix),
            Phase::Capella => payload_id.map(PayloadId::Capella),
            Phase::Deneb => payload_id.map(PayloadId::Deneb),
            Phase::Electra => payload_id.map(PayloadId::Electra),
            Phase::Fulu => payload_id.map(PayloadId::Fulu),
            _ => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 7);

                bail!(Error::PhasePreBellatrix)
            }
        };

        Ok(ForkChoiceUpdatedResponse {
            payload_status,
            payload_id,
        })
    }

    /// Calls [`engine_getPayloadV1`] or [`engine_getPayloadV2`] or [`engine_getPayloadV3`] or [`engine_getPayloadV4`] or [`engine_getPayloadV5`] depending on `payload_id`.
    ///
    /// Newer versions of the method may be used to request payloads from all prior versions,
    /// but using the old methods allows the application to work with old execution clients.
    ///
    /// [`engine_getPayloadV1`]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#engine_getpayloadv1
    /// [`engine_getPayloadV2`]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/shanghai.md#engine_getpayloadv2
    /// [`engine_getPayloadV3`]: https://github.com/ethereum/execution-apis/blob/a0d03086564ab1838b462befbc083f873dcf0c0f/src/engine/cancun.md#engine_getpayloadv3
    /// [`engine_getPayloadV4`]: https://github.com/ethereum/execution-apis/blob/4140e528360fea53c34a766d86a000c6c039100e/src/engine/prague.md#engine_getpayloadv4
    /// [`engine_getPayloadV5`]: https://github.com/ethereum/execution-apis/blob/5d634063ccfd897a6974ea589c00e2c1d889abc9/src/engine/osaka.md#engine_getpayloadv5
    pub async fn get_payload<P: Preset>(
        &self,
        payload_id: PayloadId,
    ) -> Result<WithClientVersions<WithBlobsAndMev<ExecutionPayload<P>, P>>> {
        match payload_id {
            PayloadId::Bellatrix(payload_id) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_GET_PAYLOAD_V1,
                    )
                });

                let value = self
                    .exec(move |adapter| adapter.engine_get_payload_v1(payload_id))
                    .await?;

                let value: &dyn std::any::Any = &value;
                let value: &EngineGetPayloadV1Response<P> =
                    value.downcast_ref().ok_or(Error::InvalidPreset)?;
                let value = value.clone();

                Ok(WithClientVersions::none(value).map(Into::into))
            }
            PayloadId::Capella(payload_id) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_GET_PAYLOAD_V2,
                    )
                });

                let value = self
                    .exec(move |adapter| adapter.engine_get_payload_v2(payload_id))
                    .await?;

                let value: &dyn std::any::Any = &value;
                let value: &EngineGetPayloadV2Response<P> =
                    value.downcast_ref().ok_or(Error::InvalidPreset)?;
                let value = value.clone();

                Ok(WithClientVersions::none(value).map(Into::into))
            }
            PayloadId::Deneb(payload_id) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_GET_PAYLOAD_V3,
                    )
                });

                let value = self
                    .exec(move |adapter| adapter.engine_get_payload_v3(payload_id))
                    .await?;

                let value: &dyn std::any::Any = &value;
                let value: &EngineGetPayloadV3Response<P> =
                    value.downcast_ref().ok_or(Error::InvalidPreset)?;
                let value = value.clone();

                Ok(WithClientVersions::none(value).map(Into::into))
            }
            PayloadId::Electra(payload_id) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_GET_PAYLOAD_V4,
                    )
                });

                let value = self
                    .exec(move |adapter| adapter.engine_get_payload_v4(payload_id))
                    .await?;

                let value: &dyn std::any::Any = &value;
                let value: &EngineGetPayloadV4Response<P> =
                    value.downcast_ref().ok_or(Error::InvalidPreset)?;
                let value = value.clone();

                Ok(WithClientVersions::none(value).map(Into::into))
            }
            PayloadId::Fulu(payload_id) => {
                let _timer = self.metrics.as_ref().map(|metrics| {
                    prometheus_metrics::start_timer_vec(
                        &metrics.eth1_api_request_times,
                        ENGINE_GET_PAYLOAD_V5,
                    )
                });

                let value = self
                    .exec(move |adapter| adapter.engine_get_payload_v5(payload_id))
                    .await?;

                let value: &dyn std::any::Any = &value;
                let value: &EngineGetPayloadV5Response<P> =
                    value.downcast_ref().ok_or(Error::InvalidPreset)?;
                let value = value.clone();

                Ok(WithClientVersions::none(value).map(Into::into))
            }
        }
    }

    pub(crate) async fn get_blobs_v1<P: Preset>(
        &self,
        versioned_hashes: Vec<VersionedHash>,
    ) -> Result<Vec<Option<BlobAndProofV1<P>>>> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(
                &metrics.eth1_api_request_times,
                ENGINE_GET_EL_BLOBS_V1,
            )
        });

        let results = self
            .exec(move |adapter| adapter.engine_get_blobs_v1(versioned_hashes))
            .await?;
        let results = results
            .into_iter()
            .map(|value| {
                value
                    .map(|blob| {
                        let blob: &dyn std::any::Any = &blob;
                        let blob: &BlobAndProofV1<P> =
                            blob.downcast_ref().ok_or(Error::InvalidPreset)?;
                        let blob = blob.clone();
                        Ok(blob)
                    })
                    .transpose()
            })
            .collect::<Result<Vec<Option<BlobAndProofV1<P>>>>>()?;
        Ok(results)
    }

    pub(crate) async fn get_blobs_v2<P: Preset>(
        &self,
        versioned_hashes: Vec<VersionedHash>,
    ) -> Result<Option<Vec<BlobAndProofV2<P>>>> {
        let _timer = self.metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(
                &metrics.eth1_api_request_times,
                ENGINE_GET_EL_BLOBS_V2,
            )
        });

        let results = self
            .exec(move |adapter| adapter.engine_get_blobs_v2(versioned_hashes))
            .await?;
        let results = results
            .map(|value| {
                value
                    .into_iter()
                    .map(|blob| {
                        let blob: &dyn std::any::Any = &blob;
                        let blob: &BlobAndProofV2<P> =
                            blob.downcast_ref().ok_or(Error::InvalidPreset)?;
                        let blob = blob.clone();
                        Ok(blob)
                    })
                    .collect::<Result<Vec<BlobAndProofV2<P>>>>()
            })
            .transpose()?;
        Ok(results)
    }

    pub fn el_offline(&self) -> bool {
        false
    }

    pub(crate) fn on_ok_response(&self, _endpoint: &Endpoint) {
        // do nothing
    }

    pub(crate) fn on_error_response(&self, _endpoint: &Endpoint) {
        // do nothing
    }
}
