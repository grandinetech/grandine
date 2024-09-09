use std::sync::Arc;

use anyhow::{Context as _, Result};
use eth1_api::{Eth1Api, Eth1ApiToMetrics, Eth1Block};
use futures::channel::mpsc::UnboundedSender;
use tracing::{info, warn};
use prometheus_metrics::Metrics;
use reqwest::Client;
use std_ext::ArcExt as _;
use thiserror::Error;
use types::{config::Config as ChainConfig, phase0::primitives::ExecutionBlockNumber};

use crate::{Eth1Cache, Eth1Config};

const BLOCK_BATCH_SIZE: u64 = 1000;
const DEPOSIT_BATCH_SIZE: u64 = 1_000;
const DOWNLOAD_DISTANCE_FROM_HEAD: u64 = 5000;

#[derive(Debug, Error)]
pub enum Error {
    #[error("error while downloading Eth1 blocks")]
    ConnectionError,
    #[error("could not find deposit contract on Eth1 chain")]
    DepositContractNotFound,
}

pub struct DownloadManager {
    chain_config: Arc<ChainConfig>,
    eth1_config: Arc<Eth1Config>,
    api: Eth1Api,
    cache: Arc<Eth1Cache>,
}

impl DownloadManager {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        eth1_config: Arc<Eth1Config>,
        client: Client,
        cache: Arc<Eth1Cache>,
        eth1_api_to_metrics_tx: Option<UnboundedSender<Eth1ApiToMetrics>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let api = Eth1Api::new(
            chain_config.clone_arc(),
            client,
            eth1_config.eth1_auth.clone_arc(),
            eth1_config.eth1_rpc_urls.clone(),
            eth1_api_to_metrics_tx,
            metrics,
        );

        Self {
            chain_config,
            eth1_config,
            api,
            cache,
        }
    }

    pub async fn download_and_store_blocks(&self) -> Result<()> {
        let starting_block_number = {
            if let Some(block) = self.cache.get_latest_block()? {
                features::log!(
                    DebugEth1,
                    "latest cached Eth1 block number: {}",
                    block.number,
                );

                block.number + 1
            } else {
                self.earliest_downloadable_block_number().await?
            }
        };

        let latest_downloadable_block = self.latest_downloadable_block_number().await?;

        let mut from_block = starting_block_number
            .max(latest_downloadable_block.saturating_sub(DOWNLOAD_DISTANCE_FROM_HEAD) + 1);

        if from_block <= latest_downloadable_block {
            features::log!(
                DebugEth1,
                "will download Eth1 blocks from block {} to block {}",
                from_block,
                latest_downloadable_block,
            );
        }

        while from_block <= latest_downloadable_block {
            let to_block = latest_downloadable_block.min(from_block + BLOCK_BATCH_SIZE - 1);

            features::log!(
                DebugEth1,
                "downloading Eth1 blocks from block {from_block} to block {to_block}",
            );

            let blocks = self
                .api
                .get_blocks(from_block..=to_block)
                .await
                .context(Error::ConnectionError)?;

            info!(
                "downloaded {} Eth1 blocks from block {from_block} to block {to_block}",
                blocks.len(),
            );

            if !Self::verify_blocks(&blocks) {
                warn!(
                    "Fetched invalid eth1 block batch: {} (from {from_block} to {to_block})",
                    blocks.len(),
                );

                // If invalid batch is received, stop downloading blocks.
                // Download will resume when new fetch blocks task starts.
                break;
            }

            self.cache.put_blocks(blocks)?;

            from_block = to_block + 1;
        }

        Ok(())
    }

    pub async fn download_and_store_deposits(&self) -> Result<ExecutionBlockNumber> {
        let earliest_block_number = self.earliest_downloadable_block_number().await?;
        let starting_block_number = self
            .cache
            .get_deposit_tree()?
            .expect("initial deposit tree is created when ETH1 chain is initialized")
            .last_added_block_number
            .max(earliest_block_number);
        let latest_block_number = self
            .latest_downloadable_block_number()
            .await?
            .saturating_sub(DOWNLOAD_DISTANCE_FROM_HEAD);

        features::log!(
            DebugEth1,
            "Download Deposits: \
             earliest_block_number: {earliest_block_number}, \
             starting_block_number: {starting_block_number}, \
             latest_block_number: {latest_block_number}",
        );

        let mut from_block = starting_block_number + 1;

        if from_block <= latest_block_number {
            info!(
                "will download Eth1 deposits from block {} to block {}",
                from_block, latest_block_number,
            );
        }

        while from_block <= latest_block_number {
            let to_block = latest_block_number.min(from_block + DEPOSIT_BATCH_SIZE - 1);

            info!("downloading Eth1 deposits from block {from_block} to block {to_block}");

            let deposit_event_map = self.api.get_deposit_events(from_block..=to_block).await?;
            let deposit_events = deposit_event_map.values().flatten().collect();

            if let Err(error) = self.cache.add_deposits(deposit_events, to_block) {
                warn!("{error:?}");
                break;
            }

            from_block = to_block + 1;
        }

        Ok(from_block - 1)
    }

    pub async fn is_deposit_tree_up_to_date(
        &self,
        last_added_block_number: ExecutionBlockNumber,
    ) -> Result<bool> {
        let latest_block_number = self.latest_downloadable_block_number().await?;
        Ok(last_added_block_number
            >= latest_block_number.saturating_sub(DOWNLOAD_DISTANCE_FROM_HEAD))
    }

    async fn earliest_downloadable_block_number(&self) -> Result<ExecutionBlockNumber> {
        if let Some(block_num) = self.eth1_config.deposit_contract_starting_block {
            Ok(block_num)
        } else {
            self.api
                .get_first_deposit_contract_block_number()
                .await
                .context(Error::ConnectionError)?
                .ok_or(Error::DepositContractNotFound)
                .map_err(Into::into)
        }
    }

    async fn latest_downloadable_block_number(&self) -> Result<ExecutionBlockNumber> {
        // Respect the Eth1 follow distance
        Ok(self
            .api
            .current_head_number()
            .await
            .context(Error::ConnectionError)?
            .saturating_sub(self.chain_config.eth1_follow_distance))
    }

    fn verify_blocks(blocks: &[Eth1Block]) -> bool {
        let mut iter = blocks.iter().rev();

        if let Some(latest_block) = iter.next() {
            let mut block = latest_block;

            for parent_block in iter {
                if block.parent_hash != parent_block.hash {
                    features::log!(
                        DebugEth1,
                        "Cannot verify eth1 block: block.parent_hash: {}, parent_block.hash {}",
                        block.parent_hash,
                        parent_block.hash,
                    );

                    return false;
                }

                block = parent_block;
            }
        }

        true
    }
}
