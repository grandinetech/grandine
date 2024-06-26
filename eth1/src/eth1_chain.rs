use std::sync::{Arc, RwLock};

use anyhow::{Context as _, Error as AnyhowError, Result};
use database::Database;
use deposit_tree::DepositTree;
use eth1_api::{Auth, DepositEvent, Eth1ApiToMetrics, Eth1Block};
use futures::{
    channel::mpsc::UnboundedSender,
    stream::{Stream, TryStreamExt as _},
};
use log::{error, info};
use prometheus_metrics::Metrics;
use reqwest::Client;
use std_ext::ArcExt as _;
use thiserror::Error;
use tokio::time::Duration;
use tokio_stream::StreamExt as _;
use types::{config::Config as ChainConfig, phase0::primitives::ExecutionBlockNumber};
use url::Url;

use crate::{
    download_manager::{DownloadManager, Error as DownloadError},
    Eth1Cache,
};

const BLOCK_DOWNLOAD_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const DEPOSIT_DOWNLOAD_RETRY_INTERVAL: Duration = Duration::from_secs(3);
const STREAM_BATCH_SIZE: usize = 1000;

#[derive(Default)]
pub struct Eth1Config {
    pub eth1_auth: Arc<Auth>,
    pub eth1_rpc_urls: Vec<Url>,
    pub deposit_contract_starting_block: Option<ExecutionBlockNumber>,
    pub default_deposit_tree: Option<DepositTree>,
}

pub struct Eth1Chain {
    cache: Arc<Eth1Cache>,
    unfinalized_blocks: Arc<RwLock<Vec<Eth1Block>>>,
}

impl Eth1Chain {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        eth1_config: Arc<Eth1Config>,
        client: Client,
        database: Database,
        eth1_api_to_metrics_tx: Option<UnboundedSender<Eth1ApiToMetrics>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Result<Self> {
        let cache = Eth1Cache::new(database, eth1_config.default_deposit_tree)
            .map(Arc::new)
            .context("failed to create Eth1 cache database environment")?;

        let chain = Self {
            cache,
            unfinalized_blocks: Arc::new(RwLock::new(vec![])),
        };

        if !eth1_config.eth1_rpc_urls.is_empty() {
            chain.spawn_download_task(
                chain_config,
                eth1_config,
                client,
                eth1_api_to_metrics_tx,
                metrics,
            );
        }

        Ok(chain)
    }

    #[must_use]
    pub fn unfinalized_blocks(&self) -> &RwLock<Vec<Eth1Block>> {
        &self.unfinalized_blocks
    }

    pub fn add_deposits(
        &self,
        deposit_events: Vec<&DepositEvent>,
        block_number: ExecutionBlockNumber,
    ) -> Result<()> {
        self.cache.add_deposits(deposit_events, block_number)
    }

    pub fn load_deposit_tree(&self) -> Result<DepositTree> {
        self.cache
            .get_deposit_tree()?
            .ok_or(Error)
            .map_err(Into::into)
    }

    pub fn persist_deposit_tree(&self, deposit_tree: DepositTree) -> Result<()> {
        self.cache.put_deposit_tree(&deposit_tree)
    }

    fn spawn_download_task(
        &self,
        chain_config: Arc<ChainConfig>,
        eth1_config: Arc<Eth1Config>,
        client: Client,
        eth1_api_to_metrics_tx: Option<UnboundedSender<Eth1ApiToMetrics>>,
        metrics: Option<Arc<Metrics>>,
    ) {
        let cache = self.cache.clone_arc();

        tokio::spawn(async move {
            if let Err(error) = download_deposits_and_blocks(
                chain_config,
                eth1_config,
                client,
                cache,
                eth1_api_to_metrics_tx,
                metrics,
            )
            .await
            {
                panic!("failed to download and store Eth1 data: {error}");
            }
        });
    }

    pub fn spawn_unfinalized_blocks_tracker_task(&self) -> Result<()> {
        let unfinalized_blocks = self.unfinalized_blocks.clone_arc();
        let cache = self.cache.clone_arc();
        let deposit_tree = self.load_deposit_tree()?;

        tokio::spawn(async move {
            if let Err(error) =
                run_unfinalized_blocks_tracker(unfinalized_blocks, cache, deposit_tree).await
            {
                panic!("failed to update unfinalized Eth1 block list: {error}");
            }
        });

        Ok(())
    }

    pub fn stream_blocks(&self) -> Result<impl Stream<Item = Result<Eth1Block>>> {
        let cache = self.cache.clone_arc();
        let deposit_tree = self.load_deposit_tree()?;

        let mut last_streamed_block_number = deposit_tree.last_added_block_number;

        let batches = futures::stream::repeat_with(move || -> Result<_> {
            let blocks =
                cache.get_blocks_from(last_streamed_block_number + 1, STREAM_BATCH_SIZE)?;

            if let Some(last_block) = blocks.last() {
                last_streamed_block_number = last_block.number;
            }

            Ok(blocks)
        });

        // If there are no blocks left to stream, wait for a while.
        // `tokio_stream::StreamExt::throttle` yields the first item immediately.
        let blocks = batches
            .throttle(Duration::from_secs(1))
            .map_ok(|blocks| futures::stream::iter(blocks.into_iter().map(Ok)))
            .try_flatten()
            .inspect_ok(|block| {
                features::log!(DebugEth1, "read Eth1 block from cache: {}", block.number)
            });

        Ok(blocks)
    }

    pub fn track_collection_metrics(&self, metrics: &Arc<Metrics>) {
        metrics.set_collection_length(
            module_path!(),
            &tynm::type_name::<Self>(),
            "unfinalized_blocks",
            self.unfinalized_blocks
                .read()
                .expect("unfinalized blocks lock is poisoned")
                .len(),
        );
    }
}

#[derive(Debug, Error)]
#[error("deposit tree missing")]
struct Error;

async fn download_deposits_and_blocks(
    chain_config: Arc<ChainConfig>,
    eth1_config: Arc<Eth1Config>,
    client: Client,
    cache: Arc<Eth1Cache>,
    eth1_api_to_metrics_tx: Option<UnboundedSender<Eth1ApiToMetrics>>,
    metrics: Option<Arc<Metrics>>,
) -> Result<()> {
    info!(
        "started new Eth1 deposit download task (deposit contract {:?})",
        chain_config.deposit_contract_address,
    );

    let download_manager = DownloadManager::new(
        chain_config,
        eth1_config.clone_arc(),
        client,
        cache.clone_arc(),
        eth1_api_to_metrics_tx,
        metrics,
    );

    loop {
        info!("started Eth1 deposit download task");

        match download_manager.download_and_store_deposits().await {
            Ok(block_number) => {
                if download_manager
                    .is_deposit_tree_up_to_date(block_number)
                    .await?
                {
                    break;
                }
            }
            // If it's connection error, don't panic, only print error and try again a bit later
            Err(error) => handle_error(&error),
        }

        tokio::time::sleep(DEPOSIT_DOWNLOAD_RETRY_INTERVAL).await;
    }

    loop {
        info!("started Eth1 block download task");

        if let Err(error) = download_manager.download_and_store_blocks().await {
            handle_error(&error);
        }

        tokio::time::sleep(BLOCK_DOWNLOAD_RETRY_INTERVAL).await;
    }
}

fn handle_error(error: &AnyhowError) {
    match error.downcast_ref() {
        Some(DownloadError::ConnectionError) => error!("{error}"),
        // TODO(Grandine Team): This is supposed to be temporary.
        // _ => return Err(error),
        _ => error!("error while downloading and storing blocks: {error:?}"),
    }
}

async fn run_unfinalized_blocks_tracker(
    unfinalized_blocks: Arc<RwLock<Vec<Eth1Block>>>,
    cache: Arc<Eth1Cache>,
    deposit_tree: DepositTree,
) -> Result<()> {
    let mut last_added_block_number = deposit_tree.last_added_block_number;

    loop {
        let blocks = cache.get_blocks_from(last_added_block_number + 1, STREAM_BATCH_SIZE)?;

        features::log!(
            DebugEth1,
            "Add Eth1 blocks from cache to unfinalized blocks: {}: ({:?} - {:?})",
            blocks.len(),
            blocks.first(),
            blocks.last(),
        );

        for block in blocks {
            last_added_block_number = block.number;

            features::log!(DebugEth1, "read Eth1 block from cache: {}", block.number);

            unfinalized_blocks
                .write()
                .expect("unfinalized blocks lock is poisoned")
                .push(block);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
