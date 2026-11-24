// A fork choice controller for tests in this crate and in crates that depend on it.

use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use crossbeam_utils::sync::WaitGroup;
use execution_engine::ExecutionServiceMessage;
use fork_choice_control::{Controller, EventChannels, Storage, controller::MutatorHandle};
use futures::channel::mpsc::UnboundedSender;
use pubkey_cache::PubkeyCache;
use reqwest::Client;
use std_ext::ArcExt as _;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::StorageMode,
    preset::Preset,
    redacting_url::RedactingUrl,
};

use crate::{ApiController, Eth1Api, Eth1ExecutionEngine};

pub struct TestChain<P: Preset> {
    pub api: Arc<Eth1Api>,
    pub controller: ApiController<P, WaitGroup>,
    pub mutator_handle: MutatorHandle<P, WaitGroup>,
    pub execution_engine: Arc<Eth1ExecutionEngine<P>>,
    pub event_channels: Arc<EventChannels<P>>,
}

impl<P: Preset> TestChain<P> {
    // A controller over an in-memory database, starting at `tick`.
    // Its execution engine sends its requests to `execution_service_tx`.
    // `api` talks to `execution_endpoint`, if any.
    #[expect(
        clippy::default_trait_access,
        reason = "`StoreConfig` is in `fork_choice_store`, which this crate does not depend on"
    )]
    pub fn new(
        config: &Arc<Config>,
        pubkey_cache: &Arc<PubkeyCache>,
        anchor_block: Arc<SignedBeaconBlock<P>>,
        anchor_state: Arc<BeaconState<P>>,
        tick: clock::Tick,
        execution_endpoint: Option<RedactingUrl>,
        execution_service_tx: UnboundedSender<ExecutionServiceMessage<P>>,
    ) -> Result<Self> {
        let api = Arc::new(Eth1Api::new(
            config.clone_arc(),
            Client::new(),
            Arc::default(),
            execution_endpoint,
            None,
            None,
        ));

        let execution_engine = Arc::new(Eth1ExecutionEngine::new(
            config.clone_arc(),
            api.clone_arc(),
            execution_service_tx,
        ));

        let event_channels = Arc::new(EventChannels::default());

        let storage = Arc::new(Storage::new(
            config.clone_arc(),
            pubkey_cache.clone_arc(),
            database::Database::in_memory(),
            StorageMode::default(),
            true,
            fork_choice_control::DEFAULT_ZSTD_COMPRESSION_LEVEL,
            fork_choice_control::StateStorageConfig::default_for_mode(StorageMode::default()),
        )?);

        let (controller, mutator_handle) = Controller::new(
            config.clone_arc(),
            pubkey_cache.clone_arc(),
            Default::default(),
            anchor_block,
            anchor_state,
            tick,
            event_channels.clone_arc(),
            execution_engine.clone_arc(),
            None,
            futures::channel::mpsc::unbounded().0,
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            futures::sink::drain(),
            storage,
            core::iter::empty(),
            true,
            HashSet::default(),
            Arc::default(),
            Some(2),
        )?;

        Ok(Self {
            api,
            controller,
            mutator_handle,
            execution_engine,
            event_channels,
        })
    }
}
