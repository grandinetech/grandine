use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Result};
use chrono::{Local, TimeZone as _};
use eth1_api::{DepositEvent, Eth1Block};
use futures::stream::{Stream, TryStreamExt as _};
use genesis::Incremental;
use log::info;
use pubkey_cache::PubkeyCache;
use ssz::{SszRead as _, SszWrite as _};
use thiserror::Error;
use types::{
    combined::BeaconState, config::Config, nonstandard::Phase, phase0::primitives::UnixSeconds,
    preset::Preset, traits::BeaconState as _,
};

use crate::Eth1Chain;

#[derive(Debug, Error)]
enum Error {
    #[error("blocks ran out without triggering genesis")]
    BlocksRanOut,
    // This is not a fatal error, but our convention is to fail on anything unexpected until we know
    // it's acceptable.
    #[error("genesis time {genesis_time} too far in the future to be rendered as a local time")]
    GenesisTimeOutOfRange { genesis_time: UnixSeconds },
    // TODO(Grandine Team): If the genesis state is post-Bellatrix, construct an
    //                      `ExecutionPayloadHeader` based on the Eth1 block that triggered genesis.
    #[error("post Bellatrix genesis is not implemented")]
    PostBellatrixGenesisNotImplemented,
}

pub async fn wait<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    store_directory: PathBuf,
    mut blocks: impl Stream<Item = Result<Eth1Block>> + Unpin + Send,
    eth1_chain: &Eth1Chain,
) -> Result<BeaconState<P>> {
    if let Ok(genesis_state) = try_load_genesis_from_file(config, store_directory.as_path()) {
        return Ok(genesis_state);
    }

    ensure!(
        config.genesis_phase() < Phase::Bellatrix,
        Error::PostBellatrixGenesisNotImplemented,
    );

    let mut incremental = Incremental::new(config);

    while let Some(block) = blocks.try_next().await? {
        incremental.set_eth1_timestamp(block.timestamp);

        for DepositEvent { data, index } in block.deposit_events {
            incremental.add_deposit_data(pubkey_cache, data, index)?;
        }

        if let Err(error) = incremental.validate() {
            info!("genesis not triggered: {error}");
            continue;
        }

        let (genesis_state, mut deposit_tree) =
            incremental.finish(pubkey_cache, block.hash, None)?;

        let genesis_time = genesis_state.genesis_time();

        let local_date_time = genesis_time
            .try_into()
            .ok()
            .and_then(|signed| Local.timestamp_opt(signed, 0).single())
            .ok_or(Error::GenesisTimeOutOfRange { genesis_time })?;

        // Don't log the whole state. It's huge even with the minimal configuration.
        info!("genesis triggered with genesis time {genesis_time} ({local_date_time})");

        persist_genesis_state(store_directory.as_path(), &genesis_state)?;
        deposit_tree.last_added_block_number = block.number;
        eth1_chain.persist_deposit_tree(deposit_tree)?;

        return Ok(genesis_state);
    }

    bail!(Error::BlocksRanOut);
}

fn persist_genesis_state<P: Preset>(
    store_directory: impl AsRef<Path>,
    genesis_state: &BeaconState<P>,
) -> Result<()> {
    let store_directory = store_directory.as_ref();

    fs_err::create_dir_all(store_directory)?;

    let genesis_state_bytes = genesis_state.to_ssz()?;

    fs_err::write(
        store_directory.join("genesis_state.ssz"),
        genesis_state_bytes,
    )?;

    Ok(())
}

fn try_load_genesis_from_file<P: Preset>(
    config: &Config,
    store_directory: impl AsRef<Path>,
) -> Result<BeaconState<P>> {
    let genesis_state_bytes = fs_err::read(store_directory.as_ref().join("genesis_state.ssz"))?;
    let genesis_state = BeaconState::from_ssz(config, genesis_state_bytes)?;
    Ok(genesis_state)
}
