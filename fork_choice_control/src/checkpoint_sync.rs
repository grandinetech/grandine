use core::time::Duration;
use std::sync::Arc;

use anyhow::{Result, bail};
use helper_functions::{accessors, misc};
use http_api_utils::{BlockId, StateId};
use logging::info_with_peers;
use mime::APPLICATION_OCTET_STREAM;
use reqwest::{Client, StatusCode, header::ACCEPT};
use ssz::{SszHash as _, SszRead};
use thiserror::Error;
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    nonstandard::FinalizedCheckpoint,
    phase0::{consts::GENESIS_EPOCH, primitives::H256},
    preset::Preset,
    redacting_url::RedactingUrl,
    traits::SignedBeaconBlock as _,
};

pub async fn load_from_remote<P: Preset>(
    config: &Config,
    client: &Client,
    url: &RedactingUrl,
    block_id: BlockId,
) -> Result<FinalizedCheckpoint<P>> {
    info_with_peers!("performing checkpoint sync from block {block_id} at {url}…");

    let mut block = fetch_block(config, client, url, block_id)
        .await?
        .ok_or(Error::BlockNotFound { block_id })?;

    let initial_slot = block.message().slot();

    if !misc::is_epoch_start::<P>(initial_slot) {
        let initial_epoch = misc::compute_epoch_at_slot::<P>(initial_slot);

        block = 'block: {
            for epoch in (GENESIS_EPOCH..=initial_epoch).rev() {
                let slot = misc::compute_start_slot_at_epoch::<P>(epoch);
                let block_id = BlockId::Slot(slot);

                if let Some(fetched_block) = fetch_block(config, client, url, block_id).await? {
                    break 'block fetched_block;
                }
            }

            bail!(Error::NoBlockUsableAsAnchor);
        };
    }

    let slot = block.message().slot();
    let block_root = block.message().hash_tree_root();

    let state = fetch_state(config, client, url, StateId::Slot(slot))
        .await?
        .ok_or(Error::MissingPostState { block_root })?;

    let state_root = state.hash_tree_root();

    if block.message().state_root() != state_root {
        bail!(Error::BlockStateRootMismatch {
            block_state_root: block.message().state_root(),
            state_root,
        });
    }

    let state_block_root = accessors::latest_block_root(state.as_ref());

    if state_block_root != block_root {
        bail!(Error::BlockStateMismatch {
            block_root,
            state_block_root,
        });
    }

    info_with_peers!("loaded state at slot {slot} from {url}");

    Ok(FinalizedCheckpoint { block, state })
}

async fn fetch_block<P: Preset>(
    config: &Config,
    client: &Client,
    url: &RedactingUrl,
    block_id: BlockId,
) -> Result<Option<Arc<SignedBeaconBlock<P>>>> {
    let url = url.join(&format!("/eth/v2/beacon/blocks/{block_id}"))?;

    fetch(config, client, url).await
}

async fn fetch_state<P: Preset>(
    config: &Config,
    client: &Client,
    url: &RedactingUrl,
    state_id: StateId,
) -> Result<Option<Arc<BeaconState<P>>>> {
    let url = url.join(&format!("/eth/v2/debug/beacon/states/{state_id}"))?;

    fetch(config, client, url).await
}

async fn fetch<T: SszRead<Config>>(
    config: &Config,
    client: &Client,
    url: RedactingUrl,
) -> Result<Option<T>> {
    let response = client
        .get(url.into_url())
        .header(ACCEPT, APPLICATION_OCTET_STREAM.as_ref())
        .timeout(Duration::from_mins(10))
        .send()
        .await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let response = response.error_for_status()?;
    let bytes = response.bytes().await?;

    Ok(Some(T::from_ssz(config, bytes)?))
}

#[derive(Debug, Error)]
enum Error {
    #[error(
        "downloaded block state root {block_state_root:?} does not match downloaded state root {state_root:?}"
    )]
    BlockStateRootMismatch {
        block_state_root: H256,
        state_root: H256,
    },
    #[error(
        "downloaded block root {block_root:?} does not match the downloaded state's latest block root {state_block_root:?}"
    )]
    BlockStateMismatch {
        block_root: H256,
        state_block_root: H256,
    },
    #[error("remote beacon node does not have block {block_id}")]
    BlockNotFound { block_id: BlockId },
    #[error("remote beacon node does not have post-state of block {block_root:?}")]
    MissingPostState { block_root: H256 },
    #[error("remote beacon node has no block usable as anchor")]
    NoBlockUsableAsAnchor,
}
