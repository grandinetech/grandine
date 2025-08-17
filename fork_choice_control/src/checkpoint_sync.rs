use core::time::Duration;
use std::sync::Arc;

use anyhow::{bail, Result};
use helper_functions::misc;
use http_api_utils::{BlockId, StateId};
use log::info;
use mime::APPLICATION_OCTET_STREAM;
use reqwest::{header::ACCEPT, Client, StatusCode};
use ssz::SszRead;
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

// @audit WeakSubjectivity: No cryptographic verification of checkpoint authenticity
// ↳ Trusts remote endpoint completely - enables long-range attacks if compromised
// ↳ Should verify checkpoint against hardcoded weak subjectivity checkpoints
// ↳ Review Round 3: CONFIRMED VULNERABLE - No verification against known checkpoints
pub async fn load_finalized_from_remote<P: Preset>(
    config: &Config,
    client: &Client,
    url: &RedactingUrl,
) -> Result<FinalizedCheckpoint<P>> {
    info!("performing checkpoint sync from {url}…");

    let mut block = fetch_block(config, client, url, BlockId::Finalized)
        .await?
        .ok_or(Error::NoFinalizedBlock)?;

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

    info!("loaded state at slot {slot} from {url}");

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

// @audit DoS: No size limit on response bytes - memory exhaustion possible
// ↳ Malicious server could send gigabytes of data causing OOM
// ↳ Should enforce max response size before reading entire body into memory
// ↳ Review Round 2: CONFIRMED - response.bytes() loads entire response without size check
async fn fetch<T: SszRead<Config>>(
    config: &Config,
    client: &Client,
    url: RedactingUrl,
) -> Result<Option<T>> {
    let response = client
        .get(url.into_url())
        .header(ACCEPT, APPLICATION_OCTET_STREAM.as_ref())
        .timeout(Duration::from_secs(600))
        .send()
        .await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    let response = response.error_for_status()?;
    // @audit-ok: SSZ deserialization should fail if data is malformed
    let bytes = response.bytes().await?;

    Ok(Some(T::from_ssz(config, bytes)?))
}

#[derive(Debug, Error)]
enum Error {
    #[error("remote beacon node does not have post-state of block {block_root:?}")]
    MissingPostState { block_root: H256 },
    #[error("remote beacon node has no block usable as anchor")]
    NoBlockUsableAsAnchor,
    #[error("remote beacon node has no finalized block")]
    NoFinalizedBlock,
}
