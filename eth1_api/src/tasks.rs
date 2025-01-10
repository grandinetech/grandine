use core::time::Duration;
use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use dedicated_executor::DedicatedExecutor;
use execution_engine::BlobAndProofV1;
use fork_choice_control::Wait;
use helper_functions::misc;
use log::{info, warn};
use types::{
    combined::SignedBeaconBlock, deneb::primitives::BlobIndex, preset::Preset,
    traits::SignedBeaconBlock as _,
};
use web3::{api::Namespace as _, helpers::CallFuture, Error, Transport as _};

use crate::{eth1_api::ENGINE_GET_EL_BLOBS_V1, ApiController, Eth1Api};

const ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(1);

pub fn spawn_blobs_download_task<P: Preset, W: Wait>(
    eth1_api: Arc<Eth1Api>,
    controller: ApiController<P, W>,
    dedicated_executor: &DedicatedExecutor,
    block: Arc<SignedBeaconBlock<P>>,
    blob_indices: Vec<BlobIndex>,
) {
    dedicated_executor
        .spawn(async move { download_blobs(&eth1_api, controller, block, blob_indices).await })
        .detach();
}

pub fn spawn_exchange_capabilities_task(
    eth1_api: Arc<Eth1Api>,
    dedicated_executor: &DedicatedExecutor,
) {
    dedicated_executor
        .spawn(async move {
            if let Err(error) = exchange_capabilities(&eth1_api).await {
                warn!("exhcange capabilities task failed: {error:?}");
            }
        })
        .detach();
}

async fn download_blobs<P: Preset, W: Wait>(
    eth1_api: &Eth1Api,
    controller: ApiController<P, W>,
    block: Arc<SignedBeaconBlock<P>>,
    blob_indices: Vec<BlobIndex>,
) {
    if let Some(body) = block.message().body().post_deneb() {
        let kzg_commitments = body
            .blob_kzg_commitments()
            .iter()
            .zip(0..)
            .filter(|(_, index)| blob_indices.contains(index))
            .collect::<Vec<_>>();

        let versioned_hashes = kzg_commitments
            .iter()
            .copied()
            .map(|(commitment, _)| misc::kzg_commitment_to_versioned_hash(*commitment))
            .collect();

        match eth1_api.get_blobs::<P>(versioned_hashes).await {
            Ok(blobs_and_proofs) => {
                let block_header = block.to_header();

                for (blob_and_proof, kzg_commitment, index) in blobs_and_proofs
                    .into_iter()
                    .zip(kzg_commitments.into_iter())
                    .filter_map(|(blob_and_proof, (kzg_commitment, index))| {
                        blob_and_proof.map(|blob_and_proof| (blob_and_proof, kzg_commitment, index))
                    })
                {
                    let BlobAndProofV1 { blob, proof } = blob_and_proof;

                    match misc::construct_blob_sidecar(
                        &block,
                        block_header,
                        index,
                        blob,
                        *kzg_commitment,
                        proof,
                    ) {
                        Ok(blob_sidecar) => {
                            controller.on_el_blob_sidecar(Arc::new(blob_sidecar));
                        }
                        Err(error) => warn!(
                            "failed to construct blob sidecar with blob and proof \
                            received from execution layer: {error:?}"
                        ),
                    }
                }
            }
            Err(error) => warn!("engine_getBlobsV1 call failed: {error}"),
        }
    }
}

async fn exchange_capabilities(eth1_api: &Eth1Api) -> Result<()> {
    let params = vec![serde_json::to_value([ENGINE_GET_EL_BLOBS_V1])?];
    let method = "engine_exchangeCapabilities";

    for endpoint in eth1_api.endpoints.endpoints_for_request(None) {
        let _timer = eth1_api.metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(&metrics.eth1_api_request_times, method)
        });

        let api = eth1_api.build_api_for_request(endpoint);

        let response: Result<HashSet<String>, Error> =
            CallFuture::new(api.transport().execute_with_headers(
                method,
                params.clone(),
                eth1_api.auth.headers()?,
                Some(ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT),
            ))
            .await;

        match response {
            Ok(response) => {
                eth1_api.on_ok_response(endpoint);
                endpoint.set_capabilities(response);

                info!("updated capabilities for eth1 endpoint: {}", endpoint.url());
            }
            Err(error) => {
                eth1_api.on_error_response(endpoint);

                warn!(
                    "unable to update capabilities for eth1 endpoint: {} {error:?}",
                    endpoint.url(),
                );
            }
        }
    }

    Ok(())
}
