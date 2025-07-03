use core::time::Duration;
use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use dedicated_executor::DedicatedExecutor;
use log::{debug, info, warn};
use web3::{
    api::{Eth, Namespace as _},
    helpers::CallFuture,
    transports::Http,
    Error, Transport as _,
};

use crate::{
    endpoints::Endpoint,
    eth1_api::{CAPABILITIES, ENGINE_GET_CLIENT_VERSION_V1},
    ClientVersionV1, Eth1Api,
};

const ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(1);
const ENGINE_GET_CLIENT_VERSION_V1_TIMEOUT: Duration = Duration::from_secs(1);

pub fn spawn_exchange_capabilities_and_versions_task(
    eth1_api: Arc<Eth1Api>,
    dedicated_executor: &DedicatedExecutor,
) {
    dedicated_executor
        .spawn(async move {
            if let Err(error) = exchange_capabilities_and_versions(&eth1_api).await {
                warn!("failed to exchange capabilities and client versions: {error:?}");
            }
        })
        .detach();
}

async fn exchange_capabilities_and_versions(eth1_api: &Eth1Api) -> Result<()> {
    let params = vec![serde_json::to_value(CAPABILITIES)?];
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
            Ok(capabilities) => {
                let supports_client_version = capabilities.contains(ENGINE_GET_CLIENT_VERSION_V1);

                eth1_api.on_ok_response(endpoint);
                endpoint.set_capabilities(capabilities);

                info!("updated capabilities for eth1 endpoint: {}", endpoint.url());

                if supports_client_version {
                    exchange_client_versions(eth1_api, &api, endpoint).await?;
                } else {
                    debug!(
                        "cannot get client version: {} does not support \
                        {ENGINE_GET_CLIENT_VERSION_V1}",
                        endpoint.url(),
                    );
                }
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

async fn exchange_client_versions(
    eth1_api: &Eth1Api,
    api: &Eth<Http>,
    endpoint: &Endpoint,
) -> Result<()> {
    let response = CallFuture::new(api.transport().execute_with_headers(
        ENGINE_GET_CLIENT_VERSION_V1,
        vec![serde_json::to_value(ClientVersionV1::own())?],
        eth1_api.auth.headers()?,
        Some(ENGINE_GET_CLIENT_VERSION_V1_TIMEOUT),
    ))
    .await;

    match response {
        Ok(client_versions) => {
            eth1_api.on_ok_response(endpoint);
            endpoint.set_client_versions(client_versions);

            info!(
                "updated client version for eth1 endpoint: {}",
                endpoint.url()
            );
        }
        Err(error) => {
            eth1_api.on_error_response(endpoint);

            warn!(
                "unable to update client version for eth1 endpoint: {} {error:?}",
                endpoint.url(),
            );
        }
    }

    Ok(())
}
