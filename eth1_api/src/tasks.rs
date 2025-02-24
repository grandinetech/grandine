use core::time::Duration;
use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use dedicated_executor::DedicatedExecutor;
use log::{info, warn};
use web3::{api::Namespace as _, helpers::CallFuture, Error, Transport as _};

use crate::{eth1_api::CAPABILITIES, Eth1Api};

const ENGINE_EXCHANGE_CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(1);

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

async fn exchange_capabilities(eth1_api: &Eth1Api) -> Result<()> {
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
