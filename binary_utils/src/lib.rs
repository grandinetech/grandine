use anyhow::Result;
use rayon::ThreadPoolBuilder;
use tracing_subscriber::{EnvFilter, fmt, filter::LevelFilter};

pub fn initialize_tracing_logger(module_path: &str) -> Result<()> {
    let base_filter = EnvFilter::try_from_env("GRANDINE_LOG")
        .or_else(|_| EnvFilter::try_from_default_env());
    
    let filter = match base_filter {
        Ok(filter) => filter,
        Err(_) => {
            let filter = EnvFilter::default()
            .add_directive(LevelFilter::OFF.into())
            .add_directive("attestation_verifier=info".parse()?)
            .add_directive("block_producer=info".parse()?)
            .add_directive("builder_api=info".parse()?)
            .add_directive("data_dumper=info".parse()?)
            .add_directive("database=info".parse()?)
            .add_directive("dedicated_executor=info".parse()?)
            .add_directive("doppelganger_protection=info".parse()?)
            .add_directive("eth1=info".parse()?)
            .add_directive("eth1_api=info".parse()?)
            .add_directive("eth2_libp2p=info".parse()?)
            .add_directive("execution_engine=info".parse()?)
            .add_directive("features=info".parse()?)
            .add_directive("fork_choice_control=info".parse()?)
            .add_directive("fork_choice_store=info".parse()?)
            .add_directive("genesis=info".parse()?)
            .add_directive("http_api=info".parse()?)
            .add_directive("http_api_utils=info".parse()?)
            .add_directive("keymanager=info".parse()?)
            .add_directive("liveness_tracker=info".parse()?)
            .add_directive("metrics=info".parse()?)
            .add_directive("operation_pools=info".parse()?)
            .add_directive("p2p=info".parse()?)
            .add_directive("prometheus_metrics=info".parse()?)
            .add_directive("pubkey_cache=info".parse()?)
            .add_directive("runtime=info".parse()?)
            .add_directive("signer=info".parse()?)
            .add_directive("slasher=info".parse()?)
            .add_directive("slashing_protection=info".parse()?)
            .add_directive("state_cache=info".parse()?)
            .add_directive("storage=info".parse()?)
            .add_directive("validator=info".parse()?)
            .add_directive("validator_key_cache=info".parse()?)
            .add_directive("validator_statistics=info".parse()?)
            .add_directive("web3=info".parse()?)
            .add_directive(format!("{}=info", module_path).parse()?)
            .add_directive(format!("{}=info", module_path!()).parse()?);
            
            filter
        }
    };

    fmt()
        .with_env_filter(filter)
        .compact()
        .with_thread_ids(true)
        .with_target(true)
        .with_file(false)
        .with_line_number(true)
        .init();

    Ok(())
}

pub fn initialize_rayon() -> Result<()> {
    ThreadPoolBuilder::new()
        .thread_name(|index| format!("rayon-{index}"))
        .panic_handler(panics::log)
        .build_global()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The error message will typically not show up in the output even with `--nocapture`.
    // That is because the main thread exits before the Rayon panic handler can log it.
    #[test]
    fn initialize_rayon_sets_panic_handler_for_spawned_tasks() -> Result<()> {
        initialize_rayon()?;

        rayon::spawn(|| panic!());

        Ok(())
    }
}
