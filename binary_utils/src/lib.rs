use anyhow::Result;
use logging::debug_with_peers;
use rayon::ThreadPoolBuilder;
use std::io::{self, IsTerminal};
use tracing_subscriber::{
    filter::LevelFilter,
    fmt,
    reload::{self, Handle},
    EnvFilter,
};
use tracing_subscriber::{layer::Layered, prelude::*};

type TracingLayered = Layered<
    fmt::Layer<
        tracing_subscriber::Registry,
        fmt::format::DefaultFields,
        fmt::format::Format<fmt::format::Compact>,
    >,
    tracing_subscriber::Registry,
>;

#[derive(Clone)]
pub struct TracingHandle(Handle<EnvFilter, TracingLayered>);

impl TracingHandle {
    pub fn modify<F>(&self, f: F) -> Result<(), reload::Error>
    where
        F: FnOnce(&mut EnvFilter),
    {
        self.0.modify(f)
    }
}

pub fn initialize_tracing_logger(
    module_path: &str,
    always_write_style: bool,
) -> Result<TracingHandle> {
    let mut filter = EnvFilter::default()
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
        .add_directive(format!("{module_path}=info").parse()?)
        .add_directive(format!("{}=info", module_path!()).parse()?);

    if let Ok(env_filter) = EnvFilter::try_from_env("GRANDINE_LOG") {
        for directive in env_filter.to_string().split(',') {
            filter = filter.add_directive(directive.parse()?)
        }
    }

    let enable_ansi = always_write_style || io::stdout().is_terminal();

    let (filter_layer, handle) = reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .compact()
                .with_thread_ids(true)
                .with_target(true)
                .with_file(false)
                .with_line_number(true)
                .with_ansi(enable_ansi),
        )
        .with(filter_layer)
        .init();

    debug_with_peers!("tracing started!");
    Ok(TracingHandle(handle))
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
