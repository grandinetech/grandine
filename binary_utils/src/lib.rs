use std::io::Write as _;

use anyhow::Result;
use chrono::{Local, SecondsFormat};
use env_logger::{Builder, Env, Target, WriteStyle};
use log::LevelFilter;
use logging::PEER_LOG_METRICS;
use rayon::ThreadPoolBuilder;

pub fn initialize_logger(module_path: &str, always_write_style: bool, log_level: LevelFilter) -> Result<()> {
    let mut builder = Builder::new();

    builder
        .filter_level(LevelFilter::Off)
        .filter_module("attestation_verifier", log_level)
        .filter_module("block_producer", log_level)
        .filter_module("builder_api", log_level)
        .filter_module("data_dumper", log_level)
        .filter_module("database", log_level)
        .filter_module("dedicated_executor", log_level)
        .filter_module("doppelganger_protection", log_level)
        .filter_module("eth1", log_level)
        .filter_module("eth1_api", log_level)
        .filter_module("eth2_libp2p", log_level)
        .filter_module("execution_engine", log_level)
        .filter_module("features", log_level)
        .filter_module("fork_choice_control", log_level)
        .filter_module("fork_choice_store", log_level)
        .filter_module("genesis", log_level)
        .filter_module("http_api", log_level)
        .filter_module("http_api_utils", log_level)
        .filter_module("keymanager", log_level)
        .filter_module("liveness_tracker", log_level)
        .filter_module("metrics", log_level)
        .filter_module("operation_pools", log_level)
        .filter_module("p2p", log_level)
        .filter_module("prometheus_metrics", log_level)
        .filter_module("runtime", log_level)
        .filter_module("signer", log_level)
        .filter_module("slasher", log_level)
        .filter_module("slashing_protection", log_level)
        .filter_module("state_cache", log_level)
        .filter_module("storage", log_level)
        .filter_module("validator", log_level)
        .filter_module("validator_key_cache", log_level)
        .filter_module("validator_statistics", log_level)
        .filter_module("web3", log_level)
        .filter_module(module_path!(), log_level)
        .filter_module(module_path, log_level)
        .format(|formatter, record| {
            writeln!(
                formatter,
                "[{}] [{}] [{}] [{PEER_LOG_METRICS}] {}",
                // This allocates a `String` only to write it to `formatter`, but that has a
                // negligible effect on performance. `DateTime::format_with_items` with the same
                // format is slower. Manual formatting with `core::fmt` is faster, however.
                Local::now().to_rfc3339_opts(SecondsFormat::Millis, false),
                //formatter.default_level_style(record.level()),
                record.level(),
                record.target(),
                record.args(),
            )
        })
        .target(Target::Stdout);

    if always_write_style {
        builder.write_style(WriteStyle::Always);
    }

    let env = Env::new()
        .filter("GRANDINE_LOG")
        .write_style("GRANDINE_LOG_STYLE");

    builder.parse_env(env).try_init().map_err(Into::into)
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
