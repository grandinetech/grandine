use std::io::Write as _;

use anyhow::Result;
use chrono::{Local, SecondsFormat};
use env_logger::{Builder, Env, Target, WriteStyle};
use log::LevelFilter;
use logging::PEER_LOG_METRICS;
use rayon::ThreadPoolBuilder;

pub fn initialize_logger(module_path: &str, always_write_style: bool) -> Result<()> {
    let mut builder = Builder::new();

    builder
        .filter_level(LevelFilter::Off)
        .filter_module("attestation_verifier", LevelFilter::Info)
        .filter_module("block_producer", LevelFilter::Info)
        .filter_module("builder_api", LevelFilter::Info)
        .filter_module("data_dumper", LevelFilter::Info)
        .filter_module("database", LevelFilter::Info)
        .filter_module("dedicated_executor", LevelFilter::Info)
        .filter_module("doppelganger_protection", LevelFilter::Info)
        .filter_module("eth1", LevelFilter::Info)
        .filter_module("eth1_api", LevelFilter::Debug)
        .filter_module("eth2_libp2p", LevelFilter::Debug)
        .filter_module("execution_engine", LevelFilter::Info)
        .filter_module("features", LevelFilter::Info)
        .filter_module("fork_choice_control", LevelFilter::Info)
        .filter_module("fork_choice_store", LevelFilter::Info)
        .filter_module("genesis", LevelFilter::Info)
        .filter_module("http_api", LevelFilter::Info)
        .filter_module("http_api_utils", LevelFilter::Info)
        .filter_module("keymanager", LevelFilter::Info)
        .filter_module("liveness_tracker", LevelFilter::Info)
        .filter_module("metrics", LevelFilter::Info)
        .filter_module("operation_pools", LevelFilter::Info)
        .filter_module("p2p", LevelFilter::Debug)
        .filter_module("prometheus_metrics", LevelFilter::Info)
        .filter_module("pubkey_cache", LevelFilter::Info)
        .filter_module("runtime", LevelFilter::Info)
        .filter_module("signer", LevelFilter::Info)
        .filter_module("slasher", LevelFilter::Info)
        .filter_module("slashing_protection", LevelFilter::Info)
        .filter_module("state_cache", LevelFilter::Info)
        .filter_module("storage", LevelFilter::Info)
        .filter_module("validator", LevelFilter::Info)
        .filter_module("validator_key_cache", LevelFilter::Info)
        .filter_module("validator_statistics", LevelFilter::Info)
        .filter_module("web3", LevelFilter::Info)
        .filter_module(module_path!(), LevelFilter::Info)
        .filter_module(module_path, LevelFilter::Info)
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
