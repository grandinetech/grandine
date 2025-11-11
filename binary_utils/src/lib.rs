use anyhow::Result;
use chrono::{Local, SecondsFormat};
use fs_err as fs;
use logging::{debug_with_peers, exception};
use logroller::{Compression, LogRollerBuilder, Rotation, RotationSize};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{ExporterBuildError, WithExportConfig as _};
use rayon::ThreadPoolBuilder;
use std::{
    io::{self, IsTerminal},
    path::Path,
    sync::{Arc, OnceLock},
};
use tokio::runtime::Runtime;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::{self, format::Writer, time::FormatTime},
    prelude::*,
    reload::{self, Handle},
    EnvFilter, Registry,
};
use types::redacting_url::RedactingUrl;

static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

#[derive(Debug)]
pub struct TelemetryConfig {
    pub url: RedactingUrl,
    pub service_name: String,
    pub trace_level: Level,
}

#[derive(Clone)]
pub struct TracingHandle {
    log_handle: Handle<EnvFilter, Registry>,
    telemetry_handle: Option<Handle<EnvFilter, Registry>>,
    #[expect(
        dead_code,
        reason = "telemetry runtime must exist for telemetry data exporter thread to function"
    )]
    telemetry_runtime: Option<Arc<Runtime>>,
}

impl TracingHandle {
    pub fn modify_log<F>(&self, f: F) -> Result<(), reload::Error>
    where
        F: FnOnce(&mut EnvFilter),
    {
        self.log_handle.modify(f)
    }

    pub fn modify_trace<F>(&self, f: F) -> Result<Option<()>, reload::Error>
    where
        F: FnOnce(&mut EnvFilter),
    {
        self.telemetry_handle
            .as_ref()
            .map(|telemetry_handle| telemetry_handle.modify(f))
            .transpose()
    }
}

struct LocalTimer;

impl FormatTime for LocalTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> core::fmt::Result {
        write!(
            w,
            "[{}]",
            Local::now().to_rfc3339_opts(SecondsFormat::Millis, true)
        )
    }
}

#[expect(clippy::too_many_lines)]
pub fn initialize_tracing_logger(
    module_path: &str,
    data_dir: Option<&Path>,
    telemetry_config: Option<TelemetryConfig>,
    always_write_style: bool,
) -> Result<TracingHandle> {
    let mut filter = EnvFilter::default()
        .add_directive(LevelFilter::OFF.into())
        .add_directive("attestation_verifier=info".parse()?)
        .add_directive("block_producer=info".parse()?)
        .add_directive("builder_api=info".parse()?)
        .add_directive("data_dumper=info".parse()?)
        .add_directive("database=info".parse()?)
        .add_directive("debug_info=info".parse()?)
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

    let (filter_layer, log_handle) = reload::Layer::new(filter);
    let enable_ansi = always_write_style || io::stdout().is_terminal();

    let stdout_layer = fmt::layer::<Registry>()
        .compact()
        .with_thread_ids(false)
        .with_target(true)
        .with_file(false)
        .with_line_number(true)
        .with_timer(LocalTimer)
        .with_ansi(enable_ansi);

    let mut layers = vec![stdout_layer.with_filter(filter_layer).boxed()];
    let mut telemetry_runtime = None;
    let mut telemetry_handle = None;

    if let Some(telemetry_config) = telemetry_config {
        let TelemetryConfig {
            url,
            service_name,
            trace_level,
        } = telemetry_config;

        let mut telemetry_filter = EnvFilter::default()
            .add_directive(LevelFilter::OFF.into())
            .add_directive(format!("attestation_verifier={trace_level}").parse()?)
            .add_directive(format!("binary_utils={trace_level}").parse()?)
            .add_directive(format!("block_producer={trace_level}").parse()?)
            .add_directive(format!("builder_api={trace_level}").parse()?)
            .add_directive(format!("data_dumper={trace_level}").parse()?)
            .add_directive(format!("database={trace_level}").parse()?)
            .add_directive(format!("debug_info={trace_level}").parse()?)
            .add_directive(format!("dedicated_executor={trace_level}").parse()?)
            .add_directive(format!("doppelganger_protection={trace_level}").parse()?)
            .add_directive(format!("eth1={trace_level}").parse()?)
            .add_directive(format!("eth1_api={trace_level}").parse()?)
            .add_directive(format!("eth2_libp2p={trace_level}").parse()?)
            .add_directive(format!("execution_engine={trace_level}").parse()?)
            .add_directive(format!("features={trace_level}").parse()?)
            .add_directive(format!("fork_choice_control={trace_level}").parse()?)
            .add_directive(format!("fork_choice_store={trace_level}").parse()?)
            .add_directive(format!("genesis={trace_level}").parse()?)
            .add_directive(format!("grandine={trace_level}").parse()?)
            .add_directive(format!("http_api={trace_level}").parse()?)
            .add_directive(format!("http_api_utils={trace_level}").parse()?)
            .add_directive(format!("keymanager={trace_level}").parse()?)
            .add_directive(format!("liveness_tracker={trace_level}").parse()?)
            .add_directive(format!("metrics={trace_level}").parse()?)
            .add_directive(format!("operation_pools={trace_level}").parse()?)
            .add_directive(format!("p2p={trace_level}").parse()?)
            .add_directive(format!("prometheus_metrics={trace_level}").parse()?)
            .add_directive(format!("pubkey_cache={trace_level}").parse()?)
            .add_directive(format!("runtime={trace_level}").parse()?)
            .add_directive(format!("signer={trace_level}").parse()?)
            .add_directive(format!("slasher={trace_level}").parse()?)
            .add_directive(format!("slashing_protection={trace_level}").parse()?)
            .add_directive(format!("state_cache={trace_level}").parse()?)
            .add_directive(format!("storage={trace_level}").parse()?)
            .add_directive(format!("validator={trace_level}").parse()?)
            .add_directive(format!("validator_key_cache={trace_level}").parse()?)
            .add_directive(format!("validator_statistics={trace_level}").parse()?);

        #[cfg(feature = "tracing")]
        {
            telemetry_filter = telemetry_filter
                .add_directive(format!("helper_functions={trace_level}").parse()?)
                .add_directive(format!("transition_functions={trace_level}").parse()?)
        }

        if let Ok(env_filter) = EnvFilter::try_from_env("GRANDINE_TRACE_LOG") {
            for directive in env_filter.to_string().split(',') {
                telemetry_filter = telemetry_filter.add_directive(directive.parse()?)
            }
        }

        let (telemetry_filter_layer, handle) = reload::Layer::new(telemetry_filter);

        telemetry_handle = Some(handle);

        // A Tokio runtime is required for the gRPC exporter’s async operations.
        // This runtime persists across app restarts (since the logger isn’t reinitialized),
        // while the main Tokio runtime is recreated on each restart.
        // See `grandine::block_on` for details.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name("grandine-telemetry-exporter")
            .worker_threads(2)
            .max_blocking_threads(32)
            .enable_all()
            .build()?;

        runtime.block_on(async {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(url.into_url())
                .build()?;

            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(
                    opentelemetry_sdk::Resource::builder()
                        .with_service_name(service_name)
                        .build(),
                )
                .build();

            let tracer = provider.tracer("grandine");
            let telemetry_layer = tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_filter(telemetry_filter_layer);

            layers.push(telemetry_layer.boxed());

            Ok::<(), ExporterBuildError>(())
        })?;

        telemetry_runtime = Some(Arc::new(runtime))
    }

    let registry = tracing_subscriber::registry().with(layers);

    if let Some(data_dir) = data_dir {
        match initialize_rotating_writer(data_dir) {
            Ok(non_blocking) => {
                let exception_filter = EnvFilter::default()
                    .add_directive(LevelFilter::OFF.into())
                    .add_directive("exception=error".parse()?);

                let file_layer = fmt::layer()
                    .compact()
                    .with_ansi(false)
                    .with_writer(non_blocking)
                    .with_timer(LocalTimer)
                    .with_target(true)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(exception_filter);

                registry.with(file_layer).init();
            }
            Err(e) => {
                registry.init();
                tracing::error!("failed to initialize rotating exception log in {data_dir:?}: {e}");
            }
        }
    } else {
        registry.init();
    }

    debug_with_peers!("tracing started!");
    exception!("exception macro is enabled");

    Ok(TracingHandle {
        log_handle,
        telemetry_handle,
        telemetry_runtime,
    })
}

fn initialize_rotating_writer(
    data_dir: &Path,
) -> Result<tracing_appender::non_blocking::NonBlocking> {
    if !data_dir.exists() {
        fs::create_dir_all(data_dir)?;
    }

    let rotator = LogRollerBuilder::new(data_dir, Path::new("exception.log"))
        .rotation(Rotation::SizeBased(RotationSize::GB(1)))
        .max_keep_files(5)
        .compression(Compression::Gzip)
        .build()?;

    let (non_blocking, guard) = tracing_appender::non_blocking(rotator);
    LOG_GUARD.set(guard).ok();

    Ok(non_blocking)
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
    use std::sync::{LazyLock, Mutex};

    use serial_test::serial;
    use tempfile::TempDir;

    use super::*;

    struct LoggerWithTempDir {
        handle: TracingHandle,
        _temp_dir: TempDir,
    }

    static LOGGER: LazyLock<Mutex<Option<LoggerWithTempDir>>> = LazyLock::new(|| Mutex::new(None));

    fn init_logger_once() -> TracingHandle {
        let data_dir = TempDir::new().expect("should create a temp data dir");
        let mut lock = LOGGER.lock().expect("Failed to acquire LOGGER mutex lock");
        if lock.is_none() {
            let handle =
                initialize_tracing_logger(module_path!(), Some(data_dir.path()), None, false)
                    .expect("Failed to initialize tracing logger");

            *lock = Some(LoggerWithTempDir {
                handle: handle.clone(),
                _temp_dir: data_dir,
            });

            handle
        } else {
            lock.as_ref()
                .expect("LOGGER should always be initialized")
                .handle
                .clone()
        }
    }

    // The error message will typically not show up in the output even with `--nocapture`.
    // That is because the main thread exits before the Rayon panic handler can log it.
    #[test]
    fn initialize_rayon_sets_panic_handler_for_spawned_tasks() -> Result<()> {
        initialize_rayon()?;

        rayon::spawn(|| panic!());

        Ok(())
    }

    #[test]
    #[serial]
    fn initialize_tracing_logger_info_mode() -> Result<()> {
        use gag::BufferRedirect;
        use logging::{error_with_peers, exception, info_with_peers, warn_with_peers};
        use std::io::Read;

        // stdout redirect to buffer
        let mut buf = BufferRedirect::stdout().expect("failed to redirect stdout");

        let _handle = init_logger_once();

        info_with_peers!("info_with_peers test message");
        warn_with_peers!("warn_with_peers test message");
        error_with_peers!("error_with_peers test message");
        exception!("exception test message");

        let mut output = String::new();
        buf.read_to_string(&mut output)?;

        assert!(
            output.contains("info_with_peers test message"),
            "Info log not found in output:\n{output}",
        );
        assert!(
            output.contains("warn_with_peers test message"),
            "Warn log not found in output:\n{output}",
        );
        assert!(
            output.contains("error_with_peers test message"),
            "Error log not found in output:\n{output}",
        );
        assert!(
            !output.contains("exception test message"),
            "Output should not contain exception message, but found:\n{output}"
        );
        Ok(())
    }

    #[test]
    #[serial]
    fn initialize_tracing_logger_developer_info_mode() -> Result<()> {
        use gag::BufferRedirect;
        use logging::{error_with_peers, exception, info_with_peers, warn_with_peers};
        use std::io::Read;

        let mut buf = BufferRedirect::stdout().expect("failed to redirect stdout");

        let handle = init_logger_once();
        handle.modify_log(|env_filter| {
            let new_filter = env_filter
                .clone()
                .add_directive("exception".parse().expect("Failed to parse"));
            *env_filter = new_filter;
        })?;

        info_with_peers!("info_with_peers test message");
        warn_with_peers!("warn_with_peers test message");
        error_with_peers!("error_with_peers test message");
        exception!("exception test message");

        let mut output = String::new();
        buf.read_to_string(&mut output)?;

        assert!(
            output.contains("info_with_peers test message"),
            "Info log not found in output:\n{output}",
        );
        assert!(
            output.contains("warn_with_peers test message"),
            "Warn log not found in output:\n{output}",
        );
        assert!(
            output.contains("error_with_peers test message"),
            "Error log not found in output:\n{output}",
        );
        assert!(
            output.contains("exception test message"),
            "exception log not found in output:\n{output}",
        );

        // NOTE: This turn off of the "exception" directive is necessary because the global
        // tracing subscriber persists across tests. Without this cleanup, other tests
        // could be affected by the leftover directive, breaking their expected behavior.
        handle.modify_log(|env_filter| {
            let new_filter = env_filter
                .clone()
                .add_directive("exception=off".parse().expect("Failed to parse"));
            *env_filter = new_filter;
        })?;

        Ok(())
    }

    #[test]
    #[serial]
    fn initialize_tracing_logger_debug_mode() -> Result<()> {
        use gag::BufferRedirect;
        use logging::{debug_with_peers, error_with_peers, info_with_peers, warn_with_peers};
        use std::io::Read;

        let mut buf = BufferRedirect::stdout().expect("failed to redirect stdout");

        let handle = init_logger_once();

        handle.modify_log(|env_filter| {
            let new_filter = env_filter.clone().add_directive(
                format!("{}=debug", module_path!())
                    .parse()
                    .expect("Failed to parse"),
            );
            *env_filter = new_filter;
        })?;

        info_with_peers!("info_with_peers test message");
        warn_with_peers!("warn_with_peers test message");
        error_with_peers!("error_with_peers test message");
        debug_with_peers!("debug_with_peers test message");

        let mut output = String::new();
        buf.read_to_string(&mut output)?;

        assert!(
            output.contains("info_with_peers test message"),
            "Info log not found in output:\n{output}",
        );
        assert!(
            output.contains("warn_with_peers test message"),
            "Warn log not found in output:\n{output}",
        );
        assert!(
            output.contains("error_with_peers test message"),
            "Error log not found in output:\n{output}",
        );
        assert!(
            output.contains("debug_with_peers test message"),
            "Debug log not found in output:\n{output}",
        );

        Ok(())
    }

    #[test]
    #[serial]
    fn initialize_tracing_logger_trace_mode() -> Result<()> {
        use gag::BufferRedirect;
        use logging::{
            debug_with_peers, error_with_peers, info_with_peers, trace_with_peers, warn_with_peers,
        };
        use std::io::Read;

        let mut buf = BufferRedirect::stdout().expect("failed to redirect stdout");

        let handle = init_logger_once();

        handle.modify_log(|env_filter| {
            let new_filter = env_filter.clone().add_directive(
                format!("{}=trace", module_path!())
                    .parse()
                    .expect("Failed to parse"),
            );
            *env_filter = new_filter;
        })?;

        info_with_peers!("info_with_peers test message");
        warn_with_peers!("warn_with_peers test message");
        error_with_peers!("error_with_peers test message");
        debug_with_peers!("debug_with_peers test message");
        trace_with_peers!("trace_with_peers test message");

        let mut output = String::new();
        buf.read_to_string(&mut output)?;

        assert!(
            output.contains("info_with_peers test message"),
            "Info log not found in output:\n{output}",
        );
        assert!(
            output.contains("warn_with_peers test message"),
            "Warn log not found in output:\n{output}"
        );
        assert!(
            output.contains("error_with_peers test message"),
            "Error log not found in output:\n{output}",
        );
        assert!(
            output.contains("debug_with_peers test message"),
            "Debug log not found in output:\n{output}",
        );
        assert!(
            output.contains("trace_with_peers test message"),
            "Trace log not found in output:\n{output}",
        );

        Ok(())
    }
}
