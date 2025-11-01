use anyhow::Result;
use chrono::{Local, SecondsFormat};
use fs_err::{self as fs, File, OpenOptions};
use logging::{debug_with_peers, exception};
use rayon::ThreadPoolBuilder;
use std::{
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    sync::Mutex,
};
use tracing_subscriber::{
    filter::LevelFilter,
    fmt,
    fmt::{format::Writer, time::FormatTime, writer::BoxMakeWriter, MakeWriter},
    prelude::*,
    reload::{self, Handle},
    EnvFilter, Registry,
};

#[derive(Clone)]
pub struct TracingHandle(Handle<EnvFilter, Registry>);

impl TracingHandle {
    pub fn modify<F>(&self, f: F) -> Result<(), reload::Error>
    where
        F: FnOnce(&mut EnvFilter),
    {
        self.0.modify(f)
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

struct RotatingWriter {
    path: PathBuf,
    max_size: u64,
    lock: Mutex<()>,
}

impl RotatingWriter {
    const fn new(path: PathBuf, max_size: u64) -> Self {
        Self {
            path,
            max_size,
            lock: Mutex::new(()),
        }
    }

    fn open(&self) -> File {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .expect("Failed to open log file")
    }

    fn rotate_if_needed(&self) {
        if let Ok(meta) = fs::metadata(&self.path) {
            if meta.len() >= self.max_size {
                let backup_path = self.path.with_extension("backup.log");

                if backup_path.exists() {
                    fs::remove_file(&backup_path).expect("Failed to remove old backup log");
                }

                fs::rename(&self.path, &backup_path).expect("Failed to rotate log to backup");

                File::create(&self.path).expect("Failed to create new log file");
            }
        }
    }
}

impl<'a> MakeWriter<'a> for RotatingWriter {
    type Writer = File;

    fn make_writer(&'a self) -> Self::Writer {
        let _guard = self
            .lock
            .lock()
            .expect("Failed to acquire lock for writing log");
        self.rotate_if_needed();
        self.open()
    }
}

pub fn initialize_tracing_logger(
    module_path: &str,
    data_dir: &Path,
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

    let (filter_layer, handle) = reload::Layer::new(filter);

    let enable_ansi = always_write_style || io::stdout().is_terminal();

    let stdout_layer = fmt::layer::<Registry>()
        .compact()
        .with_thread_ids(false)
        .with_target(true)
        .with_file(false)
        .with_line_number(true)
        .with_timer(LocalTimer)
        .with_ansi(enable_ansi);

    if !data_dir.exists() {
        fs::create_dir_all(data_dir)?;
    }

    let log_path = data_dir.join("exception.log");

    let writer = RotatingWriter::new(log_path, 1_000_000_000);

    let exception_filter = EnvFilter::default()
        .add_directive(LevelFilter::OFF.into())
        .add_directive("exception=error".parse()?);

    let file_layer = fmt::layer()
        .compact()
        .with_ansi(false)
        .with_writer(BoxMakeWriter::new(move || writer.make_writer()))
        .with_timer(LocalTimer)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_filter(exception_filter);

    tracing_subscriber::registry()
        .with(stdout_layer.with_filter(filter_layer))
        .with(file_layer)
        .init();

    debug_with_peers!("tracing started!");
    exception!("exception macro is enabled");
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
            let handle = initialize_tracing_logger(module_path!(), data_dir.path(), false)
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
        handle.modify(|env_filter| {
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
        handle.modify(|env_filter| {
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

        handle.modify(|env_filter| {
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

        handle.modify(|env_filter| {
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
