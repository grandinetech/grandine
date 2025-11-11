use core::sync::atomic::{AtomicUsize, Ordering};
use tracing as _;

use derive_more::Display;

pub static PEER_LOG_METRICS: PeerLogMetrics = PeerLogMetrics::new(0);

#[derive(Display, Debug)]
#[display("[{connected_peer_count:?}/{target_peer_count:?}]")]
pub struct PeerLogMetrics {
    connected_peer_count: AtomicUsize,
    target_peer_count: AtomicUsize,
}

impl PeerLogMetrics {
    #[must_use]
    pub const fn new(target_peer_count: usize) -> Self {
        Self {
            connected_peer_count: AtomicUsize::new(0),
            target_peer_count: AtomicUsize::new(target_peer_count),
        }
    }

    pub fn set_connected_peer_count(&self, connected_peer_count: usize) {
        self.connected_peer_count
            .store(connected_peer_count, Ordering::Relaxed)
    }

    pub fn set_target_peer_count(&self, target_peer_count: usize) {
        self.target_peer_count
            .store(target_peer_count, Ordering::Relaxed)
    }
}

#[macro_export]
macro_rules! info_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::info!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! warn_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::warn!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! error_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::error!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! exception {
    ( $( $rest:tt )* ) => {
        ::tracing::error!(
            target: "exception",
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! debug_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::debug!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[macro_export]
macro_rules! trace_with_peers {
    ( $( $rest:tt )* ) => {
        ::tracing::trace!(
            peers = %$crate::PEER_LOG_METRICS,
            $( $rest )*
        )
    };
}

#[cfg(test)]
mod tests {
    use std::sync::{LazyLock, Mutex};

    use binary_utils::{initialize_tracing_logger, TracingHandle};
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

    #[test]
    #[serial]
    fn exception_macro_logs() -> anyhow::Result<()> {
        use gag::BufferRedirect;
        use std::io::Read;

        let mut buf = BufferRedirect::stdout().expect("failed to redirect stdout");

        let handle = init_logger_once();
        handle.modify_log(|env_filter| {
            let new_filter = env_filter
                .clone()
                .add_directive("exception".parse().expect("Failed to parse"));
            *env_filter = new_filter;
        })?;

        PEER_LOG_METRICS.set_connected_peer_count(2);
        PEER_LOG_METRICS.set_target_peer_count(4);

        exception!("suspicious behavior has occurred");

        let mut output = String::new();
        buf.read_to_string(&mut output)?;

        assert!(
            output.contains("suspicious behavior has occurred"),
            "Here is output:\n{output}"
        );
        assert!(output.contains("[2/4]"), "Here is output:\n{output}");

        Ok(())
    }

    #[test]
    #[serial]
    fn info_with_peers_formats_correctly_various_ways() -> anyhow::Result<()> {
        use gag::BufferRedirect;
        use std::io::Read;

        let mut buf = BufferRedirect::stdout().expect("failed to redirect stdout");

        let _handle = init_logger_once();

        PEER_LOG_METRICS.set_connected_peer_count(2);
        PEER_LOG_METRICS.set_target_peer_count(4);

        let x1 = "value1";
        let x2 = "value2";
        let x3 = "value3";

        info_with_peers!("Plain info message");
        info_with_peers!("Formatted message: {}", x1);
        info_with_peers!(field1 = x1, field2 = x2, "Combined message: {}", x3);

        // With trailing comma
        info_with_peers!(
            "Trailing comma message: {x3} \
            because of something",
        );

        // Just a field, no message text
        info_with_peers!(field0 = "foo");

        let mut output = String::new();
        buf.read_to_string(&mut output)?;

        assert!(output.contains("Plain info message"));
        assert!(output.contains("Formatted message: value1"));
        assert!(output.contains("Combined message: value3"));
        assert!(output.contains("[2/4]"));
        assert!(output.contains("field1=\"value1\""));
        assert!(output.contains("field2=\"value2\""));
        assert!(output.contains("Trailing comma message: value3 because of something"));
        assert!(output.contains("field0=\"foo\""));

        Ok(())
    }
}
