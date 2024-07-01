// Code related to beaconcha.in client stats feature.
// See <https://docs.google.com/document/d/1qPWAVRjPCENlyAjUBwGkHMvz9qLdd_6u9DPZcNxDBpc>.

use core::time::Duration;
use std::{
    env::consts::OS,
    time::{SystemTime, UNIX_EPOCH},
};

use build_time::build_time_utc;
use chrono::DateTime;
use eth1_api::{Eth1ConnectionData, Eth1Metrics};
use grandine_version::{APPLICATION_NAME, APPLICATION_VERSION};
use helper_functions::{accessors, predicates};
use log::warn;
use p2p::metrics::PEERS_CONNECTED;
use prometheus::IntGauge;
use psutil::{cpu::CpuTimes, process::Process};
use serde::Serialize;
use sysinfo::{Disks, System};
use types::{preset::Preset, traits::BeaconState};

use crate::{helpers, MetricsService};

#[cfg(target_os = "linux")]
use psutil::{cpu::os::linux::CpuTimesExt, memory::os::linux::VirtualMemoryExt};

const METRICS_VERSION: usize = 1;

#[derive(Serialize)]
pub struct Metrics {
    #[serde(flatten)]
    pub meta: Meta,
    #[serde(flatten)]
    pub metrics: MetricsContent,
}

#[derive(Serialize)]
pub struct Meta {
    version: usize,
    timestamp: u128,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase", tag = "process")]
pub enum MetricsContent {
    BeaconNode {
        #[serde(flatten)]
        general: ProcessMetrics,
        #[serde(flatten)]
        additional: BeaconNodeMetrics,
    },
    Validator {
        #[serde(flatten)]
        general: ProcessMetrics,
        #[serde(flatten)]
        additional: ValidatorMetrics,
    },
    System(SystemMetrics),
}

impl Meta {
    pub fn new() -> Self {
        Self {
            version: METRICS_VERSION,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| warn!("unable to calculate timestamp: {error:?}"))
                .as_ref()
                .map(Duration::as_millis)
                .unwrap_or_default(),
        }
    }
}

#[derive(Clone, Copy, Serialize)]
pub struct ProcessMetrics {
    pub cpu_process_seconds_total: u64,
    pub memory_process_bytes: u64,
    pub client_name: &'static str,
    pub client_version: &'static str,
    pub client_build: i64,
    pub sync_eth2_fallback_configured: bool,
    pub sync_eth2_fallback_connected: bool,
}

impl ProcessMetrics {
    pub fn get() -> Self {
        let mut cpu_process_seconds_total = 0;
        let mut memory_process_bytes = 0;

        match Process::current() {
            Ok(process) => {
                match process.cpu_times() {
                    Ok(cpu_times) => {
                        cpu_process_seconds_total = cpu_times.busy().as_secs()
                            + cpu_times.children_system().as_secs()
                            + cpu_times.children_system().as_secs();
                    }
                    Err(error) => warn!("unable to get current process CPU usage: {error:?}"),
                }

                match process.memory_info() {
                    Ok(mem_info) => {
                        memory_process_bytes = mem_info.rss();
                    }
                    Err(error) => warn!("unable to get process memory usage: {error:?}"),
                }
            }
            Err(error) => warn!("unable to get current process: {error:?}"),
        }

        let client_build = DateTime::parse_from_rfc3339(build_time_utc!())
            .expect("unable to parse build time")
            .timestamp();

        Self {
            cpu_process_seconds_total,
            memory_process_bytes,
            client_name: APPLICATION_NAME,
            client_version: APPLICATION_VERSION,
            client_build,
            // Grandine does not support Eth2 sync fallbacks.
            sync_eth2_fallback_configured: false,
            sync_eth2_fallback_connected: false,
        }
    }
}

// False positive. The `bool`s are independent.
#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
pub struct BeaconNodeMetrics {
    disk_beaconchain_bytes_total: u64,
    network_libp2p_bytes_total_receive: i64,
    network_libp2p_bytes_total_transmit: i64,
    network_peers_connected: i64,
    sync_eth1_connected: bool,
    sync_eth2_synced: bool,
    sync_beacon_head_slot: u64,
    sync_eth1_fallback_configured: bool,
    sync_eth1_fallback_connected: bool,
    slasher_active: bool,
}

impl BeaconNodeMetrics {
    pub fn get<P: Preset>(service: &MetricsService<P>) -> Self {
        let MetricsService {
            controller,
            config,
            is_synced,
            eth1_metrics,
            slasher_active,
            ..
        } = service;

        let Eth1Metrics {
            eth1_connection_data,
            sync_eth1_fallback_configured,
        } = *eth1_metrics;

        let Eth1ConnectionData {
            sync_eth1_connected,
            sync_eth1_fallback_connected,
        } = eth1_connection_data;

        let network_peers_connected = PEERS_CONNECTED
            .as_ref()
            .map(IntGauge::get)
            .unwrap_or_default();

        // TODO(feature/metrics): figure this out with prometheus_client
        // let network_libp2p_bytes_total_receive = INBOUND_LIBP2P_BYTES
        //     .as_ref()
        //     .map(IntGauge::get)
        //     .unwrap_or_default();

        // let network_libp2p_bytes_total_transmit = OUTBOUND_LIBP2P_BYTES
        //     .as_ref()
        //     .map(IntGauge::get)
        //     .unwrap_or_default();

        let network_libp2p_bytes_total_receive = 0;
        let network_libp2p_bytes_total_transmit = 0;

        let disk_beaconchain_bytes_total = config.directories.disk_usage().unwrap_or_default();

        Self {
            disk_beaconchain_bytes_total,
            network_libp2p_bytes_total_receive,
            network_libp2p_bytes_total_transmit,
            network_peers_connected,
            sync_eth1_connected,
            sync_eth2_synced: *is_synced,
            sync_beacon_head_slot: controller.head_slot(),
            sync_eth1_fallback_configured,
            sync_eth1_fallback_connected,
            slasher_active: *slasher_active,
        }
    }
}

#[derive(Serialize)]
pub struct ValidatorMetrics {
    validator_active: usize,
    validator_total: usize,
}

impl ValidatorMetrics {
    pub fn get<P: Preset>(service: &MetricsService<P>) -> Self {
        let MetricsService {
            controller,
            validator_keys,
            ..
        } = service;

        let state = controller.head_state().value;
        let current_epoch = accessors::get_current_epoch(&state);

        let validator_active = validator_keys
            .iter()
            .filter(|pubkey| {
                accessors::index_of_public_key(&state, **pubkey)
                    .and_then(|validator_index| state.validators().get(validator_index).ok())
                    .is_some_and(|validator| {
                        predicates::is_active_validator(validator, current_epoch)
                    })
            })
            .count();

        Self {
            validator_active,
            validator_total: validator_keys.len(),
        }
    }
}

#[derive(Serialize)]
pub struct SystemMetrics {
    // CPU
    cpu_cores: usize,
    cpu_threads: usize,
    cpu_node_system_seconds_total: u64,
    cpu_node_user_seconds_total: u64,
    cpu_node_idle_seconds_total: u64,

    // memory
    memory_node_bytes_total: u64,
    memory_node_bytes_free: u64,

    // disk
    disk_node_bytes_total: u64,
    disk_node_bytes_free: u64,
    disk_node_io_seconds: u64,
    disk_node_reads_total: u64,
    disk_node_writes_total: u64,

    // network
    network_node_bytes_total_receive: u64,
    network_node_bytes_total_transmit: u64,

    // misc
    misc_node_boot_ts_seconds: u64,
    misc_os: &'static str,

    // platform-specific metrics
    #[serde(flatten)]
    platform_specific_metrics: PlatformSpecificSystemMetrics,
}

#[derive(Serialize)]
#[cfg_attr(not(target_os = "linux"), derive(Default))]
struct PlatformSpecificSystemMetrics {
    // CPU
    cpu_node_iowait_seconds_total: u64,

    // memory
    memory_node_bytes_cached: u64,
    memory_node_bytes_buffers: u64,
}

impl PlatformSpecificSystemMetrics {
    #[cfg(not(target_os = "linux"))]
    fn new(_cpu: Option<&CpuTimes>) -> Self {
        Self::default()
    }

    #[cfg(target_os = "linux")]
    fn new(cpu: Option<&CpuTimes>) -> Self {
        let mem = psutil::memory::virtual_memory()
            .map_err(|error| warn!("unable to get virtual memory information: {error:?}"))
            .ok();

        let mem = mem.as_ref();

        Self {
            // CPU
            cpu_node_iowait_seconds_total: cpu
                .map(CpuTimesExt::iowait)
                .unwrap_or_default()
                .as_secs(),

            // memory
            memory_node_bytes_cached: mem.map(VirtualMemoryExt::cached).unwrap_or_default(),
            memory_node_bytes_buffers: mem.map(VirtualMemoryExt::buffers).unwrap_or_default(),
        }
    }
}

impl SystemMetrics {
    pub fn get(system: &System) -> Self {
        let mut disk_node_bytes_total = 0;
        let mut disk_node_bytes_free = 0;

        for disk in Disks::new_with_refreshed_list().list() {
            disk_node_bytes_total += disk.total_space();
            disk_node_bytes_free += disk.available_space();
        }

        let (network_node_bytes_total_receive, network_node_bytes_total_transmit) =
            helpers::get_network_bytes();

        let cpu_times = psutil::cpu::cpu_times()
            .map_err(|error| warn!("unable to get CPU times information: {error:?}"))
            .ok();

        let cpu = cpu_times.as_ref();

        Self {
            // CPU
            cpu_cores: system.physical_core_count().unwrap_or_default(),
            cpu_threads: system.cpus().len(),
            cpu_node_system_seconds_total: cpu.map(CpuTimes::total).unwrap_or_default().as_secs(),
            cpu_node_user_seconds_total: cpu.map(CpuTimes::user).unwrap_or_default().as_secs(),
            cpu_node_idle_seconds_total: cpu.map(CpuTimes::idle).unwrap_or_default().as_secs(),

            // memory
            memory_node_bytes_total: system.total_memory(),
            memory_node_bytes_free: system.free_memory(),

            // disk
            disk_node_bytes_total,
            disk_node_bytes_free,
            disk_node_io_seconds: 0,
            disk_node_reads_total: 0,
            disk_node_writes_total: 0,

            // network
            network_node_bytes_total_receive,
            network_node_bytes_total_transmit,

            // misc
            misc_node_boot_ts_seconds: System::boot_time(),
            misc_os: metrics_os(),

            // platform specific metrics
            platform_specific_metrics: PlatformSpecificSystemMetrics::new(cpu),
        }
    }
}

fn metrics_os() -> &'static str {
    match OS {
        "linux" => "lin",
        "macos" => "mac",
        "windows" => "win",
        _ => "unk",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Result, Value};

    use super::*;

    #[test]
    fn metrics_are_serialized_correctly() -> Result<()> {
        let expected_json = example_metrics_json();
        let actual_json = serde_json::to_value(example_metrics())?;

        assert_eq!(actual_json, expected_json);

        Ok(())
    }

    const fn example_metrics() -> [Metrics; 3] {
        let general = ProcessMetrics {
            cpu_process_seconds_total: 1_234_567,
            memory_process_bytes: 654_321,
            client_name: APPLICATION_NAME,
            client_version: APPLICATION_VERSION,
            client_build: 12,
            sync_eth2_fallback_configured: false,
            sync_eth2_fallback_connected: false,
        };

        [
            Metrics {
                meta: Meta {
                    version: METRICS_VERSION,
                    timestamp: 1_618_835_497_239,
                },
                metrics: MetricsContent::BeaconNode {
                    general,
                    additional: BeaconNodeMetrics {
                        disk_beaconchain_bytes_total: 12_884_901_888,
                        network_libp2p_bytes_total_receive: 23_008_753_371,
                        network_libp2p_bytes_total_transmit: 1_789_569_707,
                        network_peers_connected: 41,
                        sync_eth1_connected: true,
                        sync_eth2_synced: true,
                        sync_beacon_head_slot: 1_000_956,
                        sync_eth1_fallback_configured: false,
                        sync_eth1_fallback_connected: false,
                        slasher_active: false,
                    },
                },
            },
            Metrics {
                meta: Meta {
                    version: METRICS_VERSION,
                    timestamp: 11_234_567,
                },
                metrics: MetricsContent::Validator {
                    general,
                    additional: ValidatorMetrics {
                        validator_active: 2,
                        validator_total: 3,
                    },
                },
            },
            Metrics {
                meta: Meta {
                    version: METRICS_VERSION,
                    timestamp: 1_618_835_497_258,
                },
                metrics: MetricsContent::System(SystemMetrics {
                    // CPU
                    cpu_cores: 4,
                    cpu_threads: 8,
                    cpu_node_system_seconds_total: 1_953_818,
                    cpu_node_user_seconds_total: 229_215,
                    cpu_node_idle_seconds_total: 1_688_619,

                    // memory
                    memory_node_bytes_total: 33_237_434_368_u64,
                    memory_node_bytes_free: 500_150_272,

                    // disk
                    disk_node_bytes_total: 250_436_972_544,
                    disk_node_bytes_free: 124_707_479_552,
                    disk_node_io_seconds: 0,
                    disk_node_reads_total: 3_362_272,
                    disk_node_writes_total: 47_766_864,

                    // network
                    network_node_bytes_total_receive: 26_546_324_572,
                    network_node_bytes_total_transmit: 12_057_786_467,

                    // misc
                    misc_node_boot_ts_seconds: 1_617_707_420,
                    misc_os: "unk",

                    // platform-specific metrics
                    platform_specific_metrics: PlatformSpecificSystemMetrics {
                        // CPU
                        cpu_node_iowait_seconds_total: 3761,

                        // memory
                        memory_node_bytes_cached: 13_904_945_152_u64,
                        memory_node_bytes_buffers: 517_832_704,
                    },
                }),
            },
        ]
    }

    fn example_metrics_json() -> Value {
        json!([
            {
                "version": METRICS_VERSION,
                "timestamp": 1_618_835_497_239_u64,
                "process": "beaconnode",

                "cpu_process_seconds_total": 1_234_567,
                "memory_process_bytes": 654_321,
                "client_name": APPLICATION_NAME,
                "client_version": APPLICATION_VERSION,
                "client_build": 12,
                "sync_eth2_fallback_configured": false,
                "sync_eth2_fallback_connected": false,

                "disk_beaconchain_bytes_total": 12_884_901_888_u64,
                "network_libp2p_bytes_total_receive": 23_008_753_371_u64,
                "network_libp2p_bytes_total_transmit": 1_789_569_707,
                "network_peers_connected": 41,
                "sync_eth1_connected": true,
                "sync_eth2_synced": true,
                "sync_beacon_head_slot": 1_000_956,
                "sync_eth1_fallback_configured": false,
                "sync_eth1_fallback_connected": false,
                "slasher_active": false,
            },
            {
                "version": METRICS_VERSION,
                "timestamp": 11_234_567,
                "process": "validator",

                "cpu_process_seconds_total": 1_234_567,
                "memory_process_bytes": 654_321,
                "client_name": APPLICATION_NAME,
                "client_version": APPLICATION_VERSION,
                "client_build": 12,
                "sync_eth2_fallback_configured": false,
                "sync_eth2_fallback_connected": false,

                "validator_total": 3,
                "validator_active": 2,
            },
            {
                "version": METRICS_VERSION,
                "timestamp": 1_618_835_497_258_u64,
                "process": "system",

                "cpu_cores": 4,
                "cpu_threads": 8,
                "cpu_node_system_seconds_total": 1_953_818,
                "cpu_node_user_seconds_total": 229_215,
                "cpu_node_iowait_seconds_total": 3761,
                "cpu_node_idle_seconds_total": 1_688_619,
                "memory_node_bytes_total": 33_237_434_368_u64,
                "memory_node_bytes_free": 500_150_272,
                "memory_node_bytes_cached": 13_904_945_152_u64,
                "memory_node_bytes_buffers": 517_832_704,
                "disk_node_bytes_total": 250_436_972_544_u64,
                "disk_node_bytes_free": 124_707_479_552_u64,
                "disk_node_io_seconds": 0,
                "disk_node_reads_total": 3_362_272,
                "disk_node_writes_total": 47_766_864,
                "network_node_bytes_total_receive": 26_546_324_572_u64,
                "network_node_bytes_total_transmit": 12_057_786_467_u64,
                "misc_node_boot_ts_seconds": 1_617_707_420,
                "misc_os": "unk",
            },
        ])
    }
}
