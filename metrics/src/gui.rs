use anyhow::{Error, Result};
use sysinfo::System;
use types::nonstandard::SystemStats;

use crate::helpers;

pub fn get_stats(system: &System) -> Result<SystemStats> {
    let grandine_pid = sysinfo::get_current_pid().map_err(Error::msg)?;
    let grandine = system
        .process(grandine_pid)
        .expect("the current process should always be available");

    let (rx_bytes, tx_bytes) = helpers::get_network_bytes();

    Ok(SystemStats {
        rx_bytes,
        tx_bytes,
        core_count: system.cpus().len(),
        grandine_used_memory: grandine.memory(),
        grandine_total_cpu_percentage: grandine.cpu_usage(),
        system_cpu_percentage: system.global_cpu_usage(),
        system_used_memory: system.used_memory(),
        system_total_memory: system.total_memory(),
    })
}
