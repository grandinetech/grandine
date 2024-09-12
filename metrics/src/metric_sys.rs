#[cfg(target_os = "windows")]
use anyhow::bail;
use anyhow::{Ok, Result};
#[cfg(target_os = "windows")]
use log::trace;
#[cfg(target_os = "linux")]
use log::warn;
#[cfg(target_os = "linux")]
use psutil::cpu::{self, CpuTimes};
#[cfg(target_os = "windows")]
use std::mem::size_of;
#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::FILETIME,
    System::{
        ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::{GetCurrentProcess, GetProcessTimes, GetSystemTimes},
    },
};

pub(crate) struct ProcessCpuMetric {
    pub(crate) cpu_process_seconds_total: u64,
    pub(crate) memory_process_bytes: u64,
}

pub fn get_process_cpu_metric() -> Result<ProcessCpuMetric> {
    #[cfg(target_os = "linux")]
    {
        get_process_cpu_metric_linux()
    }
    #[cfg(target_os = "windows")]
    {
        get_process_cpu_metric_win()
    }
}

#[cfg(target_os = "linux")]
fn get_process_cpu_metric_linux() -> Result<ProcessCpuMetric> {
    use psutil::process::Process;
    use std::result::Result::Ok;
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
    Ok(ProcessCpuMetric {
        cpu_process_seconds_total,
        memory_process_bytes,
    })
}

#[allow(unsafe_code, unused_assignments)]
#[cfg(target_os = "windows")]
fn get_process_cpu_metric_win() -> Result<ProcessCpuMetric> {
    let mut cpu_process_seconds_total = 0;
    let mut memory_process_bytes: u64 = 0;

    let process_handle = unsafe { GetCurrentProcess() };

    // Get CPU times
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();

    if unsafe {
        GetProcessTimes(
            process_handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
        .is_ok()
    } {
        let kernel_seconds = filetime_to_seconds(&kernel_time);
        let user_seconds = filetime_to_seconds(&user_time);
        cpu_process_seconds_total = kernel_seconds + user_seconds;
        trace!("CPU time: {:.2} seconds", cpu_process_seconds_total);
    } else {
        bail!("Unable to get process CPU usage");
    }

    // Get memory info
    let mut mem_counters = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };

    if unsafe {
        GetProcessMemoryInfo(
            process_handle,
            &mut mem_counters,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .is_ok()
    } {
        memory_process_bytes = mem_counters.WorkingSetSize as _;
        trace!("Memory usage: {} bytes", memory_process_bytes);
    } else {
        bail!("Unable to get process memory usage");
    }

    Ok(ProcessCpuMetric {
        cpu_process_seconds_total,
        memory_process_bytes,
    })
}

pub(crate) struct CpuMetric {
    pub(crate) idle_seconds: u64,
    pub(crate) system_seconds: u64,
    pub(crate) user_seconds: u64,
}

pub fn get_cpu_metric() -> Result<CpuMetric> {
    #[cfg(target_os = "linux")]
    {
        get_cpu_metric_linux()
    }
    #[cfg(target_os = "windows")]
    {
        get_cpu_metric_win()
    }
}

// TODO maybe work for MacOS or wider Unix?
#[cfg(target_os = "linux")]
fn get_cpu_metric_linux() -> Result<CpuMetric> {
    let cpu_times = cpu::cpu_times()
        .map_err(|error| warn!("unable to get CPU times information: {error:?}"))
        .ok();
    let cpu = cpu_times.as_ref();
    let system_seconds = cpu.map(CpuTimes::total).unwrap_or_default().as_secs();
    let user_seconds = cpu.map(CpuTimes::user).unwrap_or_default().as_secs();
    let idle_seconds = cpu.map(CpuTimes::idle).unwrap_or_default().as_secs();
    Ok(CpuMetric {
        idle_seconds,
        system_seconds,
        user_seconds,
    })
}

#[allow(unsafe_code)]
#[cfg(target_os = "windows")]
fn get_cpu_metric_win() -> Result<CpuMetric> {
    let mut idle_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();

    unsafe {
        if GetSystemTimes(
            Some(&mut idle_time),
            Some(&mut kernel_time),
            Some(&mut user_time),
        )
        .is_err()
        {
            bail!("Failed to get system times");
        }
    }

    // Convert FILETIME to u64 (100-nanosecond intervals)
    let idle = filetime_to_seconds(&idle_time);
    let kernel = filetime_to_seconds(&kernel_time);
    let user = filetime_to_seconds(&user_time);

    // Calculate system time (kernel time includes idle time)
    let system = kernel - idle;

    Ok(CpuMetric {
        idle_seconds: idle,
        system_seconds: system,
        user_seconds: user,
    })
}

#[inline(always)]
#[cfg(target_os = "windows")]
fn filetime_to_seconds(ft: &FILETIME) -> u64 {
    let total_seconds = ((ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64) / 10_000_000;
    total_seconds
}
