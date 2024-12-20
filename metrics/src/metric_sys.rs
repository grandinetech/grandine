use anyhow::Result;
#[cfg(target_os = "linux")]
use {
    anyhow::bail,
    psutil::{cpu, process::Process},
};
#[cfg(target_os = "windows")]
use {
    log::debug,
    winsafe::{self as w, prelude::*},
};

pub struct ProcessCpuMetric {
    pub cpu_process_seconds_total: u64,
    pub memory_process_bytes: u64,
}

#[cfg(target_os = "linux")]
pub fn get_process_cpu_metric() -> Result<ProcessCpuMetric> {
    #[expect(unused_assignments)]
    let mut cpu_process_seconds_total = 0;
    #[expect(unused_assignments)]
    let mut memory_process_bytes = 0;
    match Process::current() {
        Ok(process) => {
            match process.cpu_times() {
                Ok(cpu_times) => {
                    cpu_process_seconds_total = cpu_times.busy().as_secs()
                        + cpu_times.children_system().as_secs()
                        + cpu_times.children_system().as_secs();
                }
                Err(error) => bail!("unable to get current process CPU usage: {error:?}"),
            }

            match process.memory_info() {
                Ok(mem_info) => {
                    memory_process_bytes = mem_info.rss();
                }
                Err(error) => bail!("unable to get process memory usage: {error:?}"),
            }
        }
        Err(error) => bail!("unable to get current process: {error:?}"),
    }
    Ok(ProcessCpuMetric {
        cpu_process_seconds_total,
        memory_process_bytes,
    })
}

#[expect(unused_assignments)]
#[cfg(target_os = "windows")]
pub fn get_process_cpu_metric() -> Result<ProcessCpuMetric> {
    let proc = w::HPROCESS::GetCurrentProcess();

    // Get CPU times
    let (_, _, kernel, user) = proc.GetProcessTimes()?;
    let kernel_seconds = filetime_to_seconds(kernel);
    let user_seconds = filetime_to_seconds(user);
    let cpu_process_seconds_total = kernel_seconds + user_seconds;
    debug!("CPU time: {:.2} seconds", cpu_process_seconds_total);

    // Get memory info
    let mem_info = proc.GetProcessMemoryInfo()?;
    let memory_process_bytes = mem_info.WorkingSetSize.try_into()?;
    debug!("memory usage: {} bytes", memory_process_bytes);

    Ok(ProcessCpuMetric {
        cpu_process_seconds_total,
        memory_process_bytes,
    })
}

#[derive(Debug)]
pub struct CpuMetric {
    pub idle_seconds: u64,
    pub system_seconds: u64,
    pub user_seconds: u64,
}

// TODO maybe work for MacOS or wider Unix?
#[cfg(target_os = "linux")]
pub fn get_cpu_metric() -> Result<CpuMetric> {
    let cpu = cpu::cpu_times()?;
    let system_seconds = cpu.total().as_secs();
    let user_seconds = cpu.user().as_secs();
    let idle_seconds = cpu.idle().as_secs();
    Ok(CpuMetric {
        idle_seconds,
        system_seconds,
        user_seconds,
    })
}

#[cfg(target_os = "windows")]
pub fn get_cpu_metric() -> Result<CpuMetric> {
    let (idle_time, kernel_time, user_time) = w::GetSystemTimes()?;

    // Convert FILETIME to u64 (100-nanosecond intervals)
    let idle = filetime_to_seconds(idle_time);
    let kernel = filetime_to_seconds(kernel_time);
    let user = filetime_to_seconds(user_time);

    // Calculate system time (kernel time includes idle time)
    let system = kernel - idle;

    Ok(CpuMetric {
        idle_seconds: idle,
        system_seconds: system,
        user_seconds: user,
    })
}

// NOTE:
//   FILETIME: Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC). (Ref: https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime)
//   But some Windows APIs just use it to represent a relative time interval, a.k.a., duration.
//   For example, GetSystemTimes like APIs are used in this mod.
//   The helper function just converts the number of 100-nanosecond into the number of seconds
#[inline(always)]
#[cfg(target_os = "windows")]
fn filetime_to_seconds(ft: w::FILETIME) -> u64 {
    let total_seconds = ((ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64) / 10_000_000;
    total_seconds
}
