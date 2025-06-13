use std::io::{prelude::*, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use fs_err::{File, OpenOptions};
use log::{debug, warn};
use types::config::Config;
use types::phase0::primitives::Epoch;

const CUSTODY_UPDATES_SCHEDULE_FILENAME: &str = "custody_updates_schedule";

pub struct ValidatorCustody {
    updates_schedule: Vec<(Epoch, u64)>,
    chain_config: Arc<Config>,
    network_dir: Option<PathBuf>,
}

impl ValidatorCustody {
    pub fn load_updates_schedule(network_dir: Option<&Path>, chain_config: Arc<Config>) -> Self {
        let mut updates_schedule = Vec::new();

        if let Some(dir) = network_dir {
            let updates_schedule_path = dir.join(CUSTODY_UPDATES_SCHEDULE_FILENAME);
            if let Ok(file) = File::open(updates_schedule_path) {
                let reader = BufReader::new(file);

                for entry in reader.lines().map_while(Result::ok) {
                    let parts: Vec<&str> = entry.trim().split(',').collect();

                    if parts.len() == 2 {
                        if let Ok(epoch) = parts[0].parse::<Epoch>() {
                            if let Ok(cgc) = parts[1].parse::<u64>() {
                                updates_schedule.push((epoch, cgc));
                            }
                        }
                    }
                }
            }
        }

        debug!("custody updates schedule: {updates_schedule:?}");

        Self {
            updates_schedule,
            chain_config,
            network_dir: network_dir.map(Path::to_path_buf),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.updates_schedule.is_empty()
    }

    pub fn at_epoch(&self, current_epoch: Epoch) -> u64 {
        self.updates_schedule
            .iter()
            .find_map(|(epoch, cgc)| (current_epoch >= *epoch).then_some(*cgc))
            .unwrap_or(self.chain_config.custody_requirement)
    }

    pub fn schedule_custody_update(&mut self, epoch: Epoch, custody_group_count: u64) {
        self.updates_schedule.push((epoch, custody_group_count));
        save_entry_to_disk(epoch, custody_group_count, self.network_dir.as_deref());
    }
}

fn save_entry_to_disk(epoch: Epoch, custody_group_count: u64, network_dir: Option<&Path>) {
    let Some(dir) = network_dir else {
        debug!("Skipping Metadata writing to disk");
        return;
    };

    let write_to_disk = || -> Result<()> {
        let filename = dir.join(CUSTODY_UPDATES_SCHEDULE_FILENAME);

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)?;

        writeln!(file, "{epoch},{custody_group_count}")?;
        Ok(())
    };

    match write_to_disk() {
        Ok(()) => {
            debug!("Custody update entry written to disk");
        }
        Err(_) => {
            warn!("Could not write custody update entry to disk");
        }
    }
}
