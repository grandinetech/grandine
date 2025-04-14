use std::path::{Path, PathBuf};

use anyhow::Result;
use bls::Backend;
use genesis::AnchorCheckpointProvider;
use log::info;
use ssz::{SszHash as _, SszRead, SszWrite as _};
use std_ext::ArcExt as _;
use thiserror::Error;
use transition_functions::combined;
use types::{
    combined::BeaconState, config::Config, phase0::primitives::Slot, preset::Preset,
    traits::BeaconState as _,
};

use crate::Storage;

#[derive(Debug, Error)]
enum Error {
    #[error("state file is missing for slot: {slot}")]
    StateFileMissing { slot: Slot },
}

pub fn export_state_and_blocks<P: Preset>(
    storage: &Storage<P>,
    from_slot: Slot,
    to_slot: Slot,
    output_dir: &Path,
    anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
) -> Result<()> {
    let export_state = |state_slot| -> Result<()> {
        let state = match storage.stored_state(state_slot)? {
            Some(found_state) => found_state,
            None => {
                let mut temporary_state =
                    anchor_checkpoint_provider.clone().checkpoint().value.state;

                for current_slot in (temporary_state.slot() + 1)..=state_slot {
                    if let Some((block, _)) = storage.finalized_block_by_slot(current_slot)? {
                        combined::untrusted_state_transition(
                            storage.config(),
                            temporary_state.make_mut(),
                            &block,
                        )?;
                    }
                }

                if temporary_state.slot() < state_slot {
                    combined::process_slots(
                        storage.config(),
                        temporary_state.make_mut(),
                        state_slot,
                        storage.backend,
                    )?;
                }

                assert_eq!(temporary_state.slot(), state_slot);

                temporary_state
            }
        };

        let state_file_name = format!(
            "beacon_state_slot_{state_slot:06}_root_{:?}.ssz",
            state.hash_tree_root(),
        );

        fs_err::write(output_dir.join(state_file_name), state.to_ssz()?)?;

        Ok(())
    };

    export_state(from_slot)?;
    export_state(to_slot)?;

    for current_slot in from_slot..=to_slot {
        if let Some((block, block_root)) = storage.finalized_block_by_slot(current_slot)? {
            let block_file_name =
                format!("beacon_block_slot_{current_slot:06}_root_{block_root:?}.ssz");

            fs_err::write(output_dir.join(block_file_name), block.to_ssz()?)?;
        }
    }

    Ok(())
}

pub fn replay_blocks<P: Preset>(
    config: &Config,
    input_dir: &Path,
    from_slot: Slot,
    to_slot: Slot,
    backend: Backend,
) -> Result<()> {
    let first_state_file_prefix = format!("beacon_state_slot_{from_slot:06}_root_");
    let mut state =
        from_prefixed_file::<BeaconState<P>>(config, input_dir, &first_state_file_prefix)?
            .ok_or(Error::StateFileMissing { slot: from_slot })?;

    assert_eq!(state.slot(), from_slot);

    for current_slot in (from_slot + 1)..=to_slot {
        let block_file_prefix = format!("beacon_block_slot_{current_slot:06}_root_");
        if let Some(block) = from_prefixed_file(config, input_dir, &block_file_prefix)? {
            combined::untrusted_state_transition(config, &mut state, &block)?;
        }
    }

    if state.slot() < to_slot {
        combined::process_slots(config, &mut state, to_slot, backend)?;
    }

    let last_state_file_prefix = format!("beacon_state_slot_{to_slot:06}_root_");
    let final_state =
        from_prefixed_file::<BeaconState<P>>(config, input_dir, &last_state_file_prefix)?
            .ok_or(Error::StateFileMissing { slot: to_slot })?;

    assert_eq!(final_state.slot(), to_slot);
    assert_eq!(final_state.hash_tree_root(), state.hash_tree_root());

    Ok(())
}

fn from_prefixed_file<T: SszRead<Config>>(
    config: &Config,
    input_dir: &Path,
    file_prefix: &str,
) -> Result<Option<T>> {
    if let Some(file_path) = find_file(input_dir, file_prefix)? {
        let data = fs_err::read(file_path)?;
        let value = T::from_ssz(config, data)?;
        return Ok(Some(value));
    }

    Ok(None)
}

fn find_file(input_dir: &Path, file_prefix: &str) -> Result<Option<PathBuf>> {
    let path = fs_err::read_dir(input_dir)?
        .filter_map(Result::ok)
        .find_map(|file| {
            file.file_name()
                .to_str()?
                .starts_with(file_prefix)
                .then_some(file.path())
        });

    if path.is_none() {
        info!("unable to locate file with prefix {file_prefix}, skipping");
    }

    Ok(path)
}
