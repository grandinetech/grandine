use anyhow::Result;
use bls::PublicKeyBytes;
use types::{
    config::Config,
    gloas::{containers::Builder, primitives::BuilderIndex},
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        primitives::{ExecutionAddress, Gwei, Slot},
    },
    preset::Preset,
    traits::PostGloasBeaconState,
};

use crate::{accessors::get_current_epoch, error::Error, misc::compute_epoch_at_slot};

pub fn add_builder_to_registry<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    version: u8,
    address: ExecutionAddress,
    amount: Gwei,
    slot: Slot,
) -> Result<()> {
    let builder_index = get_index_for_new_builder(state);

    let builder = Builder {
        pubkey,
        version,
        execution_address: address,
        balance: amount,
        deposit_epoch: compute_epoch_at_slot::<P>(slot),
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };

    if builder_index == state.builders().len_u64() {
        state.builders_mut().push(builder)?;
    } else {
        *state.builders_mut().get_mut(builder_index)? = builder;
    }

    // TODO(gloas): Should builder indices be cached like validators?
    // if so, it need to pruned since builder index is reusable. remove this TODO if not
    Ok(())
}

pub fn initiate_builder_exit<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    builder_index: BuilderIndex,
) -> Result<()> {
    // > Set builder withdrawable epoch
    let current_epoch = get_current_epoch(state);
    let builder = state.builders_mut().get_mut(builder_index)?;

    builder.withdrawable_epoch = current_epoch
        .checked_add(config.min_builder_withdrawability_delay)
        .ok_or(Error::EpochOverflow)?;

    Ok(())
}

fn get_index_for_new_builder<P: Preset>(state: &impl PostGloasBeaconState<P>) -> BuilderIndex {
    let current_epoch = get_current_epoch(state);

    state
        .builders()
        .into_iter()
        .zip(0..)
        .find_map(|(builder, index)| {
            (builder.withdrawable_epoch <= current_epoch && builder.balance == 0).then_some(index)
        })
        .unwrap_or_else(|| state.builders().len_u64())
}
