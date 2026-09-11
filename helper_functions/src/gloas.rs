use core::marker::PhantomData;

use anyhow::Result;
use bls::PublicKeyBytes;
use ssz::{ProgressiveList, SszList as _, SszListMut as _};
use try_from_iterator::TryFromIterator as _;
use types::{
    config::Config,
    gloas::{
        containers::{Attestation, Builder, IndexedAttestation},
        primitives::BuilderIndex,
    },
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        primitives::{ExecutionAddress, Gwei, Slot},
    },
    preset::Preset,
    traits::{BeaconState, PostGloasBeaconState},
};

use crate::{
    accessors::get_current_epoch, electra::get_attesting_indices, error::Error,
    misc::compute_epoch_at_slot,
};

pub fn get_indexed_attestation<P: Preset>(
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<IndexedAttestation<P>> {
    let attesting_indices = get_attesting_indices(state, attestation)?;

    let mut attesting_indices = ProgressiveList::try_from_iter(attesting_indices).expect(
        "Attestation.aggregation_bits and IndexedAttestation.attesting_indices \
         have the same maximum length",
    );

    // Sorting a slice is faster than building a `BTreeMap`.
    attesting_indices.sort_unstable();

    Ok(IndexedAttestation {
        attesting_indices,
        data: attestation.data,
        signature: attestation.signature,
        phantom: PhantomData,
    })
}

/// Remembers that the builder registry has no index left to reuse.
///
/// [`get_index_for_new_builder`] scans the whole registry to answer that.
/// Adding builders never frees an index, so the answer cannot change once it is
/// `true`. Without it, onboarding a deposit queue rescans the registry per
/// deposit, which is quadratic.
///
/// Only share one across additions that cannot free an index, i.e. that never
/// zero a builder balance and never set a `withdrawable_epoch`.
#[derive(Default)]
pub struct ReusableBuilderIndices {
    exhausted: bool,
}

pub fn add_builder_to_registry<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    version: u8,
    address: ExecutionAddress,
    amount: Gwei,
    slot: Slot,
) -> Result<BuilderIndex> {
    add_builder_to_registry_reusing(
        state,
        &mut ReusableBuilderIndices::default(),
        pubkey,
        version,
        address,
        amount,
        slot,
    )
}

/// Like [`add_builder_to_registry`], but skips the search for a reusable index
/// once `reusable` has recorded that there is none left.
pub fn add_builder_to_registry_reusing<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    reusable: &mut ReusableBuilderIndices,
    pubkey: PublicKeyBytes,
    version: u8,
    address: ExecutionAddress,
    amount: Gwei,
    slot: Slot,
) -> Result<BuilderIndex> {
    let length = state.builders().len_u64();

    let builder_index = if reusable.exhausted {
        length
    } else {
        let index = get_index_for_new_builder(state);

        reusable.exhausted = index == length;

        index
    };

    let builder = Builder {
        pubkey,
        version,
        execution_address: address,
        balance: amount,
        deposit_epoch: compute_epoch_at_slot::<P>(slot),
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };

    if builder_index == length {
        state.builders_mut().push(builder)?;
    } else {
        *state.builders_mut().get_mut(builder_index)? = builder;
    }

    // TODO(gloas): Should builder indices be cached like validators?
    // if so, it need to pruned since builder index is reusable. remove this TODO if not
    Ok(builder_index)
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

#[cfg(test)]
mod tests {
    use types::{
        gloas::beacon_state::BeaconState as GloasBeaconState, phase0::primitives::ExecutionAddress,
        preset::Minimal,
    };

    use super::*;

    fn builder(balance: Gwei, withdrawable_epoch: u64) -> Builder {
        Builder {
            pubkey: PublicKeyBytes::default(),
            version: 0,
            execution_address: ExecutionAddress::zero(),
            balance,
            deposit_epoch: 0,
            withdrawable_epoch,
        }
    }

    fn add(
        state: &mut GloasBeaconState<Minimal>,
        reusable: &mut ReusableBuilderIndices,
    ) -> BuilderIndex {
        add_builder_to_registry_reusing(
            state,
            reusable,
            PublicKeyBytes::repeat_byte(1),
            0,
            ExecutionAddress::zero(),
            32_000_000_000,
            0,
        )
        .expect("registry has room")
    }

    #[test]
    fn reuses_a_free_index_before_appending() {
        let mut state = GloasBeaconState::<Minimal>::default();
        let mut reusable = ReusableBuilderIndices::default();

        state
            .builders
            .push(builder(32_000_000_000, FAR_FUTURE_EPOCH))
            .expect("registry has room");

        // Exited and fully withdrawn, so its index can be taken over.
        state
            .builders
            .push(builder(0, 0))
            .expect("registry has room");

        assert_eq!(add(&mut state, &mut reusable), 1);

        // The registry has no free index left, and the cursor must not miss that.
        assert_eq!(add(&mut state, &mut reusable), 2);
        assert_eq!(add(&mut state, &mut reusable), 3);
    }

    #[test]
    fn appends_when_no_index_is_free() {
        let mut state = GloasBeaconState::<Minimal>::default();
        let mut reusable = ReusableBuilderIndices::default();

        assert_eq!(add(&mut state, &mut reusable), 0);
        assert_eq!(add(&mut state, &mut reusable), 1);
        assert_eq!(add(&mut state, &mut reusable), 2);
    }
}
