// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use core::{cell::LazyCell, convert::Infallible as Never};
use std::sync::Arc;

use allocator as _;
use anyhow::Result;
use clock::Tick;
use criterion::{BatchSize, Criterion, Throughput};
use easy_ext::ext;
use eth2_cache_utils::holesky::{self, CAPELLA_BEACON_STATE};
use execution_engine::NullExecutionEngine;
use fork_choice_store::{
    ApplyBlockChanges, ApplyTickChanges, AttestationAction, AttestationItem, AttestationOrigin,
    BlockAction, Store, StoreConfig, ValidAttestation,
};
use helper_functions::{misc, verifier::NullVerifier};
use itertools::Itertools as _;
use std_ext::ArcExt as _;
use transition_functions::{combined, unphased::StateRootPolicy};
use types::{
    combined::SignedBeaconBlock,
    config::Config,
    phase0::{containers::Attestation, primitives::Slot},
    preset::{Mainnet, Preset},
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

// Criterion macros only add confusion.
fn main() {
    Criterion::default()
        .configure_from_args()
        .benchmark_store_apply_tick()
        .final_summary();
}

#[ext]
impl Criterion {
    fn benchmark_store_apply_tick(&mut self) -> &mut Self {
        // The slot is at a weird point in the epoch, but it's good enough for benchmarking.
        // We have no attestations from later slots in `eth2-cache`.
        let last_attestation_slot = 50014;

        let next_ordinary_slot = last_attestation_slot + 1;
        let next_ordinary_tick = Tick::start_of_slot(next_ordinary_slot);

        let next_epoch_start_slot = next_ordinary_slot + 1;
        let next_epoch_start_tick = Tick::start_of_slot(next_epoch_start_slot);

        assert!(misc::is_epoch_start::<Mainnet>(next_epoch_start_slot));

        let store_before_next_ordinary_slot = LazyCell::new(|| {
            let run = || -> Result<_> {
                let config = Arc::new(Config::holesky());
                let anchor_state = CAPELLA_BEACON_STATE.force().clone_arc();
                let anchor_slot = anchor_state.slot();

                let anchor_block = holesky::beacon_blocks(anchor_slot..=anchor_slot, 6)
                    .into_iter()
                    .exactly_one()?;

                let mut store = Store::new(
                    config.clone_arc(),
                    StoreConfig::default(),
                    anchor_block,
                    anchor_state,
                    false,
                );

                for slot in (anchor_slot + 1)..=last_attestation_slot {
                    process_slot(&mut store, slot)?;

                    if let Some(block) = holesky::beacon_blocks(slot..=slot, 6)
                        .into_iter()
                        .at_most_one()?
                    {
                        process_block(&mut store, &block)?
                    }

                    for attestation in holesky::aggregate_attestations_by_slot(slot) {
                        process_attestation(&mut store, Arc::new(attestation))?;
                    }
                }

                assert_eq!(store.head().slot(), last_attestation_slot);

                Ok(store)
            };

            run().expect("all data should be processed successfully")
        });

        let store_before_next_epoch = LazyCell::new(|| {
            let mut store = LazyCell::force(&store_before_next_ordinary_slot).clone();

            process_slot(&mut store, next_ordinary_slot)
                .expect("slot should be processed successfully");

            store
        });

        self.benchmark_group("Store::apply_tick")
            .throughput(Throughput::Elements(1))
            .bench_function(
                format!("at slot {next_ordinary_slot} in Holesky"),
                |bencher| {
                    let store = LazyCell::force(&store_before_next_ordinary_slot);

                    bencher.iter_batched_ref(
                        || store.clone(),
                        |store| store.apply_tick(next_ordinary_tick),
                        BatchSize::SmallInput,
                    );
                },
            )
            .bench_function(
                format!("at slot {next_epoch_start_slot} in Holesky"),
                |bencher| {
                    let store = LazyCell::force(&store_before_next_epoch);

                    bencher.iter_batched_ref(
                        || store.clone(),
                        |store| store.apply_tick(next_epoch_start_tick),
                        BatchSize::SmallInput,
                    );
                },
            );

        self
    }
}

fn process_slot(store: &mut Store<impl Preset>, slot: Slot) -> Result<()> {
    let Some(changes) = store.apply_tick(Tick::start_of_slot(slot))? else {
        panic!("tick at slot {slot} should be later than the current one")
    };

    let ApplyTickChanges::SlotUpdated { .. } = changes else {
        panic!("tick should update store to slot {slot} without a reorganization")
    };

    Ok(())
}

fn process_block<P: Preset>(store: &mut Store<P>, block: &Arc<SignedBeaconBlock<P>>) -> Result<()> {
    let slot = block.message().slot();

    let block_action = store.validate_block(
        block,
        StateRootPolicy::Trust,
        NullExecutionEngine,
        NullVerifier,
    )?;

    let BlockAction::Accept(chain_link, _) = block_action else {
        panic!("block at slot {slot} should be accepted")
    };

    if let ApplyBlockChanges::Reorganized { .. } = store.apply_block(chain_link)? {
        panic!("block at slot {slot} should not cause a reorganization")
    };

    let checkpoint = store.unrealized_justified_checkpoint();

    if !store.contains_checkpoint_state(checkpoint) {
        let mut checkpoint_state = store
            .state_by_block_root(checkpoint.root)
            .expect("base state should be present in the store");

        let checkpoint_slot = misc::compute_start_slot_at_epoch::<Mainnet>(checkpoint.epoch);

        if checkpoint_state.slot() < checkpoint_slot {
            combined::process_slots(
                store.chain_config(),
                checkpoint_state.make_mut(),
                checkpoint_slot,
            )?;
        }

        store.insert_checkpoint_state(checkpoint, checkpoint_state);
    }

    Ok(())
}

fn process_attestation<P: Preset>(
    store: &mut Store<P>,
    attestation: Arc<Attestation<P>>,
) -> Result<()> {
    let slot = attestation.data.slot;
    let origin = AttestationOrigin::<Never>::Test;
    let attestation_action =
        store.validate_attestation(AttestationItem::unverified(attestation, origin), false)?;

    let AttestationAction::Accept {
        attestation,
        attesting_indices,
    } = attestation_action
    else {
        panic!("attestation at slot {slot} should be accepted")
    };

    let valid_attestation = ValidAttestation {
        data: attestation.data(),
        attesting_indices,
        is_from_block: false,
    };

    assert!(
        store.apply_attestation(valid_attestation)?.is_none(),
        "attestation at slot {slot} should not cause a reorganization",
    );

    Ok(())
}
