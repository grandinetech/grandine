use core::ops::Range;
use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use eth1_api::Eth1ExecutionEngine;
use execution_engine::ExecutionEngine;
use fork_choice_control::{Controller, Wait};
use helper_functions::{
    misc,
    verifier::{MultiVerifier, VerifierOption},
};
use itertools::Itertools as _;
use log::{debug, warn};
use rayon::{
    iter::{IndexedParallelIterator as _, IntoParallelIterator as _, ParallelIterator as _},
    ThreadPool, ThreadPoolBuilder,
};
use std_ext::ArcExt as _;
use transition_functions::combined::{self, PhaseError};
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    phase0::primitives::{Epoch, Slot},
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

pub struct BlockVerificationPool<P: Preset, E = Arc<Eth1ExecutionEngine<P>>, W: Wait = ()> {
    controller: Arc<Controller<P, E, W>>,
    thread_pool: ThreadPool,
    unverified_blocks: BTreeMap<Slot, Vec<Arc<SignedBeaconBlock<P>>>>,
}

impl<P, E, W> BlockVerificationPool<P, E, W>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
    W: Wait,
{
    pub fn new(controller: Arc<Controller<P, E, W>>) -> Result<Self> {
        let thread_pool = ThreadPoolBuilder::new()
            .thread_name(|index| format!("bvp-{index}"))
            .build()?;

        Ok(Self {
            controller,
            thread_pool,
            unverified_blocks: BTreeMap::new(),
        })
    }

    pub fn push(&mut self, block: Arc<SignedBeaconBlock<P>>) {
        self.unverified_blocks
            .entry(block.message().slot())
            .or_default()
            .push(block);
    }

    pub fn prune_outdated_blocks(&mut self, finalized_epoch: Epoch) {
        let slot = misc::compute_start_slot_at_epoch::<P>(finalized_epoch + 1);
        self.unverified_blocks = self.unverified_blocks.split_off(&slot);
    }

    // This has several flaws:
    // - Blocks are verified using a recent head state, which is technically incorrect.
    //   Long-lived forks may diverge to the point where their validators are different.
    //   Verification of blocks may falsely fail when that happens.
    // - This will stall if two epochs' worth of blocks are not enough to update the head and no
    //   other mechanism is used to assist syncing. This may happen if the fork choice anchor is a
    //   non-genesis block or if the chain has many consecutive empty slots.
    // - Only up to two epochs' worth of blocks can be verified before pausing to wait for the state
    //   transition, which reduces performance. It's most noticeable when the number of logical CPU
    //   cores does not divide 32.
    // The correct approach would be to verify blocks in the fork choice store, either all of them
    // with a single call to `multi_verify` or in parallel. We have tried doing so and achieved a
    // speedup in benchmarks, but it made the fork choice store significantly more complicated.
    pub fn verify_and_process_blocks(&mut self, head_state: &Arc<BeaconState<P>>) {
        let head_state_epoch = misc::compute_epoch_at_slot::<P>(head_state.slot());
        let next_state_epoch = head_state_epoch + 1;

        self.process_older_blocks(head_state_epoch);

        let head_epoch_blocks = self.take_blocks_by_epoch(head_state_epoch);
        let next_epoch_blocks = self.take_blocks_by_epoch(next_state_epoch);

        if head_epoch_blocks.is_empty() && next_epoch_blocks.is_empty() {
            return;
        }

        let mut verifiable_blocks_by_epoch = vec![(head_state.clone_arc(), head_epoch_blocks)];

        if !next_epoch_blocks.is_empty() {
            // We only need beacon committees from the next epoch to validate signatures.
            let mut state = head_state.clone_arc();

            *state.slot_mut() = misc::compute_start_slot_at_epoch::<P>(next_state_epoch);
            state.cache_mut().advance_epoch();

            verifiable_blocks_by_epoch.push((state, next_epoch_blocks));
        }

        let config = self.controller.chain_config();

        self.thread_pool.install(|| {
            verifiable_blocks_by_epoch
                .into_par_iter()
                .flat_map(|(state, blocks)| rayon::iter::repeatn(state, blocks.len()).zip(blocks))
                .for_each(|(state, block)| {
                    let verifier =
                        MultiVerifier::new([VerifierOption::SkipBlockSyncAggregateSignature]);

                    match combined::verify_signatures(config, &state, &block, verifier) {
                        Ok(()) => self.controller.on_semi_verified_block(block),
                        Err(error) if error.is::<PhaseError>() => {
                            // If phases of the block and state do not match (this can happen around
                            // a phase boundary), fall back to `Controller::on_requested_block`.
                            debug!("{error}");
                            self.controller.on_requested_block(block, None);
                        }
                        Err(error) => {
                            warn!(
                                "block signature verification failed \
                                 (block: {block:?}, error: {error:?})",
                            );
                            self.controller.on_requested_block(block, None);
                        }
                    }
                });
        });
    }

    // Send older blocks to fork choice to be verified and processed there
    fn process_older_blocks(&mut self, head_epoch: Epoch) {
        let end_slot = misc::compute_start_slot_at_epoch::<P>(head_epoch) + 1;

        for block in self.take_blocks_by_slot_range(0..end_slot) {
            self.controller.on_requested_block(block, None);
        }
    }

    fn take_blocks_by_epoch(&mut self, epoch: Epoch) -> Vec<Arc<SignedBeaconBlock<P>>> {
        let slot_range = Self::verifiable_slot_range(epoch);

        let blocks = self
            .take_blocks_by_slot_range(slot_range.clone())
            .collect_vec();

        debug!(
            "took {} unverified blocks in epoch {} (slot range: {:?})",
            blocks.len(),
            epoch,
            slot_range,
        );

        blocks
    }

    fn take_blocks_by_slot_range(
        &mut self,
        slot_range: Range<Slot>,
    ) -> impl Iterator<Item = Arc<SignedBeaconBlock<P>>> {
        let mut taken = self.unverified_blocks.split_off(&slot_range.start);

        self.unverified_blocks
            .extend(taken.split_off(&slot_range.end));

        taken.into_values().flatten()
    }

    #[allow(clippy::range_plus_one)]
    const fn verifiable_slot_range(head_epoch: Epoch) -> Range<Slot> {
        let Range { start, end } = misc::slots_in_epoch::<P>(head_epoch);
        start + 1..end + 1
    }
}
