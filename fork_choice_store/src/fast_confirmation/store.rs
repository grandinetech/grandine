//! `FastConfirmationStore` — the state store for the Fast Confirmation Rule.
//!
//! Corresponds to [`FastConfirmationStore`] from the Fast Confirmation specification.
//! Per the spec, this holds the FCR-tracked variables and has read-only access to the fork
//! choice `Store`. In this implementation the `store` reference is passed to methods instead
//! of being held as a field (a trivial rearrangement with the same semantics).
//!
//! [`FastConfirmationStore`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#fastconfirmationstore

use core::marker::PhantomData;
use std::sync::Arc;

use helper_functions::misc;
use std_ext::ArcExt as _;
use transition_functions::combined;
use types::{
    combined::BeaconState,
    phase0::{
        containers::Checkpoint,
        primitives::{Gwei, H256},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::Store;
use crate::misc::{ChainLink, Storage};

use super::rules::{
    compute_honest_ffg_support_for_current_target, find_latest_confirmed_descendant,
    get_voting_source_epoch, is_confirmed_chain_safe,
};

/// Returns the state at `checkpoint`'s first slot, computing it lazily from the block state
/// (advancing via `process_slots` if needed) when the cached entry is absent.
///
/// Mirrors the spec's `state_at_checkpoint` used by FCR. Grandine's mutator only pre-caches the
/// state for `store.unrealized_justified_checkpoint`; FCR additionally needs states for the
/// observed-justified checkpoints, which are snapshotted at the last slot of the previous epoch
/// and may diverge from the store's live `unrealized_justified_checkpoint` before rotation.
fn fcr_state_at_checkpoint<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    checkpoint: Checkpoint,
) -> Option<Arc<BeaconState<P>>> {
    if let Some(state) = store.checkpoint_state(checkpoint) {
        return Some(state.clone_arc());
    }
    let mut state = store.state_by_block_root(checkpoint.root)?;
    let target_slot = misc::compute_start_slot_at_epoch::<P>(checkpoint.epoch);
    if state.slot() >= target_slot {
        return Some(state);
    }
    combined::process_slots(
        store.chain_config(),
        store.pubkey_cache(),
        state.make_mut(),
        target_slot,
    )
    .ok()?;
    Some(state)
}

/// Returns the head state advanced via `process_slots` to the first slot of the store's
/// current epoch when the head state is behind; otherwise returns the head state unchanged.
///
/// Mirrors the spec's [`get_pulled_up_head_state`]. The spec uses this as the balance source
/// for the FFG helpers (`get_current_target_score`,
/// `compute_honest_ffg_support_for_current_target`, `will_no_conflicting_checkpoint_be_justified`,
/// `will_current_target_be_justified`).
///
/// [`get_pulled_up_head_state`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#get_pulled_up_head_state
fn get_pulled_up_head_state<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
) -> Option<Arc<BeaconState<P>>> {
    let mut state = store.head().state(store);
    let current_store_epoch = store.current_epoch();
    let head_state_epoch = misc::compute_epoch_at_slot::<P>(state.slot());
    if head_state_epoch >= current_store_epoch {
        return Some(state);
    }
    let target_slot = misc::compute_start_slot_at_epoch::<P>(current_store_epoch);
    combined::process_slots(
        store.chain_config(),
        store.pubkey_cache(),
        state.make_mut(),
        target_slot,
    )
    .ok()?;
    Some(state)
}

/// The spec's `FastConfirmationStore`, carrying all state tracked by the Fast Confirmation Rule.
///
/// Roughly corresponds to [`FastConfirmationStore`] from the Fast Confirmation specification.
///
/// [`FastConfirmationStore`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#fastconfirmationstore
#[derive(Debug, Clone)]
pub struct FastConfirmationStore<P: Preset> {
    /// Root of the most recent confirmed block.
    confirmed_root: H256,
    /// Justified checkpoint observed by all honest nodes at the start of the previous epoch,
    /// assuming synchrony.
    previous_epoch_observed_justified_checkpoint: Checkpoint,
    /// Justified checkpoint observed by all honest nodes at the start of the current epoch,
    /// assuming synchrony.
    current_epoch_observed_justified_checkpoint: Checkpoint,
    /// Greatest unrealized justified checkpoint at the start of the last slot of the previous
    /// epoch, according to the local view.
    previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    /// The head at the start of the previous slot.
    previous_slot_head: H256,
    /// The head at the start of the current slot.
    current_slot_head: H256,
    /// Implementation cache — minimum honest FFG support for the current epoch target,
    /// refreshed each slot by `on_fast_confirmation`.
    honest_ffg_support: Gwei,
    /// Implementation cache — total active balance from the current balance source,
    /// refreshed each slot by `on_fast_confirmation`.
    ffg_total_active_balance: Gwei,
    _marker: PhantomData<P>,
}

impl<P: Preset> FastConfirmationStore<P> {
    /// Constructs a new FCR store anchored at the fork choice store's finalized checkpoint.
    ///
    /// Roughly corresponds to [`get_fast_confirmation_store`] from the Fast Confirmation specification.
    ///
    /// [`get_fast_confirmation_store`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#get_fast_confirmation_store
    #[must_use]
    pub const fn new<S: Storage<P>>(store: &Store<P, S>) -> Self {
        let finalized = store.finalized_checkpoint();
        Self {
            confirmed_root: finalized.root,
            previous_epoch_observed_justified_checkpoint: finalized,
            current_epoch_observed_justified_checkpoint: finalized,
            previous_epoch_greatest_unrealized_checkpoint: finalized,
            previous_slot_head: finalized.root,
            current_slot_head: finalized.root,
            honest_ffg_support: 0,
            ffg_total_active_balance: 0,
            _marker: PhantomData,
        }
    }

    /// Per-slot FCR handler: updates tracking variables and advances `confirmed_root`.
    ///
    /// Roughly corresponds to [`on_fast_confirmation`] from the Fast Confirmation specification.
    ///
    /// [`on_fast_confirmation`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#on_fast_confirmation
    pub fn on_fast_confirmation<S: Storage<P>>(&mut self, store: &Store<P, S>) {
        self.update_variables(store);
        self.confirmed_root = self.get_latest_confirmed(store);
    }

    /// Rotates slot heads, snapshots the greatest-unrealized checkpoint at epoch end,
    /// and rotates observed justified checkpoints at epoch start.
    ///
    /// Roughly corresponds to [`update_fast_confirmation_variables`] from the Fast Confirmation specification.
    ///
    /// [`update_fast_confirmation_variables`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#update_fast_confirmation_variables
    fn update_variables<S: Storage<P>>(&mut self, store: &Store<P, S>) {
        let current_slot = store.slot();
        let current_head = store.head().block_root;

        self.previous_slot_head = self.current_slot_head;
        self.current_slot_head = current_head;

        // Last slot of epoch → snapshot greatest unrealized justified checkpoint.
        // Spec: is_start_slot_at_epoch(current_slot + 1)
        let is_last_slot_of_epoch = misc::is_epoch_start::<P>(current_slot.saturating_add(1));
        if is_last_slot_of_epoch {
            self.previous_epoch_greatest_unrealized_checkpoint =
                store.unrealized_justified_checkpoint();
        }

        // First slot of epoch → rotate observed justified checkpoints.
        // Spec: is_start_slot_at_epoch(current_slot)
        if misc::is_epoch_start::<P>(current_slot) {
            self.previous_epoch_observed_justified_checkpoint =
                self.current_epoch_observed_justified_checkpoint;
            self.current_epoch_observed_justified_checkpoint =
                self.previous_epoch_greatest_unrealized_checkpoint;
        }

        // Refresh the per-slot FFG support cache. Spec
        // `compute_honest_ffg_support_for_current_target` line 734 sources `total_active_balance`
        // and the active-validator set from `get_pulled_up_head_state(store)` — the head state
        // advanced to the start of the current store epoch via `process_slots`.
        let ffg_inputs = get_pulled_up_head_state(store).map(|arc| {
            let balances = Store::<P, S>::active_balances(&arc);
            let total: Gwei = balances.iter().sum();
            (arc, balances, total)
        });

        if let Some((_state, balances, total)) = ffg_inputs {
            self.ffg_total_active_balance = total;
            let ffg = store.fcr_build_ffg_data(self.honest_ffg_support, &balances, total);
            self.honest_ffg_support = compute_honest_ffg_support_for_current_target(&ffg);
        } else {
            self.ffg_total_active_balance = 0;
            self.honest_ffg_support = 0;
        }
    }

    /// Runs the FCR algorithm (revert → restart → advance) and returns the new confirmed root.
    ///
    /// Roughly corresponds to [`get_latest_confirmed`] from the Fast Confirmation specification.
    ///
    /// [`get_latest_confirmed`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.9/specs/phase0/fast-confirmation.md#get_latest_confirmed
    #[expect(
        clippy::too_many_lines,
        reason = "Direct translation of the five-step `get_latest_confirmed` algorithm from \
                  the spec. Splitting it would obscure the 1:1 correspondence."
    )]
    fn get_latest_confirmed<S: Storage<P>>(&self, store: &Store<P, S>) -> H256 {
        let current_epoch = store.current_epoch();
        let current_slot = store.slot();
        let head = store.head();
        let is_epoch_start = misc::is_epoch_start::<P>(current_slot);

        let confirmed_epoch = store
            .chain_link(self.confirmed_root)
            .map(|cl| misc::compute_epoch_at_slot::<P>(cl.slot()))
            .unwrap_or(0);

        // confirmed_root is canonical iff ancestor of head at that slot equals confirmed_root.
        let confirmed_slot = store
            .chain_link(self.confirmed_root)
            .map(ChainLink::slot)
            .unwrap_or(0);
        let confirmed_canonical = store
            .ancestor(head.block_root, confirmed_slot)
            .is_some_and(|a| a == self.confirmed_root);

        let mut confirmed_root = if confirmed_epoch + 1 < current_epoch || !confirmed_canonical {
            store.finalized_checkpoint().root
        } else if is_epoch_start {
            // spec: is_confirmed_chain_safe — build chain with the previous balance source.
            let safe = (|| -> Option<bool> {
                let obs_cp = self.current_epoch_observed_justified_checkpoint;
                let target_slot = misc::compute_start_slot_at_epoch::<P>(obs_cp.epoch);
                let cp_block = store.ancestor(self.confirmed_root, target_slot)?;
                if cp_block != obs_cp.root {
                    return Some(false);
                }

                let start_root_exclusive = if self.current_epoch_observed_justified_checkpoint.epoch
                    + 1
                    >= current_epoch
                {
                    self.current_epoch_observed_justified_checkpoint.root
                } else {
                    let prev_epoch = current_epoch - 1;
                    let prev_epoch_start = misc::compute_start_slot_at_epoch::<P>(prev_epoch);
                    let anc_root = store.ancestor(self.confirmed_root, prev_epoch_start)?;
                    let anc_cl = store.chain_link(anc_root)?;
                    let anc_epoch = misc::compute_epoch_at_slot::<P>(anc_cl.slot());
                    if anc_epoch + 1 == current_epoch {
                        anc_cl.block.message().parent_root()
                    } else {
                        anc_root
                    }
                };

                let prev_state = fcr_state_at_checkpoint(
                    store,
                    self.previous_epoch_observed_justified_checkpoint,
                )?;
                let prev_balances = Store::<P, S>::active_balances(&prev_state);
                let prev_total: Gwei = prev_balances.iter().sum();

                let chain = store.fcr_build_chain_info(
                    self.previous_slot_head,
                    self.confirmed_root,
                    start_root_exclusive,
                    &prev_balances,
                    prev_total,
                );
                Some(is_confirmed_chain_safe(&chain))
            })()
            .unwrap_or(false);

            if safe {
                self.confirmed_root
            } else {
                store.finalized_checkpoint().root
            }
        } else {
            self.confirmed_root
        };

        let obs = self.current_epoch_observed_justified_checkpoint;
        // Use the epoch of the block obs.root points to, not checkpoint.epoch — a checkpoint
        // may have epoch N while its block is from epoch N-1 (when the epoch-start slot was skipped).
        let obs_slot = store.chain_link(obs.root).map(ChainLink::slot).unwrap_or(0);
        let obs_block_epoch = misc::compute_epoch_at_slot::<P>(obs_slot);
        if is_epoch_start
            && obs_block_epoch + 1 == current_epoch
            && obs == head.unrealized_justified_checkpoint
        {
            let confirmed_slot = store
                .chain_link(confirmed_root)
                .map(ChainLink::slot)
                .unwrap_or(0);
            if confirmed_slot < obs_slot {
                confirmed_root = obs.root;
            }
        }

        let confirmed_epoch = store
            .chain_link(confirmed_root)
            .map(|cl| misc::compute_epoch_at_slot::<P>(cl.slot()))
            .unwrap_or(0);

        if confirmed_epoch + 1 < current_epoch {
            return confirmed_root;
        }

        // LMD-GHOST balance source — spec `get_current_balance_source` (lines 894, 920):
        // state at the current-epoch observed justified checkpoint. Used for the chain-info
        // `active_balances` / `total_active_balance` passed into `is_one_confirmed`.
        let curr_state =
            fcr_state_at_checkpoint(store, self.current_epoch_observed_justified_checkpoint);

        // FFG balance source — spec `get_pulled_up_head_state` (lines 697, 734, 779, 795):
        // head state advanced to the start of the current store epoch when behind.
        let pulled_up_head = get_pulled_up_head_state(store);

        let (chain, ffg) = match (curr_state, pulled_up_head) {
            (Some(balance_state), Some(pulled_up_state)) => {
                let balances = Store::<P, S>::active_balances(&balance_state);
                let total: Gwei = balances.iter().sum();
                let chain = store.fcr_build_chain_info(
                    self.previous_slot_head,
                    head.block_root,
                    confirmed_root,
                    &balances,
                    total,
                );
                let ffg_balances = Store::<P, S>::active_balances(&pulled_up_state);
                let ffg_total: Gwei = ffg_balances.iter().sum();
                let ffg =
                    store.fcr_build_ffg_data(self.honest_ffg_support, &ffg_balances, ffg_total);
                (chain, ffg)
            }
            _ => {
                return confirmed_root;
            }
        };

        let prev_head_voting_source_epoch = store
            .chain_link(self.previous_slot_head)
            .map(|cl| {
                get_voting_source_epoch(
                    misc::compute_epoch_at_slot::<P>(cl.slot()),
                    current_epoch,
                    cl.unrealized_justified_checkpoint.epoch,
                    cl.current_justified_checkpoint.epoch,
                )
            })
            .unwrap_or(0);
        let prev_head_unrealized_justified_epoch = store
            .chain_link(self.previous_slot_head)
            .map(|cl| cl.unrealized_justified_checkpoint.epoch)
            .unwrap_or(0);
        let head_unrealized_justified_epoch = head.unrealized_justified_checkpoint.epoch;

        find_latest_confirmed_descendant(
            &chain,
            confirmed_root,
            confirmed_epoch,
            current_epoch,
            is_epoch_start,
            &ffg,
            prev_head_voting_source_epoch,
            prev_head_unrealized_justified_epoch,
            head_unrealized_justified_epoch,
        )
    }

    /// Returns the current FCR-confirmed root.
    #[must_use]
    pub const fn confirmed_root(&self) -> H256 {
        self.confirmed_root
    }

    /// Returns `store.previous_epoch_observed_justified_checkpoint`.
    #[must_use]
    pub const fn previous_epoch_observed_justified_checkpoint(&self) -> Checkpoint {
        self.previous_epoch_observed_justified_checkpoint
    }

    /// Returns `store.current_epoch_observed_justified_checkpoint`.
    #[must_use]
    pub const fn current_epoch_observed_justified_checkpoint(&self) -> Checkpoint {
        self.current_epoch_observed_justified_checkpoint
    }

    /// Returns `store.previous_epoch_greatest_unrealized_checkpoint`.
    #[must_use]
    pub const fn previous_epoch_greatest_unrealized_checkpoint(&self) -> Checkpoint {
        self.previous_epoch_greatest_unrealized_checkpoint
    }

    /// Returns `store.previous_slot_head`.
    #[must_use]
    pub const fn previous_slot_head(&self) -> H256 {
        self.previous_slot_head
    }

    /// Returns `store.current_slot_head`.
    #[must_use]
    pub const fn current_slot_head(&self) -> H256 {
        self.current_slot_head
    }
}
