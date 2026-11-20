//! [Fast Confirmation Rule](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md)
//!
//! Functions in this module follow the specification closely.
//! Function names omit the `get_` prefix as is customary elsewhere in Grandine.
//!
//! A literal implementation of `consensus-specs` iterates over all latest messages for every block
//! it checks and recomputes committees for every range of slots. This implementation computes
//! expensive values at most once per [`FastConfirmationStore::latest_confirmed`] call and caches
//! them in a [`Context`]. Most notably, scores weighted by the justified balances are read from the
//! fork choice store, and the support of all blocks in the canonical chain under any other balances
//! is computed in a single pass over latest messages. See [`CanonicalSupport`].

use core::cell::{OnceCell, RefCell};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
    sync::Arc,
};

use anyhow::{Result, anyhow};
use arithmetic::{NonZeroExt as _, U64Ext as _};
use bitvec::vec::BitVec;
use hash_hasher::HashedMap;
use helper_functions::{accessors, misc, predicates};
use std_ext::ArcExt as _;
use typenum::Unsigned as _;
use types::{
    combined::BeaconState,
    phase0::{
        containers::Checkpoint,
        primitives::{Epoch, Gwei, H256, Slot, ValidatorIndex},
    },
    preset::Preset,
    traits::BeaconState as _,
};

use crate::{
    misc::{ChainLink, LatestMessage, PayloadPresence, Storage},
    store::Store,
};

/// Per mille value added to the estimate of the committee weight across a range of slots
/// spanning an epoch boundary that does not cover a full epoch.
const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// Debug builds and builds with the `fast-confirmation-cross-check` feature (which includes all
/// tests of `fork_choice_control`) compare attestation scores with a literal implementation of
/// [`get_attestation_score`] when there are at most this many validators.
///
/// [`get_attestation_score`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fork-choice.md#get_attestation_score
const MAX_VALIDATORS_TO_CROSS_CHECK: usize = 1 << 14;

/// [`FastConfirmationStore`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#fastconfirmationstore)
///
/// Unlike in `consensus-specs`, this does not contain the fork choice [`Store`].
/// It is stored in [`Store`] instead.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FastConfirmationStore {
    pub confirmed_root: H256,
    pub previous_epoch_observed_justified_checkpoint: Checkpoint,
    pub current_epoch_observed_justified_checkpoint: Checkpoint,
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    pub previous_slot_head: H256,
    pub current_slot_head: H256,
}

impl FastConfirmationStore {
    /// [`get_fast_confirmation_store`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_fast_confirmation_store)
    #[must_use]
    pub const fn new(finalized_checkpoint: Checkpoint) -> Self {
        Self {
            confirmed_root: finalized_checkpoint.root,
            previous_epoch_observed_justified_checkpoint: finalized_checkpoint,
            current_epoch_observed_justified_checkpoint: finalized_checkpoint,
            previous_epoch_greatest_unrealized_checkpoint: finalized_checkpoint,
            previous_slot_head: finalized_checkpoint.root,
            current_slot_head: finalized_checkpoint.root,
        }
    }

    /// [`update_fast_confirmation_variables`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#update_fast_confirmation_variables)
    pub(crate) fn update_variables<P: Preset, S: Storage<P>>(&mut self, store: &Store<P, S>) {
        let current_slot = store.slot();

        self.previous_slot_head = self.current_slot_head;
        self.current_slot_head = store.head().block_root;

        // > Update greatest unrealized justified checkpoint at the last slot of an epoch
        if misc::is_epoch_start::<P>(current_slot.saturating_add(1)) {
            self.previous_epoch_greatest_unrealized_checkpoint =
                store.unrealized_justified_checkpoint();
        }

        // > Update observed justified checkpoints at the start of an epoch
        if misc::is_epoch_start::<P>(current_slot) {
            self.previous_epoch_observed_justified_checkpoint =
                self.current_epoch_observed_justified_checkpoint;
            self.current_epoch_observed_justified_checkpoint =
                self.previous_epoch_greatest_unrealized_checkpoint;
        }
    }

    /// [`get_latest_confirmed`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_latest_confirmed)
    pub(crate) fn latest_confirmed<P: Preset, S: Storage<P>>(
        &self,
        store: &Store<P, S>,
    ) -> Result<H256> {
        let context = Context::new(store);
        let mut confirmed_root = self.confirmed_root;
        let current_epoch = store.current_epoch();
        let is_epoch_start = misc::is_epoch_start::<P>(store.slot());
        let head = context.head;

        // > Revert to finalized block if either of the following is true:
        // > 1) the latest confirmed block's epoch is older than the previous epoch,
        // > 2) the latest confirmed block does not belong to the canonical chain,
        // > 3) the confirmed chain starting from the current epoch observed justified checkpoint
        // >    cannot be re-confirmed at the start of the current epoch.
        let revert = self.is_confirmed_root_outdated(store)?
            || (is_epoch_start && !self.is_confirmed_chain_safe(&context, confirmed_root)?);

        if revert {
            confirmed_root = store.finalized_checkpoint().root;
        }

        // > Restart the confirmation chain if each of the following conditions are true:
        // > 1) it is the start of the current epoch,
        // > 2) epoch of fcr_store.current_epoch_observed_justified_checkpoint.root equals to the previous epoch,
        // > 3) fcr_store.current_epoch_observed_justified_checkpoint equals to unrealized justification of the head,
        // > 4) confirmed block is older than the block of fcr_store.current_epoch_observed_justified_checkpoint.
        //
        // The observed justified block may have been pruned if it ended up off the canonical chain.
        // The head cannot be unrealized justified by it in that case, so the restart is skipped.
        if is_epoch_start
            && let Some(observed_justified_block) =
                store.chain_link(self.current_epoch_observed_justified_checkpoint.root)
        {
            let observed_justified_block_slot = observed_justified_block.slot();

            let is_observed_justified_block_epoch_ok =
                observed_justified_block.epoch().saturating_add(1) == current_epoch;

            let is_head_unrealized_justified_ok = self.current_epoch_observed_justified_checkpoint
                == chain_link(store, head)?.unrealized_justified_checkpoint;

            let is_confirmed_block_stale =
                block_slot(store, confirmed_root)? < observed_justified_block_slot;

            if is_observed_justified_block_epoch_ok
                && is_head_unrealized_justified_ok
                && is_confirmed_block_stale
            {
                confirmed_root = self.current_epoch_observed_justified_checkpoint.root;
            }
        }

        // > Attempt to further advance the latest confirmed block
        if block_epoch(store, confirmed_root)?.saturating_add(1) >= current_epoch {
            return self.find_latest_confirmed_descendant(&context, confirmed_root);
        }

        Ok(confirmed_root)
    }

    /// Conditions 1 and 2 of the revert step in [`get_latest_confirmed`].
    /// Unlike condition 3, these are cheap enough to check in the mutator thread.
    ///
    /// [`get_latest_confirmed`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_latest_confirmed
    pub(crate) fn is_confirmed_root_outdated<P: Preset, S: Storage<P>>(
        &self,
        store: &Store<P, S>,
    ) -> Result<bool> {
        // The confirmed block may have been pruned if it ended up off the canonical chain
        // or if finality advanced past it.
        let Some(confirmed) = store.chain_link(self.confirmed_root) else {
            return Ok(true);
        };

        Ok(confirmed.epoch().saturating_add(1) < store.current_epoch()
            || !is_ancestor(store, store.head().block_root, self.confirmed_root)?)
    }

    /// [`get_restart_resilient_confirmed_root`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_restart_resilient_confirmed_root)
    ///
    /// `root_before_restart` is the result of `get_root_confirmed_before_restart`.
    pub(crate) fn restart_resilient_confirmed_root<P: Preset, S: Storage<P>>(
        &self,
        store: &Store<P, S>,
        root_before_restart: H256,
    ) -> Result<H256> {
        // The block may have been pruned or may not have been loaded from storage.
        let Some(block_before_restart) = store.chain_link(root_before_restart) else {
            return Ok(self.confirmed_root);
        };

        let root_before_restart_slot = block_before_restart.slot();

        // > Recently confirmed block has advanced beyond the block that was confirmed
        // > before the node restart
        if root_before_restart_slot <= block_slot(store, self.confirmed_root)? {
            return Ok(self.confirmed_root);
        }

        // > If the block is old enough it either has been finalized already or
        // > finality has been delayed which makes block confirmed before restart
        // > unreliable
        if block_should_be_finalized::<P>(store.slot(), root_before_restart_slot)? {
            return Ok(self.confirmed_root);
        }

        // > If a block confirmed before the restart is not canonical,
        // > return the recently confirmed block
        if !is_ancestor(store, store.head().block_root, root_before_restart)? {
            return Ok(self.confirmed_root);
        }

        Ok(root_before_restart)
    }

    /// [`find_latest_confirmed_descendant`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#find_latest_confirmed_descendant)
    fn find_latest_confirmed_descendant<P: Preset, S: Storage<P>>(
        &self,
        context: &Context<P, S>,
        latest_confirmed_root: H256,
    ) -> Result<H256> {
        let store = context.store;
        let head = context.head;
        let current_epoch = store.current_epoch();
        let is_epoch_start = misc::is_epoch_start::<P>(store.slot());
        let balance_source =
            context.balance_source(self.current_epoch_observed_justified_checkpoint)?;
        let head_unrealized_justified_epoch = chain_link(store, head)?
            .unrealized_justified_checkpoint
            .epoch;

        let mut confirmed_root = latest_confirmed_root;

        // `will_no_conflicting_checkpoint_be_justified` is expensive,
        // so it is evaluated lazily like in the `and` and `or` expressions in `consensus-specs`.
        let previous_epoch_condition = || -> Result<bool> {
            // The previous head may have been pruned if it ended up off the canonical chain.
            // None of the blocks it could have confirmed can be canonical in that case.
            let Some(previous_slot_head) = store.chain_link(self.previous_slot_head) else {
                return Ok(false);
            };

            let previous_slot_head_unrealized_justified_epoch =
                previous_slot_head.unrealized_justified_checkpoint.epoch;

            Ok(
                block_epoch(store, confirmed_root)?.saturating_add(1) == current_epoch
                    && store
                        .voting_source(previous_slot_head)
                        .epoch
                        .saturating_add(2)
                        >= current_epoch
                    && (is_epoch_start
                        || (context.will_no_conflicting_checkpoint_be_justified()?
                            && (previous_slot_head_unrealized_justified_epoch.saturating_add(1)
                                >= current_epoch
                                || head_unrealized_justified_epoch.saturating_add(1)
                                    >= current_epoch))),
            )
        };

        if previous_epoch_condition()? {
            // > Get suffix of the canonical chain
            // > Starting with the child of the latest_confirmed_root
            // > move towards the head in attempt to advance the confirmed block
            // > and stop when the first unconfirmed descendant is encountered
            for block_root in ancestor_roots(store, head, confirmed_root)? {
                // > If the current epoch is reached, exit the loop
                // > as this code is meant to confirm blocks from the previous epoch
                if block_epoch(store, block_root)? == current_epoch {
                    break;
                }

                // > The algorithm can only rely on the previous head
                // > if it is a descendant of the block that is attempted to be confirmed
                if !is_ancestor(store, self.previous_slot_head, block_root)? {
                    break;
                }

                if !context.is_one_confirmed(&balance_source, block_root)? {
                    break;
                }

                confirmed_root = block_root;
            }
        }

        if is_epoch_start || head_unrealized_justified_epoch.saturating_add(1) >= current_epoch {
            let mut tentative_confirmed_root = confirmed_root;

            for block_root in ancestor_roots(store, head, confirmed_root)? {
                // > The following condition can only be true the first time
                // > the algorithm advances to a block from the current epoch
                if block_epoch(store, block_root)? > block_epoch(store, tentative_confirmed_root)? {
                    // > To confirm blocks from the current epoch ensure that
                    // > current epoch target will be justified
                    if !context.will_current_target_be_justified()? {
                        break;
                    }
                }

                if !context.is_one_confirmed(&balance_source, block_root)? {
                    break;
                }

                tentative_confirmed_root = block_root;
            }

            // > The tentative_confirmed_root can only be confirmed
            // > if it is for sure not going to be reorged out in either the current or next epoch.
            if block_epoch(store, tentative_confirmed_root)? == current_epoch
                || (store
                    .voting_source(chain_link(store, tentative_confirmed_root)?)
                    .epoch
                    .saturating_add(2)
                    >= current_epoch
                    && (is_epoch_start || context.will_no_conflicting_checkpoint_be_justified()?))
            {
                confirmed_root = tentative_confirmed_root;
            }
        }

        Ok(confirmed_root)
    }

    /// [`is_confirmed_chain_safe`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#is_confirmed_chain_safe)
    fn is_confirmed_chain_safe<P: Preset, S: Storage<P>>(
        &self,
        context: &Context<P, S>,
        confirmed_root: H256,
    ) -> Result<bool> {
        let store = context.store;
        let observed_justified = self.current_epoch_observed_justified_checkpoint;

        // > Check if the confirmed_root has current_epoch_observed_justified_checkpoint in its chain
        if observed_justified
            != checkpoint_for_block(store, confirmed_root, observed_justified.epoch)?
        {
            return Ok(false);
        }

        let current_epoch = store.current_epoch();

        let start_root_exclusive = if observed_justified.epoch.saturating_add(1) >= current_epoch {
            // > Exclude the justified checkpoint block if it is from the previous epoch
            // > as then this block will always be canonical in this case.
            observed_justified.root
        } else {
            // > Limit reconfirmation to the first block of the previous epoch
            // > as if it is successful, reconfirmation of the ancestors is implied.
            let ancestor_at_previous_epoch_start = ancestor(
                store,
                confirmed_root,
                misc::compute_start_slot_at_epoch::<P>(misc::previous_epoch(current_epoch)),
            )?;

            if block_epoch(store, ancestor_at_previous_epoch_start)?.saturating_add(1)
                == current_epoch
            {
                // > The parent of the first block of the previous epoch
                chain_link(store, ancestor_at_previous_epoch_start)?.parent_root()
            } else {
                // > The last block of the epoch before the previous one
                ancestor_at_previous_epoch_start
            }
        };

        // > Run is_one_confirmed for each block in the confirmed chain with the previous epoch balance source
        let chain_roots = ancestor_roots(store, confirmed_root, start_root_exclusive)?;

        if chain_roots.is_empty() {
            return Ok(true);
        }

        let balance_source =
            context.balance_source(self.previous_epoch_observed_justified_checkpoint)?;

        for root in chain_roots {
            if !context.is_one_confirmed(&balance_source, root)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Values computed lazily and at most once during a single
/// [`FastConfirmationStore::latest_confirmed`] call.
///
/// The fork choice store does not change during the call, so none of them need to be invalidated.
struct Context<'store, P: Preset, S: Storage<P>> {
    store: &'store Store<P, S>,
    head: H256,
    // `None` if there are no equivocating validators.
    equivocators: Option<BitVec>,
    balance_sources: RefCell<HashMap<Checkpoint, Rc<BalanceSource<P>>>>,
    shuffling_sources: RefCell<HashMap<Epoch, Arc<BeaconState<P>>>>,
    equivocator_slots: RefCell<HashMap<Epoch, Rc<HashMap<ValidatorIndex, Slot>>>>,
    pulled_up_head_state: OnceCell<Rc<BalanceSource<P>>>,
    honest_ffg_support: OnceCell<Gwei>,
}

impl<'store, P: Preset, S: Storage<P>> Context<'store, P, S> {
    fn new(store: &'store Store<P, S>) -> Self {
        let equivocators = (!store.equivocating_indices().is_empty()).then(|| {
            let validator_count = store.latest_messages().len();
            let mut bits = BitVec::repeat(false, validator_count);

            for validator_index in store.equivocating_indices() {
                if let Ok(index) = usize::try_from(*validator_index)
                    && index < validator_count
                {
                    bits.set(index, true);
                }
            }

            bits
        });

        Self {
            store,
            head: store.head().block_root,
            equivocators,
            balance_sources: RefCell::default(),
            shuffling_sources: RefCell::default(),
            equivocator_slots: RefCell::default(),
            pulled_up_head_state: OnceCell::new(),
            honest_ffg_support: OnceCell::new(),
        }
    }

    fn is_equivocating(&self, validator_index: ValidatorIndex) -> bool {
        // Validators added after the latest messages were last extended cannot have equivocated.
        self.equivocators.as_ref().is_some_and(|equivocators| {
            usize::try_from(validator_index)
                .ok()
                .and_then(|index| equivocators.get(index))
                .is_some_and(|bit| *bit)
        })
    }

    /// Latest messages of validators that have not equivocated.
    fn latest_messages(&self) -> impl Iterator<Item = (ValidatorIndex, &LatestMessage)> {
        (0..)
            .zip(self.store.latest_messages())
            .filter_map(|(validator_index, latest_message)| {
                let latest_message = latest_message.as_deref()?;
                (!self.is_equivocating(validator_index))
                    .then_some((validator_index, latest_message))
            })
    }

    fn is_canonical(&self, block_root: H256) -> Result<bool> {
        is_ancestor(self.store, self.head, block_root)
    }

    /// [`get_previous_balance_source`] and [`get_current_balance_source`].
    ///
    /// [`get_previous_balance_source`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_previous_balance_source
    /// [`get_current_balance_source`]:  https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_current_balance_source
    fn balance_source(&self, checkpoint: Checkpoint) -> Result<Rc<BalanceSource<P>>> {
        if let Some(balance_source) = self.balance_sources.borrow().get(&checkpoint) {
            return Ok(Rc::clone(balance_source));
        }

        let state = checkpoint_state(self.store, checkpoint)?;

        // The observed justified checkpoint is usually the justified checkpoint.
        // Its balances are already cached in the fork choice store.
        let active_balances = if checkpoint == self.store.justified_checkpoint() {
            self.store.justified_active_balances().clone_arc()
        } else {
            Store::<P, S>::active_balances(&state)
        };

        let balance_source = Rc::new(BalanceSource::new(state, active_balances));

        self.balance_sources
            .borrow_mut()
            .insert(checkpoint, Rc::clone(&balance_source));

        Ok(balance_source)
    }

    /// [`get_pulled_up_head_state`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_pulled_up_head_state)
    fn pulled_up_head_state(&self) -> Result<Rc<BalanceSource<P>>> {
        if let Some(balance_source) = self.pulled_up_head_state.get() {
            return Ok(Rc::clone(balance_source));
        }

        let store = self.store;
        let head = chain_link(store, self.head)?;
        let head_state = head.state(store);
        let current_epoch = store.current_epoch();

        let state = if accessors::get_current_epoch(&head_state) < current_epoch {
            state_at_slot(
                store,
                self.head,
                misc::compute_start_slot_at_epoch::<P>(current_epoch),
            )?
        } else {
            head_state
        };

        let active_balances = Store::<P, S>::active_balances(&state);
        let balance_source = Rc::new(BalanceSource::new(state, active_balances));

        Ok(Rc::clone(
            self.pulled_up_head_state.get_or_init(|| balance_source),
        ))
    }

    /// [`get_slot_committee`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_slot_committee)
    ///
    /// `consensus-specs` uses the head state as the shuffling source for all slots.
    /// The head state can only be used to compute committees for epochs adjacent to its own.
    /// Committees for other epochs are computed using the state of the canonical chain at the
    /// start of the epoch. The result is the same because shufflings are determined by the chain.
    fn slot_committee(&self, slot: Slot) -> Result<Vec<ValidatorIndex>> {
        let shuffling_source = self.shuffling_source(misc::compute_epoch_at_slot::<P>(slot))?;

        let participants = accessors::beacon_committees(&shuffling_source, slot)?
            .flatten()
            .collect();

        Ok(participants)
    }

    fn shuffling_source(&self, epoch: Epoch) -> Result<Arc<BeaconState<P>>> {
        if let Some(state) = self.shuffling_sources.borrow().get(&epoch) {
            return Ok(state.clone_arc());
        }

        let store = self.store;
        let head_state = chain_link(store, self.head)?.state(store);

        let state = if accessors::relative_epoch(&head_state, epoch).is_ok() {
            head_state
        } else {
            let epoch_start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);
            let root = ancestor(store, self.head, epoch_start_slot)?;
            state_at_slot(store, root, epoch_start_slot)?
        };

        self.shuffling_sources
            .borrow_mut()
            .insert(epoch, state.clone_arc());

        Ok(state)
    }

    fn participants_between_slots(
        &self,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<HashSet<ValidatorIndex>> {
        let mut participants = HashSet::new();

        for slot in start_slot..=end_slot {
            participants.extend(self.slot_committee(slot)?);
        }

        Ok(participants)
    }

    /// Slots that equivocating validators are assigned to in `epoch`.
    fn equivocator_slots(&self, epoch: Epoch) -> Result<Rc<HashMap<ValidatorIndex, Slot>>> {
        if let Some(slots) = self.equivocator_slots.borrow().get(&epoch) {
            return Ok(Rc::clone(slots));
        }

        let mut slots = HashMap::new();
        let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);
        let end_slot = start_slot.try_add(P::SlotsPerEpoch::U64)?;

        for slot in start_slot..end_slot {
            for validator_index in self.slot_committee(slot)? {
                if self.is_equivocating(validator_index) {
                    slots.insert(validator_index, slot);
                }
            }
        }

        let slots = Rc::new(slots);

        self.equivocator_slots
            .borrow_mut()
            .insert(epoch, Rc::clone(&slots));

        Ok(slots)
    }

    // LMD-GHOST helpers

    /// [`get_attestation_score`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fork-choice.md#get_attestation_score)
    ///
    /// Proposer boost is not included.
    fn attestation_score(
        &self,
        balance_source: &BalanceSource<P>,
        block_root: H256,
    ) -> Result<Gwei> {
        let store = self.store;

        // The fork choice store keeps scores weighted by the justified balances up to date.
        // Finalized blocks other than the last one do not have scores.
        let stored_score = balance_source
            .has_justified_balances(store)
            .then(|| store.stored_attestation_score(block_root))
            .flatten()
            .map(|(_, score)| score);

        let attestation_score = if let Some(stored_score) = stored_score {
            stored_score
        } else {
            // The Fast Confirmation Rule only checks blocks in the canonical chain.
            // This is a fallback in case that ever changes.
            if !self.is_canonical(block_root)? {
                return self.attestation_score_by_iteration(balance_source, block_root);
            }

            balance_source
                .canonical_support(self)?
                .support_at(block_slot(store, block_root)?)
        };

        if cfg!(any(
            debug_assertions,
            feature = "fast-confirmation-cross-check",
        )) && store.latest_messages().len() <= MAX_VALIDATORS_TO_CROSS_CHECK
        {
            assert_eq!(
                attestation_score,
                self.attestation_score_by_iteration(balance_source, block_root)?,
                "attestation score should match iterative computation \
                 (block_root: {block_root:?})",
            );
        }

        Ok(attestation_score)
    }

    /// Literal implementation of [`get_attestation_score`].
    ///
    /// [`get_attestation_score`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fork-choice.md#get_attestation_score
    fn attestation_score_by_iteration(
        &self,
        balance_source: &BalanceSource<P>,
        block_root: H256,
    ) -> Result<Gwei> {
        let store = self.store;
        let slot = block_slot(store, block_root)?;
        let mut descends_from_block = HashedMap::default();
        let mut support: Gwei = 0;

        for (validator_index, latest_message) in self.latest_messages() {
            let vote_root = latest_message.root;

            let supports_block = match descends_from_block.get(&vote_root) {
                Some(supports_block) => *supports_block,
                None => {
                    // Blocks missing from the store were pruned and cannot descend from `block_root`.
                    let supports_block = store.chain_link(vote_root).is_some()
                        && ancestor(store, vote_root, slot)? == block_root;

                    descends_from_block.insert(vote_root, supports_block);
                    supports_block
                }
            };

            if supports_block {
                support = support.try_add(balance_source.balance(validator_index))?;
            }
        }

        Ok(support)
    }

    /// [`get_node_support_between_slots`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_node_support_between_slots)
    ///
    /// `node_payload_status` is only compared after Gloas.
    fn node_support_between_slots(
        &self,
        balance_source: &BalanceSource<P>,
        node_root: H256,
        node_payload_status: Option<PayloadPresence>,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Gwei> {
        let participants = self.participants_between_slots(start_slot, end_slot)?;
        let latest_messages = self.store.latest_messages();
        let mut support: Gwei = 0;

        for validator_index in participants {
            let Some(Some(latest_message)) = latest_messages.get(usize::try_from(validator_index)?)
            else {
                continue;
            };

            if latest_message.root != node_root || self.is_equivocating(validator_index) {
                continue;
            }

            if let Some(node_payload_status) = node_payload_status
                && supported_payload_status(self.store, latest_message)? != node_payload_status
            {
                continue;
            }

            support = support.try_add(balance_source.balance(validator_index))?;
        }

        Ok(support)
    }

    /// [`get_equivocation_score`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_equivocation_score)
    fn equivocation_score(
        &self,
        balance_source: &BalanceSource<P>,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Gwei> {
        if self.equivocators.is_none() || start_slot > end_slot {
            return Ok(0);
        }

        let start_epoch = misc::compute_epoch_at_slot::<P>(start_slot);
        let end_epoch = misc::compute_epoch_at_slot::<P>(end_slot);
        let slot_range = start_slot..=end_slot;

        // A validator may be assigned to slots in multiple epochs, but it is only counted once.
        let mut committee_equivocators = HashSet::new();

        for epoch in start_epoch..=end_epoch {
            committee_equivocators.extend(
                self.equivocator_slots(epoch)?
                    .iter()
                    .filter(|(_, slot)| slot_range.contains(slot))
                    .map(|(validator_index, _)| *validator_index),
            );
        }

        let state = &balance_source.state;
        let epoch = accessors::get_current_epoch(state);
        let validators = state.validators();
        let mut equivocating_balance: Gwei = 0;

        for validator_index in committee_equivocators {
            let Ok(validator) = validators.partial_validator(validator_index) else {
                continue;
            };

            // Slashed validators are deliberately not excluded. See `consensus-specs`.
            if predicates::is_active_validator(validator, epoch) {
                equivocating_balance =
                    equivocating_balance.try_add(validators.effective_balance(validator_index)?)?;
            }
        }

        Ok(equivocating_balance)
    }

    /// [`compute_adversarial_weight`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#compute_adversarial_weight)
    fn compute_adversarial_weight(
        &self,
        balance_source: &BalanceSource<P>,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Gwei> {
        let maximum_weight = estimate_committee_weight_between_slots::<P>(
            balance_source.total_active_balance(),
            start_slot,
            end_slot,
        )?;

        let max_adversarial_weight = (maximum_weight / 100)
            .try_mul(self.store.chain_config().confirmation_byzantine_threshold)?;

        // > Discount total weight of equivocating validators
        let equivocation_score = self.equivocation_score(balance_source, start_slot, end_slot)?;

        Ok(max_adversarial_weight.saturating_sub(equivocation_score))
    }

    /// [`get_adversarial_weight`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_adversarial_weight)
    fn adversarial_weight(
        &self,
        balance_source: &BalanceSource<P>,
        block_root: H256,
    ) -> Result<Gwei> {
        let store = self.store;
        let block = chain_link(store, block_root)?;
        let parent_epoch = block_epoch(store, block.parent_root())?;
        let end_slot = store.slot().saturating_sub(1);

        let start_slot = if block.epoch() > parent_epoch {
            // > Use the first epoch slot as the start slot when crossing epoch boundary
            misc::compute_start_slot_at_epoch::<P>(block.epoch())
        } else {
            block.slot()
        };

        self.compute_adversarial_weight(balance_source, start_slot, end_slot)
    }

    /// [`compute_empty_slot_support_discount`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#compute_empty_slot_support_discount)
    fn compute_empty_slot_support_discount(
        &self,
        balance_source: &BalanceSource<P>,
        block_root: H256,
    ) -> Result<Gwei> {
        let block = chain_link(self.store, block_root)?;
        let first_empty_slot = block_slot(self.store, block.parent_root())?.try_add(1)?;

        // > No empty slot
        if first_empty_slot == block.slot() {
            return Ok(0);
        }

        // The block is later than its parent, so this cannot underflow.
        let last_empty_slot = block.slot().try_sub(1)?;

        // > Discount votes supporting the parent block if they are from the committees of empty slots
        let parent_payload_status = block
            .is_post_gloas()
            .then_some(block.parent_payload_presence);

        let parent_support_in_empty_slots = self.node_support_between_slots(
            balance_source,
            block.parent_root(),
            parent_payload_status,
            first_empty_slot,
            last_empty_slot,
        )?;

        // > Adversarial weight is not discounted
        let adversarial_weight =
            self.compute_adversarial_weight(balance_source, first_empty_slot, last_empty_slot)?;

        Ok(parent_support_in_empty_slots.saturating_sub(adversarial_weight))
    }

    /// [`compute_safety_threshold`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#compute_safety_threshold)
    fn compute_safety_threshold(
        &self,
        balance_source: &BalanceSource<P>,
        block_root: H256,
    ) -> Result<Gwei> {
        let store = self.store;
        let block = chain_link(store, block_root)?;
        let parent_slot = block_slot(store, block.parent_root())?;
        let proposer_score = balance_source.proposer_score(store);

        let maximum_support = estimate_committee_weight_between_slots::<P>(
            balance_source.total_active_balance(),
            parent_slot.try_add(1)?,
            store.slot().saturating_sub(1),
        )?;

        let support_discount =
            self.compute_empty_slot_support_discount(balance_source, block_root)?;
        let adversarial_weight = self.adversarial_weight(balance_source, block_root)?;

        // > Return (maximum_support + proposer_score - support_discount) // 2 + adversarial_weight
        // > with an underflow guard
        let total = maximum_support
            .try_add(proposer_score)?
            .try_add(adversarial_weight.try_mul(2)?)?;

        Ok(total.saturating_sub(support_discount) / 2)
    }

    /// [`is_one_confirmed`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#is_one_confirmed)
    fn is_one_confirmed(
        &self,
        balance_source: &BalanceSource<P>,
        block_root: H256,
    ) -> Result<bool> {
        // > This function **MUST** return `False` if `block_root` status is **not** `VALID`
        if !chain_link(self.store, block_root)?.is_valid() {
            return Ok(false);
        }

        let support = self.attestation_score(balance_source, block_root)?;
        let safety_threshold = self.compute_safety_threshold(balance_source, block_root)?;

        Ok(support > safety_threshold)
    }

    // FFG helpers

    /// [`get_current_target_score`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_current_target_score)
    fn current_target_score(&self, state: &BalanceSource<P>) -> Result<Gwei> {
        let store = self.store;
        let target = current_target(store, self.head)?;
        let mut supports_target_by_root = HashedMap::default();
        let mut target_support: Gwei = 0;

        for (validator_index, latest_message) in self.latest_messages() {
            // Messages from other epochs have checkpoints with other epochs.
            if misc::compute_epoch_at_slot::<P>(latest_message.slot) != target.epoch {
                continue;
            }

            let vote_root = latest_message.root;

            let supports_target = match supports_target_by_root.get(&vote_root) {
                Some(supports_target) => *supports_target,
                None => {
                    let supports_target = store.chain_link(vote_root).is_some()
                        && checkpoint_for_block(store, vote_root, target.epoch)? == target;

                    supports_target_by_root.insert(vote_root, supports_target);
                    supports_target
                }
            };

            if supports_target {
                target_support = target_support.try_add(state.balance(validator_index))?;
            }
        }

        Ok(target_support)
    }

    /// [`compute_honest_ffg_support_for_current_target`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#compute_honest_ffg_support_for_current_target)
    fn compute_honest_ffg_support_for_current_target(&self) -> Result<Gwei> {
        if let Some(honest_ffg_support) = self.honest_ffg_support.get() {
            return Ok(*honest_ffg_support);
        }

        let store = self.store;
        let previous_slot = store.slot().saturating_sub(1);
        let current_epoch_start_slot =
            misc::compute_start_slot_at_epoch::<P>(store.current_epoch());
        let balance_source = self.pulled_up_head_state()?;
        let total_active_balance = balance_source.total_active_balance();
        let threshold = store.chain_config().confirmation_byzantine_threshold;

        // > Compute FFG support for the target
        let ffg_support_for_checkpoint = self.current_target_score(&balance_source)?;

        // > Compute the total FFG weight up to, but excluding, the current slot
        let ffg_weight_till_now = estimate_committee_weight_between_slots::<P>(
            total_active_balance,
            current_epoch_start_slot,
            previous_slot,
        )?;

        // > Compute remaining honest FFG weight
        let remaining_ffg_weight = total_active_balance.try_sub(ffg_weight_till_now)?;
        let remaining_honest_ffg_weight =
            (remaining_ffg_weight / 100).try_mul(100_u64.try_sub(threshold)?)?;

        // > Compute potential adversarial weight
        let adversarial_weight = self.compute_adversarial_weight(
            &balance_source,
            current_epoch_start_slot,
            previous_slot,
        )?;

        // > Compute min honest FFG support
        let min_honest_ffg_support = ffg_support_for_checkpoint.saturating_sub(adversarial_weight);
        let honest_ffg_support = min_honest_ffg_support.try_add(remaining_honest_ffg_weight)?;

        Ok(*self.honest_ffg_support.get_or_init(|| honest_ffg_support))
    }

    /// [`will_no_conflicting_checkpoint_be_justified`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#will_no_conflicting_checkpoint_be_justified)
    fn will_no_conflicting_checkpoint_be_justified(&self) -> Result<bool> {
        // > If the target is unrealized justified then no conflicting checkpoint can be justified
        if current_target(self.store, self.head)? == self.store.unrealized_justified_checkpoint() {
            return Ok(true);
        }

        let total_active_balance = self.pulled_up_head_state()?.total_active_balance();
        let honest_ffg_support = self.compute_honest_ffg_support_for_current_target()?;

        Ok(honest_ffg_support.try_mul(3)? > total_active_balance)
    }

    /// [`will_current_target_be_justified`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#will_current_target_be_justified)
    fn will_current_target_be_justified(&self) -> Result<bool> {
        let total_active_balance = self.pulled_up_head_state()?.total_active_balance();
        let honest_ffg_support = self.compute_honest_ffg_support_for_current_target()?;

        Ok(honest_ffg_support.try_mul(3)? >= total_active_balance.try_mul(2)?)
    }
}

/// A state whose validator balances are used to weigh votes.
struct BalanceSource<P: Preset> {
    state: Arc<BeaconState<P>>,
    // Effective balances of validators that are active and unslashed in `state`.
    // Other validators have a balance of 0.
    active_balances: Arc<[Gwei]>,
    proposer_score: OnceCell<Gwei>,
    canonical_support: OnceCell<CanonicalSupport>,
}

impl<P: Preset> BalanceSource<P> {
    const fn new(state: Arc<BeaconState<P>>, active_balances: Arc<[Gwei]>) -> Self {
        Self {
            state,
            active_balances,
            proposer_score: OnceCell::new(),
            canonical_support: OnceCell::new(),
        }
    }

    /// Returns the balance of a validator if it is active and unslashed.
    ///
    /// Validators missing from the state are treated as inactive.
    fn balance(&self, validator_index: ValidatorIndex) -> Gwei {
        usize::try_from(validator_index)
            .ok()
            .and_then(|index| self.active_balances.get(index))
            .copied()
            .unwrap_or_default()
    }

    /// [`get_total_active_balance`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/beacon-chain.md#get_total_active_balance)
    ///
    /// Unlike the balances in [`BalanceSource::balance`], this includes slashed validators.
    fn total_active_balance(&self) -> Gwei {
        accessors::total_active_balance(&self.state)
    }

    /// [`compute_proposer_score`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fork-choice.md#compute_proposer_score)
    fn proposer_score<S: Storage<P>>(&self, store: &Store<P, S>) -> Gwei {
        *self.proposer_score.get_or_init(|| {
            if self.has_justified_balances(store) {
                store.timely_proposer_score()
            } else {
                Store::<P, S>::committee_fraction(
                    self.active_balances.iter().sum(),
                    store.chain_config().proposer_score_boost,
                )
            }
        })
    }

    /// Returns whether this source weighs votes the same way as scores in the fork choice store.
    fn has_justified_balances<S: Storage<P>>(&self, store: &Store<P, S>) -> bool {
        Arc::ptr_eq(&self.active_balances, store.justified_active_balances())
    }

    fn canonical_support<S: Storage<P>>(
        &self,
        context: &Context<P, S>,
    ) -> Result<&CanonicalSupport> {
        if let Some(canonical_support) = self.canonical_support.get() {
            return Ok(canonical_support);
        }

        let canonical_support = CanonicalSupport::new(context, self)?;

        Ok(self.canonical_support.get_or_init(|| canonical_support))
    }
}

/// Support of all blocks in the canonical chain, weighed by a single [`BalanceSource`].
///
/// Used for balance sources and blocks that have no score in the fork choice store.
///
/// A vote for a block supports all of its ancestors.
/// The canonical ancestors of a vote are exactly the canonical blocks at or before the slot of
/// its latest canonical ancestor (the block where its chain branches off the canonical chain).
/// Because of that, the support of a canonical block is the sum of the weights of all votes whose
/// latest canonical ancestor is at or after the slot of the block.
struct CanonicalSupport {
    // Slots of latest canonical ancestors of votes in descending order,
    // each paired with the total weight of votes whose latest canonical ancestor is at that slot
    // or later.
    cumulative_weights: Vec<(Slot, Gwei)>,
}

impl CanonicalSupport {
    fn new<P: Preset, S: Storage<P>>(
        context: &Context<P, S>,
        balance_source: &BalanceSource<P>,
    ) -> Result<Self> {
        let store = context.store;
        let mut weights_by_root = HashedMap::<H256, Gwei>::default();

        for (validator_index, latest_message) in context.latest_messages() {
            let balance = balance_source.balance(validator_index);

            if balance == 0 {
                continue;
            }

            let weight = weights_by_root.entry(latest_message.root).or_default();
            *weight = weight.try_add(balance)?;
        }

        let mut weights_by_slot = BTreeMap::<Slot, Gwei>::new();

        for (root, weight) in weights_by_root {
            // Blocks missing from the store were pruned and cannot descend from canonical blocks.
            let Some(chain_link) = store.chain_link(root) else {
                continue;
            };

            let latest_canonical_ancestor = if context.is_canonical(root)? {
                chain_link
            } else if let Some(common_ancestor) = store.common_ancestor(root, context.head) {
                common_ancestor
            } else {
                continue;
            };

            let total = weights_by_slot
                .entry(latest_canonical_ancestor.slot())
                .or_default();

            *total = total.try_add(weight)?;
        }

        let mut cumulative_weight: Gwei = 0;

        let cumulative_weights = weights_by_slot
            .into_iter()
            .rev()
            .map(|(slot, weight)| {
                cumulative_weight = cumulative_weight.try_add(weight)?;
                Ok((slot, cumulative_weight))
            })
            .collect::<Result<_>>()?;

        Ok(Self { cumulative_weights })
    }

    /// Returns the support of the canonical block at `slot`.
    fn support_at(&self, slot: Slot) -> Gwei {
        let count = self
            .cumulative_weights
            .partition_point(|(ancestor_slot, _)| *ancestor_slot >= slot);

        count
            .checked_sub(1)
            .and_then(|index| self.cumulative_weights.get(index))
            .map(|(_, cumulative_weight)| *cumulative_weight)
            .unwrap_or_default()
    }
}

// Misc helpers

fn chain_link<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    block_root: H256,
) -> Result<&ChainLink<P>> {
    store
        .chain_link(block_root)
        .ok_or_else(|| anyhow!("block not found in fork choice store: {block_root:?}"))
}

fn block_slot<P: Preset, S: Storage<P>>(store: &Store<P, S>, block_root: H256) -> Result<Slot> {
    chain_link(store, block_root).map(ChainLink::slot)
}

fn block_epoch<P: Preset, S: Storage<P>>(store: &Store<P, S>, block_root: H256) -> Result<Epoch> {
    chain_link(store, block_root).map(ChainLink::epoch)
}

/// [`get_ancestor`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fork-choice.md#get_ancestor)
///
/// Only returns the root of the ancestor.
/// Payload statuses of ancestors are only needed in
/// [`Context::compute_empty_slot_support_discount`], which obtains it directly from the child.
fn ancestor<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    block_root: H256,
    slot: Slot,
) -> Result<H256> {
    // `Store::ancestor` may return a later finalized block if `block_root` is finalized.
    if block_slot(store, block_root)? <= slot {
        return Ok(block_root);
    }

    store
        .ancestor(block_root, slot)
        .ok_or_else(|| anyhow!("ancestor of {block_root:?} at slot {slot} not found"))
}

/// [`is_ancestor`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fork-choice.md#is_ancestor)
///
/// All nodes passed to `is_ancestor` by the Fast Confirmation Rule have
/// `payload_status == PAYLOAD_STATUS_PENDING`, so only roots need to be compared.
fn is_ancestor<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    descendant_root: H256,
    ancestor_root: H256,
) -> Result<bool> {
    Ok(ancestor(store, descendant_root, block_slot(store, ancestor_root)?)? == ancestor_root)
}

/// [`get_checkpoint_for_block`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_checkpoint_for_block)
fn checkpoint_for_block<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    block_root: H256,
    epoch: Epoch,
) -> Result<Checkpoint> {
    let root = ancestor(
        store,
        block_root,
        misc::compute_start_slot_at_epoch::<P>(epoch),
    )?;
    Ok(Checkpoint { epoch, root })
}

/// [`get_current_target`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_current_target)
fn current_target<P: Preset, S: Storage<P>>(store: &Store<P, S>, head: H256) -> Result<Checkpoint> {
    checkpoint_for_block(store, head, store.current_epoch())
}

/// [`get_ancestor_roots`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_ancestor_roots)
fn ancestor_roots<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    block_root: H256,
    terminal_root: H256,
) -> Result<Vec<H256>> {
    let terminal_slot = block_slot(store, terminal_root)?;
    let mut roots = vec![];

    for chain_link in store.chain_ending_with(block_root) {
        if chain_link.slot() <= terminal_slot {
            break;
        }

        roots.push(chain_link.block_root);

        // > Return when terminal_root is reached
        if chain_link.parent_root() == terminal_root {
            roots.reverse();
            return Ok(roots);
        }
    }

    // > Return empty list if terminal_root is not in the chain of block_root
    Ok(vec![])
}

/// `block_should_be_finalized` from [`get_restart_resilient_confirmed_root`].
///
/// [`get_restart_resilient_confirmed_root`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#get_restart_resilient_confirmed_root
fn block_should_be_finalized<P: Preset>(current_slot: Slot, block_slot: Slot) -> Result<bool> {
    let last_slot_of_block_epoch = block_slot.try_add(P::SlotsPerEpoch::U64)?.try_sub(1)?;
    let next_checkpoint_epoch = misc::compute_epoch_at_slot::<P>(last_slot_of_block_epoch);
    let earliest_finality_slot =
        misc::compute_start_slot_at_epoch::<P>(next_checkpoint_epoch.try_add(2)?);

    Ok(earliest_finality_slot <= current_slot)
}

/// The payload status of the node returned by [`get_supported_node`] after Gloas.
///
/// [`get_supported_node`]: https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/gloas/fork-choice.md#new-get_supported_node
fn supported_payload_status<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    latest_message: &LatestMessage,
) -> Result<PayloadPresence> {
    if block_slot(store, latest_message.root)? < latest_message.slot {
        if latest_message.payload_present {
            return Ok(PayloadPresence::Full);
        }

        return Ok(PayloadPresence::Empty);
    }

    Ok(PayloadPresence::Pending)
}

// State helpers

fn checkpoint_state<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    checkpoint: Checkpoint,
) -> Result<Arc<BeaconState<P>>> {
    if let Some(state) = store.checkpoint_state(checkpoint) {
        return Ok(state.clone_arc());
    }

    state_at_slot(
        store,
        checkpoint.root,
        misc::compute_start_slot_at_epoch::<P>(checkpoint.epoch),
    )
}

fn state_at_slot<P: Preset, S: Storage<P>>(
    store: &Store<P, S>,
    block_root: H256,
    slot: Slot,
) -> Result<Arc<BeaconState<P>>> {
    if block_slot(store, block_root)? == slot {
        return Ok(chain_link(store, block_root)?.state(store));
    }

    store
        .state_cache()
        .state_at_slot(store.pubkey_cache(), store, block_root, slot)
}

// Committee weight estimation

/// [`is_full_validator_set_covered`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#is_full_validator_set_covered)
fn is_full_validator_set_covered<P: Preset>(start_slot: Slot, end_slot: Slot) -> Result<bool> {
    let last_slot_of_start_epoch = start_slot.try_add(P::SlotsPerEpoch::U64)?.try_sub(1)?;
    let start_full_epoch = misc::compute_epoch_at_slot::<P>(last_slot_of_start_epoch);
    let end_full_epoch = misc::compute_epoch_at_slot::<P>(end_slot.try_add(1)?);
    Ok(start_full_epoch < end_full_epoch)
}

/// [`adjust_committee_weight_estimate_to_ensure_safety`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#adjust_committee_weight_estimate_to_ensure_safety)
fn adjust_committee_weight_estimate_to_ensure_safety(estimate: Gwei) -> Result<Gwei> {
    estimate
        .div_ceil(1000)
        .try_mul(1000 + COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR)
        .map_err(Into::into)
}

/// [`estimate_committee_weight_between_slots`](https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.4/specs/phase0/fast-confirmation.md#estimate_committee_weight_between_slots)
fn estimate_committee_weight_between_slots<P: Preset>(
    total_active_balance: Gwei,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<Gwei> {
    // > Sanity check
    if start_slot > end_slot {
        return Ok(0);
    }

    // > If an entire epoch is covered by the range, return the total active balance
    if is_full_validator_set_covered::<P>(start_slot, end_slot)? {
        return Ok(total_active_balance);
    }

    let slots_per_epoch = P::SlotsPerEpoch::U64;
    let start_epoch = misc::compute_epoch_at_slot::<P>(start_slot);
    let end_epoch = misc::compute_epoch_at_slot::<P>(end_slot);
    let committee_weight = total_active_balance / P::SlotsPerEpoch::non_zero();

    if start_epoch == end_epoch {
        let slot_count = end_slot.try_sub(start_slot)?.try_add(1)?;
        return committee_weight.try_mul(slot_count).map_err(Into::into);
    }

    // > First, calculate the number of committees in the end epoch
    let num_slots_in_end_epoch = misc::slots_since_epoch_start::<P>(end_slot).try_add(1)?;
    // > Next, calculate the number of slots remaining in the end epoch
    let remaining_slots_in_end_epoch = slots_per_epoch.try_sub(num_slots_in_end_epoch)?;
    // > Then, calculate the number of slots in the start epoch
    let num_slots_in_start_epoch =
        slots_per_epoch.try_sub(misc::slots_since_epoch_start::<P>(start_slot))?;

    let start_epoch_weight = committee_weight.try_mul(num_slots_in_start_epoch)?;
    let end_epoch_weight = committee_weight.try_mul(num_slots_in_end_epoch)?;

    // > A range that spans an epoch boundary, but does not span any full epoch
    // > needs pro-rata calculation
    let start_epoch_weight_pro_rated = (start_epoch_weight / P::SlotsPerEpoch::non_zero())
        .try_mul(remaining_slots_in_end_epoch)?;

    adjust_committee_weight_estimate_to_ensure_safety(
        start_epoch_weight_pro_rated.try_add(end_epoch_weight)?,
    )
}

#[cfg(test)]
mod tests {
    use types::preset::Minimal;

    use super::*;

    // Minimal has 8 slots per epoch.

    #[test]
    fn estimate_committee_weight_within_one_epoch() -> Result<()> {
        assert_eq!(
            estimate_committee_weight_between_slots::<Minimal>(800, 9, 11)?,
            300,
        );
        assert_eq!(
            estimate_committee_weight_between_slots::<Minimal>(800, 11, 9)?,
            0,
        );
        Ok(())
    }

    #[test]
    fn estimate_committee_weight_covering_full_epoch() -> Result<()> {
        assert_eq!(
            estimate_committee_weight_between_slots::<Minimal>(800, 8, 15)?,
            800,
        );
        assert_eq!(
            estimate_committee_weight_between_slots::<Minimal>(800, 3, 20)?,
            800,
        );
        Ok(())
    }

    #[test]
    fn estimate_committee_weight_across_epoch_boundary() -> Result<()> {
        // Slots 6..=7 of epoch 0 and slots 8..=9 of epoch 1:
        // start epoch weight = 200, pro-rated = 200 / 8 * 6 = 150, end epoch weight = 200,
        // adjusted = ceil(350 / 1000) * 1005 = 1005.
        assert_eq!(
            estimate_committee_weight_between_slots::<Minimal>(800, 6, 9)?,
            1005,
        );
        Ok(())
    }

    #[test]
    fn block_should_be_finalized_after_two_checkpoints() -> Result<()> {
        // A block in slot 9 (epoch 1) is first covered by the checkpoint of epoch 2.
        // That checkpoint can be finalized at the start of epoch 4 at the earliest.
        assert!(!block_should_be_finalized::<Minimal>(31, 9)?);
        assert!(block_should_be_finalized::<Minimal>(32, 9)?);

        // A block at the start of an epoch is its own checkpoint.
        assert!(!block_should_be_finalized::<Minimal>(23, 8)?);
        assert!(block_should_be_finalized::<Minimal>(24, 8)?);
        Ok(())
    }
}
