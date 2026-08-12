//! Circuit breaker for Gloas builders that win an auction but do not reveal the payload.
//!
//! The pre-Gloas circuit breaker in `builder_api` counts missing blocks. That signal is meaningless
//! under Gloas, where the payload is decoupled from the block: a builder can win the auction, the
//! block can land, and the payload can simply never appear. The thresholds are shared with it,
//! because "this many bad slots" means the same thing on both sides of the fork.

use arithmetic::NonZeroExt as _;
use derivative::Derivative;
use im::hashmap::HashMap;
use logging::{debug_with_peers, warn_with_peers};
use typenum::Unsigned as _;
use types::{
    gloas::primitives::BuilderIndex,
    nonstandard::{DEFAULT_BUILDER_MAX_SKIPPED_SLOTS, DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH},
    phase0::primitives::{Epoch, H256, Slot},
    preset::Preset,
};

/// Epochs the node builds payloads locally for after the circuit breaker trips.
const TRIP_PERIOD: Epoch = 1;

/// Epochs a builder stays blacklisted for its first withheld payload, increase by one with
/// every further withheld payload up to `max_blacklist_period`.
const BLACKLIST_PERIOD: Epoch = 1;
pub const DEFAULT_BUILDER_MAX_BLACKLIST_PERIOD: Epoch = 8;

/// Percentage of a slot's committee that must have attested a block before an untimely payload is
/// blamed on its builder.
pub const ATTESTED_PERCENT: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct BuilderCircuitBreakerConfig {
    /// Whether the global tier is disabled. Independent of the per-builder tier.
    pub global_disabled: bool,
    /// Whether bids from blacklisted builders are skipped. Independent of the global tier.
    pub blacklisting_enabled: bool,
    #[derivative(Default(value = "DEFAULT_BUILDER_MAX_SKIPPED_SLOTS"))]
    pub max_skipped_slots: u64,
    #[derivative(Default(value = "DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH"))]
    pub max_skipped_slots_per_epoch: u64,
    #[derivative(Default(value = "DEFAULT_BUILDER_MAX_BLACKLIST_PERIOD"))]
    pub max_blacklist_period: Epoch,
}

impl BuilderCircuitBreakerConfig {
    fn blacklist_period_for(self, withheld_payloads: u8) -> Epoch {
        BLACKLIST_PERIOD
            .saturating_mul(withheld_payloads.into())
            .min(self.max_blacklist_period)
    }

    fn max_withheld_payloads(self) -> u8 {
        u8::try_from(self.max_blacklist_period.div_ceil(BLACKLIST_PERIOD)).unwrap_or(u8::MAX)
    }
}

/// There are two independent tiers of circuit breaking:
///
/// - Per-builder: a builder that withholds payloads is blacklisted for a period of time, and its
///   bids are not selected while it is.
/// - Global: if payloads are withheld often enough on the canonical chain, no bid is selected at
///   all and the node self-builds until the builder ecosystem recovers.
#[derive(Clone, Debug)]
pub struct BuilderCircuitBreaker {
    config: BuilderCircuitBreakerConfig,
    blacklisted_builders: HashMap<BuilderIndex, BlacklistedBuilder>,
    evaluated_slot: Slot,
    consecutive_withheld: Slot,
    consecutive_delivered: Slot,
    /// Slots of the last rolling epoch whose payload was withheld, store in bitmask, indexed by slot position in the epoch.
    withheld_slots: Slot,
    tripped_until: Slot,
}

impl BuilderCircuitBreaker {
    #[must_use]
    pub fn new(config: BuilderCircuitBreakerConfig, anchor_slot: Slot) -> Self {
        Self {
            config,
            blacklisted_builders: HashMap::new(),
            evaluated_slot: anchor_slot,
            consecutive_withheld: 0,
            consecutive_delivered: 0,
            withheld_slots: 0,
            tripped_until: 0,
        }
    }

    #[must_use]
    pub const fn config(&self) -> BuilderCircuitBreakerConfig {
        self.config
    }

    #[must_use]
    pub const fn evaluated_slot(&self) -> Slot {
        self.evaluated_slot
    }

    pub const fn set_evaluated_slot(&mut self, slot: Slot) {
        self.evaluated_slot = slot;
    }

    /// Resumes at `slot`, discarding evidence gathered before the slots that are being skipped.
    pub const fn skip_to(&mut self, slot: Slot) {
        self.evaluated_slot = slot;
        self.consecutive_withheld = 0;
        self.consecutive_delivered = 0;
        self.withheld_slots = 0;
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blacklisted_builders.is_empty()
    }

    #[must_use]
    pub fn is_builder_blacklisted(&self, current_slot: Slot, builder_index: BuilderIndex) -> bool {
        self.config.blacklisting_enabled
            && self
                .blacklisted_builders
                .get(&builder_index)
                .is_some_and(|blacklisted_builder| {
                    blacklisted_builder.is_blacklisted_at(current_slot)
                })
    }

    #[must_use]
    pub const fn is_tripped(&self, current_slot: Slot) -> bool {
        !self.config.global_disabled && current_slot < self.tripped_until
    }

    pub fn expire_blacklists(&mut self, current_slot: Slot) {
        self.blacklisted_builders
            .retain(|&builder_index, blacklisted_builder| {
                let blacklisted = blacklisted_builder.is_blacklisted_at(current_slot);

                if !blacklisted {
                    debug_with_peers!(
                        "builder {builder_index} served its blacklist and is now whitelisted again"
                    );
                }

                blacklisted
            });
    }

    pub fn record_withheld_payload<P: Preset>(
        &mut self,
        current_slot: Slot,
        builder_index: BuilderIndex,
        block_root: H256,
        block_slot: Slot,
    ) {
        let config = self.config;

        let blacklisted_builder = self.blacklisted_builders.entry(builder_index).or_default();

        blacklisted_builder.record_withheld_payload::<P>(current_slot, config);

        let withheld_payloads = blacklisted_builder.withheld_payloads;
        let blacklisted_until = blacklisted_builder.blacklisted_until;

        debug_with_peers!(
            "builder {builder_index} did not reveal the payload in time for block {block_root:?} \
             at slot {block_slot} ({withheld_payloads} withheld payloads in a row), \
             blacklisting it until slot {blacklisted_until}"
        );
    }

    pub fn record_delivered_payload(
        &mut self,
        builder_index: BuilderIndex,
        block_root: H256,
        block_slot: Slot,
    ) {
        let Some(blacklisted_builder) = self.blacklisted_builders.get_mut(&builder_index) else {
            return;
        };

        blacklisted_builder.record_delivered_payload();

        let withheld_payloads = blacklisted_builder.withheld_payloads;
        let blacklisted_until = blacklisted_builder.blacklisted_until;

        if withheld_payloads == 0 {
            self.blacklisted_builders.remove(&builder_index);

            debug_with_peers!(
                "builder {builder_index} delivered the payload of block {block_root:?} at slot \
                 {block_slot} and is now whitelisted again"
            );

            return;
        }

        debug_with_peers!(
            "builder {builder_index} delivered the payload of block {block_root:?} at slot \
             {block_slot} (still {withheld_payloads} withheld payloads left to clear), blacklisted \
             until slot {blacklisted_until}"
        );
    }

    /// Judges the canonical block of `canonical_slot`.
    pub fn record_canonical_outcome<P: Preset>(
        &mut self,
        current_slot: Slot,
        canonical_slot: Slot,
        outcome: PayloadOutcome,
    ) {
        let slot_bit = 1 << (canonical_slot % P::SlotsPerEpoch::non_zero());

        match outcome {
            PayloadOutcome::Delivered => {
                self.consecutive_withheld = 0;
                self.consecutive_delivered = self.consecutive_delivered.saturating_add(1);
                self.withheld_slots &= !slot_bit;
            }
            PayloadOutcome::Withheld => {
                self.consecutive_withheld = self.consecutive_withheld.saturating_add(1);
                self.consecutive_delivered = 0;
                self.withheld_slots |= slot_bit;
            }
            // A slot nobody can be blamed for still ages out of the rolling window.
            PayloadOutcome::Unknown => self.withheld_slots &= !slot_bit,
        }

        // Builders recovered, so the trip is cleared ahead of its expiry.
        if self.consecutive_delivered > self.config.max_skipped_slots {
            self.tripped_until = 0;
        }

        let withheld_in_epoch = Slot::from(self.withheld_slots.count_ones());

        // Both thresholds are inclusive, like the pre-Gloas circuit breaker they are shared with.
        if self.consecutive_withheld > self.config.max_skipped_slots {
            let consecutive_withheld = self.consecutive_withheld;

            warn_with_peers!(
                "builders withheld {consecutive_withheld} payloads in a row, \
                 building payloads locally"
            );
        } else if withheld_in_epoch > self.config.max_skipped_slots_per_epoch {
            warn_with_peers!(
                "builders withheld {withheld_in_epoch} payloads in the last epoch, \
                 building payloads locally"
            );
        } else {
            return;
        }

        // The trip lasts one trip period, after which it re-arms. The expiry is what clears it when
        // recovery cannot be observed: this node's own slots are no evidence about builders while it
        // self-builds, so a node proposing most of them would stay tripped forever.
        self.tripped_until = self
            .tripped_until
            .max(current_slot.saturating_add(TRIP_PERIOD.saturating_mul(P::SlotsPerEpoch::U64)));

        // Both counters are reset, or the evidence that tripped the breaker would keep tripping it
        // every slot until it ages out of the window.
        self.consecutive_withheld = 0;
        self.withheld_slots = 0;
    }

    /// Forgets builders that are no longer in the builder registry.
    ///
    /// Gloas reuses the indices of exited builders, so without this a long blacklist would punish
    /// whichever builder inherits the index.
    pub fn retain_active_builders(&mut self, is_active: impl Fn(BuilderIndex) -> bool) {
        self.blacklisted_builders
            .retain(|&builder_index, _| is_active(builder_index));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadOutcome {
    Delivered,
    /// The builder did not reveal the payload in time, whether it revealed it later or not at all.
    Withheld,
    /// No conclusion: the slot was skipped, the block was self-built, or nobody attested it.
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BlacklistedBuilder {
    withheld_payloads: u8,
    blacklisted_until: Slot,
}

impl BlacklistedBuilder {
    const fn is_blacklisted_at(self, current_slot: Slot) -> bool {
        current_slot < self.blacklisted_until
    }

    const fn record_delivered_payload(&mut self) {
        self.withheld_payloads = self.withheld_payloads.saturating_sub(1);
    }

    fn record_withheld_payload<P: Preset>(
        &mut self,
        current_slot: Slot,
        config: BuilderCircuitBreakerConfig,
    ) {
        self.withheld_payloads = self
            .withheld_payloads
            .saturating_add(1)
            .min(config.max_withheld_payloads());

        self.blacklisted_until = self.blacklisted_until.max(
            current_slot.saturating_add(
                config
                    .blacklist_period_for(self.withheld_payloads)
                    .saturating_mul(P::SlotsPerEpoch::U64),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use types::preset::Mainnet;

    use super::*;

    const SLOTS_PER_EPOCH: u64 = <Mainnet as Preset>::SlotsPerEpoch::U64;
    const CURRENT_SLOT: Slot = 10 * SLOTS_PER_EPOCH + 7;
    const BUILDER_INDEX: BuilderIndex = 3;

    fn withhold_payload(breaker: &mut BuilderCircuitBreaker, current_slot: Slot) {
        breaker.record_withheld_payload::<Mainnet>(
            current_slot,
            BUILDER_INDEX,
            H256::zero(),
            current_slot,
        );
    }

    fn deliver_payload(breaker: &mut BuilderCircuitBreaker, block_slot: Slot) {
        breaker.record_delivered_payload(BUILDER_INDEX, H256::zero(), block_slot);
    }

    /// Pins the blacklist expiry, which is the only way the withheld payload count is observable.
    fn assert_blacklisted_until(breaker: &BuilderCircuitBreaker, expiry: Slot) {
        assert!(breaker.is_builder_blacklisted(expiry.saturating_sub(1), BUILDER_INDEX));
        assert!(!breaker.is_builder_blacklisted(expiry, BUILDER_INDEX));
    }

    fn new_breaker() -> BuilderCircuitBreaker {
        BuilderCircuitBreaker::new(
            BuilderCircuitBreakerConfig {
                blacklisting_enabled: true,
                ..BuilderCircuitBreakerConfig::default()
            },
            0,
        )
    }

    #[test]
    fn blacklist_period_grows_with_every_withheld_payload() {
        let config = BuilderCircuitBreakerConfig::default();

        // 1, 2, 3, 4, ... epochs, capped at `DEFAULT_BUILDER_MAX_BLACKLIST_PERIOD`.
        assert_eq!(config.blacklist_period_for(1), 1);
        assert_eq!(config.blacklist_period_for(2), 2);
        assert_eq!(config.blacklist_period_for(3), 3);
        assert_eq!(
            config.blacklist_period_for(8),
            DEFAULT_BUILDER_MAX_BLACKLIST_PERIOD,
        );
        assert_eq!(
            config.blacklist_period_for(u8::MAX),
            DEFAULT_BUILDER_MAX_BLACKLIST_PERIOD,
        );
    }

    #[test]
    fn blacklist_outlives_the_epoch_it_was_recorded_in() {
        let mut breaker = new_breaker();
        let last_slot_of_epoch = 11 * SLOTS_PER_EPOCH - 1;

        withhold_payload(&mut breaker, last_slot_of_epoch);

        let expiry = last_slot_of_epoch + BLACKLIST_PERIOD * SLOTS_PER_EPOCH;

        // The next epoch starts one slot later and must not lift the blacklist with it.
        assert!(breaker.is_builder_blacklisted(last_slot_of_epoch + 1, BUILDER_INDEX));
        assert!(breaker.is_builder_blacklisted(expiry - 1, BUILDER_INDEX));
        assert!(!breaker.is_builder_blacklisted(expiry, BUILDER_INDEX));
    }

    #[test]
    fn repaid_withheld_payloads_lift_a_blacklist_early() {
        let mut breaker = new_breaker();

        withhold_payload(&mut breaker, CURRENT_SLOT);

        // The builder delivered as many payloads as it withheld, so the rest of the period is
        // not served.
        deliver_payload(&mut breaker, CURRENT_SLOT);

        assert!(!breaker.is_builder_blacklisted(CURRENT_SLOT, BUILDER_INDEX));
        assert!(breaker.is_empty());
    }

    #[test]
    fn served_blacklists_are_lifted_with_payloads_still_owed() {
        let mut breaker = new_breaker();

        for _ in 0..3 {
            withhold_payload(&mut breaker, CURRENT_SLOT);
        }

        let expiry = CURRENT_SLOT + 3 * SLOTS_PER_EPOCH;

        breaker.expire_blacklists(expiry - 1);

        assert!(!breaker.is_empty());

        // Two payloads are still owed, but the period has been served.
        breaker.expire_blacklists(expiry);

        assert!(breaker.is_empty());

        // The escalation starts over rather than resuming where it left off, so the next withheld
        // payload is worth a single epoch again.
        withhold_payload(&mut breaker, expiry);

        assert_blacklisted_until(&breaker, expiry + BLACKLIST_PERIOD * SLOTS_PER_EPOCH);
    }

    #[test]
    fn withholding_while_blacklisted_still_escalates() {
        let mut breaker = new_breaker();

        withhold_payload(&mut breaker, CURRENT_SLOT);

        let expiry = CURRENT_SLOT + BLACKLIST_PERIOD * SLOTS_PER_EPOCH;

        // Blacklisted builders are only skipped by this node, so other nodes can still hand them
        // an auction to withhold, and that is what the escalation is for.
        breaker.expire_blacklists(expiry - 1);
        withhold_payload(&mut breaker, expiry - 1);

        assert_blacklisted_until(
            &breaker,
            expiry - 1 + 2 * BLACKLIST_PERIOD * SLOTS_PER_EPOCH,
        );
    }

    #[test]
    fn delivered_payload_forgives_a_single_withheld_one() {
        let mut breaker = new_breaker();

        for _ in 0..3 {
            withhold_payload(&mut breaker, CURRENT_SLOT);
        }

        deliver_payload(&mut breaker, CURRENT_SLOT);

        assert_blacklisted_until(&breaker, CURRENT_SLOT + 3 * SLOTS_PER_EPOCH);

        // Only one of the three withheld payloads was forgiven, so the escalation resumes where it
        // left off: the next one is worth three epochs again, not one.
        withhold_payload(&mut breaker, CURRENT_SLOT + 1);

        assert_blacklisted_until(&breaker, CURRENT_SLOT + 1 + 3 * SLOTS_PER_EPOCH);
    }

    #[test]
    fn max_withheld_payloads_covers_blacklist_periods() {
        let config_with = |max_blacklist_period| BuilderCircuitBreakerConfig {
            max_blacklist_period,
            ..BuilderCircuitBreakerConfig::default()
        };

        // A blacklist period of zero never blacklists anyone, so nothing is worth counting.
        assert_eq!(config_with(0).max_withheld_payloads(), 0);

        // `builder_max_blacklist_period` is bounded to what the counter can express.
        for max_blacklist_period in [0, 1, 2, 3, 8, 127, 128, 129, u8::MAX.into()] {
            let config = config_with(max_blacklist_period);
            let max_withheld_payloads = config.max_withheld_payloads();

            assert_eq!(
                config.blacklist_period_for(max_withheld_payloads),
                max_blacklist_period,
            );

            for withheld_payloads in 1..max_withheld_payloads {
                assert!(config.blacklist_period_for(withheld_payloads) < max_blacklist_period);
            }
        }
    }

    #[test]
    fn exited_builders_are_forgotten() {
        let mut breaker = new_breaker();

        withhold_payload(&mut breaker, CURRENT_SLOT);
        breaker.retain_active_builders(|builder_index| builder_index != BUILDER_INDEX);

        assert!(breaker.is_empty());
        assert!(!breaker.is_builder_blacklisted(CURRENT_SLOT, BUILDER_INDEX));
    }

    #[test]
    fn disabled_global_tier_never_trips_but_still_blacklists() {
        let mut breaker = BuilderCircuitBreaker::new(
            BuilderCircuitBreakerConfig {
                global_disabled: true,
                blacklisting_enabled: true,
                ..BuilderCircuitBreakerConfig::default()
            },
            0,
        );

        withhold_payload(&mut breaker, CURRENT_SLOT);

        for slot in 0..SLOTS_PER_EPOCH {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Withheld,
            );
        }

        assert!(breaker.is_builder_blacklisted(CURRENT_SLOT, BUILDER_INDEX));
        assert!(!breaker.is_tripped(CURRENT_SLOT));
    }

    #[test]
    fn consecutive_withheld_payloads_trip_the_circuit_breaker() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Withheld,
            );

            assert!(!breaker.is_tripped(CURRENT_SLOT));
        }

        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT,
            config.max_skipped_slots,
            PayloadOutcome::Withheld,
        );

        assert!(breaker.is_tripped(CURRENT_SLOT));
        assert!(!breaker.is_tripped(CURRENT_SLOT + TRIP_PERIOD * SLOTS_PER_EPOCH));
    }

    #[test]
    fn withheld_payloads_in_a_rolling_epoch_trip_the_circuit_breaker() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        // Alternating slots never accumulate consecutive failures.
        for slot in 0..(2 * config.max_skipped_slots_per_epoch) {
            let outcome = if slot.is_multiple_of(2) {
                PayloadOutcome::Withheld
            } else {
                PayloadOutcome::Delivered
            };

            breaker.record_canonical_outcome::<Mainnet>(CURRENT_SLOT, slot, outcome);

            assert!(!breaker.is_tripped(CURRENT_SLOT));
        }

        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT,
            2 * config.max_skipped_slots_per_epoch,
            PayloadOutcome::Withheld,
        );

        assert!(breaker.is_tripped(CURRENT_SLOT));

        // The window is cleared on the trip, so the payloads that tripped it cannot trip it again.
        // A later slot is judged, or a second trip would expire at the same slot as the first.
        let later_slot = CURRENT_SLOT + TRIP_PERIOD * SLOTS_PER_EPOCH;

        breaker.record_canonical_outcome::<Mainnet>(
            later_slot,
            2 * config.max_skipped_slots_per_epoch + 1,
            PayloadOutcome::Withheld,
        );

        assert!(!breaker.is_tripped(later_slot));
    }

    #[test]
    fn skipped_slots_discard_global_evidence() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        withhold_payload(&mut breaker, CURRENT_SLOT);

        for slot in 0..config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Withheld,
            );
        }

        breaker.skip_to(CURRENT_SLOT);

        assert_eq!(breaker.evaluated_slot(), CURRENT_SLOT);

        // A run cannot continue across the gap.
        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT,
            CURRENT_SLOT,
            PayloadOutcome::Withheld,
        );

        assert!(!breaker.is_tripped(CURRENT_SLOT));

        // Per-builder evidence is not observed through the canonical chain and survives the gap.
        assert!(breaker.is_builder_blacklisted(CURRENT_SLOT, BUILDER_INDEX));
    }

    #[test]
    fn delivered_payload_resets_consecutive_withheld_payloads() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Withheld,
            );
        }

        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT,
            config.max_skipped_slots,
            PayloadOutcome::Delivered,
        );

        for slot in 0..config.max_skipped_slots {
            let slot = slot + config.max_skipped_slots + 1;

            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Withheld,
            );

            assert!(!breaker.is_tripped(CURRENT_SLOT));
        }
    }

    #[test]
    fn delivered_payloads_untrip_the_circuit_breaker_before_it_expires() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..=config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Withheld,
            );
        }

        assert!(breaker.is_tripped(CURRENT_SLOT));

        // A single timely reveal says nothing about the builder that would win the next auction.
        for slot in 0..config.max_skipped_slots {
            let slot = slot + config.max_skipped_slots + 1;

            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Delivered,
            );

            assert!(breaker.is_tripped(CURRENT_SLOT));
        }

        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT,
            2 * config.max_skipped_slots + 1,
            PayloadOutcome::Delivered,
        );

        assert!(!breaker.is_tripped(CURRENT_SLOT));
    }

    #[test]
    fn withheld_payloads_break_a_run_of_delivered_ones() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..=config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Withheld,
            );
        }

        assert!(breaker.is_tripped(CURRENT_SLOT));

        // Alternating outcomes are the flapping the threshold exists to prevent.
        for slot in 0..(4 * config.max_skipped_slots) {
            let slot = slot + config.max_skipped_slots + 1;

            let outcome = if slot.is_multiple_of(2) {
                PayloadOutcome::Withheld
            } else {
                PayloadOutcome::Delivered
            };

            breaker.record_canonical_outcome::<Mainnet>(CURRENT_SLOT, slot, outcome);

            assert!(breaker.is_tripped(CURRENT_SLOT));
        }
    }

    #[test]
    fn unknown_outcomes_neither_trip_nor_reset_the_circuit_breaker() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                2 * slot,
                PayloadOutcome::Withheld,
            );
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                2 * slot + 1,
                PayloadOutcome::Unknown,
            );
        }

        assert!(!breaker.is_tripped(CURRENT_SLOT));

        // Self-built and skipped slots do not mask a builder-wide failure.
        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT,
            2 * config.max_skipped_slots,
            PayloadOutcome::Withheld,
        );

        assert!(breaker.is_tripped(CURRENT_SLOT));
    }

    #[test]
    fn unknown_outcomes_age_out_of_the_rolling_epoch() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        // Alternating slots fill the window right up to the threshold.
        for slot in 0..(2 * config.max_skipped_slots_per_epoch) {
            let outcome = if slot.is_multiple_of(2) {
                PayloadOutcome::Withheld
            } else {
                PayloadOutcome::Delivered
            };

            breaker.record_canonical_outcome::<Mainnet>(CURRENT_SLOT, slot, outcome);
        }

        // Slot 0 comes around again as a slot nobody can be blamed for, freeing its place in the
        // window for the next withheld payload.
        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT,
            SLOTS_PER_EPOCH,
            PayloadOutcome::Unknown,
        );

        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT,
            SLOTS_PER_EPOCH + 1,
            PayloadOutcome::Withheld,
        );

        assert!(!breaker.is_tripped(CURRENT_SLOT));
    }

    #[test]
    fn withheld_payloads_age_out_of_the_rolling_epoch() {
        let mut breaker = new_breaker();

        for slot in 0..SLOTS_PER_EPOCH {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                slot,
                PayloadOutcome::Withheld,
            );
        }

        assert!(breaker.is_tripped(CURRENT_SLOT));

        // A full epoch of delivered payloads clears the window.
        for slot in SLOTS_PER_EPOCH..(2 * SLOTS_PER_EPOCH) {
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT + 1,
                slot,
                PayloadOutcome::Delivered,
            );
        }

        breaker.record_canonical_outcome::<Mainnet>(
            CURRENT_SLOT + 1,
            2 * SLOTS_PER_EPOCH,
            PayloadOutcome::Withheld,
        );

        assert!(!breaker.is_tripped(CURRENT_SLOT + 1));
    }
}
