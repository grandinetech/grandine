//! Circuit breaker for Gloas builders that win an auction but do not reveal the payload.
//!
//! The pre-Gloas circuit breaker in `builder_api` counts missing blocks. That signal is meaningless
//! under Gloas, where the payload is decoupled from the block: a builder can win the auction, the
//! block can land, and the payload can simply never appear. The thresholds are shared with it,
//! because "this many bad slots" means the same thing on both sides of the fork.

use arithmetic::NonZeroExt as _;
use derivative::Derivative;
use typenum::Unsigned as _;
use types::{
    nonstandard::{DEFAULT_BUILDER_MAX_SKIPPED_SLOTS, DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH},
    phase0::primitives::{Epoch, Slot},
    preset::Preset,
};

/// Epochs the node builds payloads locally for after the circuit breaker trips.
const TRIP_PERIOD: Epoch = 1;

/// Percentage of a slot's committee that must have attested a block before an untimely payload is
/// blamed on its builder.
pub const ATTESTED_PERCENT: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct BuilderCircuitBreakerConfig {
    pub disabled: bool,
    /// Consecutive canonical blocks with withheld payloads tolerated before the node self-builds.
    #[derivative(Default(value = "DEFAULT_BUILDER_MAX_SKIPPED_SLOTS"))]
    pub max_skipped_slots: u64,
    /// Withheld payloads tolerated in the last rolling epoch before the node self-builds.
    #[derivative(Default(value = "DEFAULT_BUILDER_MAX_SKIPPED_SLOTS_PER_EPOCH"))]
    pub max_skipped_slots_per_epoch: u64,
}

/// Watches the canonical chain for withheld payloads and, if they are frequent enough, has the node
/// fall back to self-building until the builder ecosystem recovers.
#[derive(Clone, Debug)]
pub struct BuilderCircuitBreaker {
    config: BuilderCircuitBreakerConfig,
    evaluated_slot: Slot,
    consecutive_withheld: Slot,
    consecutive_delivered: Slot,
    /// Slots of the last rolling epoch whose payload was withheld, store in bitmask, indexed by slot position in the epoch.
    withheld_slots: Slot,
    tripped_until: Slot,
}

impl BuilderCircuitBreaker {
    #[must_use]
    pub const fn new(config: BuilderCircuitBreakerConfig, anchor_slot: Slot) -> Self {
        Self {
            config,
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
    pub const fn is_tripped(&self, current_slot: Slot) -> bool {
        !self.config.disabled && current_slot < self.tripped_until
    }

    /// Judges the canonical block of `slot`.
    ///
    /// Returns the threshold this outcome crossed if it tripped the circuit breaker, [`None`]
    /// otherwise. Slots must be reported in ascending order.
    pub fn record_canonical_outcome<P: Preset>(
        &mut self,
        slot: Slot,
        outcome: PayloadOutcome,
        current_slot: Slot,
    ) -> Option<Trip> {
        let slot_bit = 1 << (slot % P::SlotsPerEpoch::non_zero());

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

        let withheld_in_epoch = self.withheld_slots.count_ones().into();

        // Both thresholds are inclusive, like the pre-Gloas circuit breaker they are shared with.
        let trip = if self.consecutive_withheld > self.config.max_skipped_slots {
            Trip::ConsecutiveWithheld(self.consecutive_withheld)
        } else if withheld_in_epoch > self.config.max_skipped_slots_per_epoch {
            Trip::WithheldInEpoch(withheld_in_epoch)
        } else {
            return None;
        };

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

        Some(trip)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trip {
    ConsecutiveWithheld(Slot),
    WithheldInEpoch(Slot),
}

#[cfg(test)]
mod tests {
    use itertools::Itertools as _;
    use types::preset::Mainnet;

    use super::*;

    const SLOTS_PER_EPOCH: u64 = <Mainnet as Preset>::SlotsPerEpoch::U64;
    const CURRENT_SLOT: Slot = 10 * SLOTS_PER_EPOCH + 7;

    fn new_breaker() -> BuilderCircuitBreaker {
        BuilderCircuitBreaker::new(BuilderCircuitBreakerConfig::default(), 0)
    }

    #[test]
    fn disabled_circuit_breaker_never_trips() {
        let mut breaker = BuilderCircuitBreaker::new(
            BuilderCircuitBreakerConfig {
                disabled: true,
                ..BuilderCircuitBreakerConfig::default()
            },
            0,
        );

        for slot in 0..SLOTS_PER_EPOCH {
            breaker.record_canonical_outcome::<Mainnet>(
                slot,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            );
        }

        assert!(!breaker.is_tripped(CURRENT_SLOT));
    }

    #[test]
    fn consecutive_withheld_payloads_trip_the_circuit_breaker() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..config.max_skipped_slots {
            assert_eq!(
                breaker.record_canonical_outcome::<Mainnet>(
                    slot,
                    PayloadOutcome::Withheld,
                    CURRENT_SLOT
                ),
                None,
            );
            assert!(!breaker.is_tripped(CURRENT_SLOT));
        }

        assert_eq!(
            breaker.record_canonical_outcome::<Mainnet>(
                config.max_skipped_slots,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            ),
            Some(Trip::ConsecutiveWithheld(config.max_skipped_slots + 1)),
        );

        assert!(breaker.is_tripped(CURRENT_SLOT));
        assert!(!breaker.is_tripped(CURRENT_SLOT + TRIP_PERIOD * SLOTS_PER_EPOCH));
    }

    #[test]
    fn withheld_payloads_in_a_rolling_epoch_trip_the_circuit_breaker() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        // Alternating slots never accumulate consecutive failures.
        let trips = (0..=(2 * config.max_skipped_slots_per_epoch))
            .filter_map(|slot| {
                let outcome = if slot.is_multiple_of(2) {
                    PayloadOutcome::Withheld
                } else {
                    PayloadOutcome::Delivered
                };

                breaker.record_canonical_outcome::<Mainnet>(slot, outcome, CURRENT_SLOT)
            })
            .collect_vec();

        assert_eq!(
            trips,
            [Trip::WithheldInEpoch(
                config.max_skipped_slots_per_epoch + 1
            )],
        );
        assert!(breaker.is_tripped(CURRENT_SLOT));

        // The window is cleared on the trip, so the payloads that tripped it cannot trip it again.
        assert_eq!(
            breaker.record_canonical_outcome::<Mainnet>(
                2 * config.max_skipped_slots_per_epoch + 1,
                PayloadOutcome::Delivered,
                CURRENT_SLOT,
            ),
            None,
        );
    }

    #[test]
    fn skipped_slots_discard_evidence() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                slot,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            );
        }

        breaker.skip_to(CURRENT_SLOT);

        assert_eq!(breaker.evaluated_slot(), CURRENT_SLOT);

        // A run cannot continue across the gap.
        assert_eq!(
            breaker.record_canonical_outcome::<Mainnet>(
                CURRENT_SLOT,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            ),
            None,
        );
    }

    #[test]
    fn delivered_payload_resets_consecutive_withheld_payloads() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                slot,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            );
        }

        breaker.record_canonical_outcome::<Mainnet>(
            config.max_skipped_slots,
            PayloadOutcome::Delivered,
            CURRENT_SLOT,
        );

        for slot in 0..config.max_skipped_slots {
            let slot = slot + config.max_skipped_slots + 1;

            assert_eq!(
                breaker.record_canonical_outcome::<Mainnet>(
                    slot,
                    PayloadOutcome::Withheld,
                    CURRENT_SLOT
                ),
                None,
            );
        }

        assert!(!breaker.is_tripped(CURRENT_SLOT));
    }

    #[test]
    fn delivered_payloads_untrip_the_circuit_breaker_before_it_expires() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..=config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                slot,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            );
        }

        assert!(breaker.is_tripped(CURRENT_SLOT));

        // A single timely reveal says nothing about the builder that would win the next auction.
        for slot in 0..config.max_skipped_slots {
            let slot = slot + config.max_skipped_slots + 1;

            breaker.record_canonical_outcome::<Mainnet>(
                slot,
                PayloadOutcome::Delivered,
                CURRENT_SLOT,
            );

            assert!(breaker.is_tripped(CURRENT_SLOT));
        }

        breaker.record_canonical_outcome::<Mainnet>(
            2 * config.max_skipped_slots + 1,
            PayloadOutcome::Delivered,
            CURRENT_SLOT,
        );

        assert!(!breaker.is_tripped(CURRENT_SLOT));
    }

    #[test]
    fn withheld_payloads_break_a_run_of_delivered_ones() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..=config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                slot,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
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

            breaker.record_canonical_outcome::<Mainnet>(slot, outcome, CURRENT_SLOT);

            assert!(breaker.is_tripped(CURRENT_SLOT));
        }
    }

    #[test]
    fn unknown_outcomes_neither_trip_nor_reset_the_circuit_breaker() {
        let mut breaker = new_breaker();
        let config = breaker.config();

        for slot in 0..config.max_skipped_slots {
            breaker.record_canonical_outcome::<Mainnet>(
                2 * slot,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            );
            breaker.record_canonical_outcome::<Mainnet>(
                2 * slot + 1,
                PayloadOutcome::Unknown,
                CURRENT_SLOT,
            );
        }

        assert!(!breaker.is_tripped(CURRENT_SLOT));

        // Self-built and skipped slots do not mask a builder-wide failure.
        assert_eq!(
            breaker.record_canonical_outcome::<Mainnet>(
                2 * config.max_skipped_slots,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            ),
            Some(Trip::ConsecutiveWithheld(config.max_skipped_slots + 1)),
        );
    }

    #[test]
    fn withheld_payloads_age_out_of_the_rolling_epoch() {
        let mut breaker = new_breaker();

        for slot in 0..SLOTS_PER_EPOCH {
            breaker.record_canonical_outcome::<Mainnet>(
                slot,
                PayloadOutcome::Withheld,
                CURRENT_SLOT,
            );
        }

        assert!(breaker.is_tripped(CURRENT_SLOT));

        // A full epoch of delivered payloads clears the window.
        for slot in SLOTS_PER_EPOCH..(2 * SLOTS_PER_EPOCH) {
            breaker.record_canonical_outcome::<Mainnet>(
                slot,
                PayloadOutcome::Delivered,
                CURRENT_SLOT + 1,
            );
        }

        assert_eq!(
            breaker.record_canonical_outcome::<Mainnet>(
                2 * SLOTS_PER_EPOCH,
                PayloadOutcome::Withheld,
                CURRENT_SLOT + 1,
            ),
            None,
        );
    }
}
