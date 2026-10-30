//! A [`Stream`]-based timer for the Ethereum 2.0 Beacon Chain.
//!
//! # Implementation
//!
//! This is implemented using [`try_unfold`] with [`sleep_until`]. Each iteration sleeps until the
//! next tick's deadline, then advances the deadline by the current tick duration before looping.
//! Some subtleties to keep in mind:
//!
//! - The API of [`sleep_until`] (as well as other timer utilities in [`tokio::time`]) uses
//!   [`Instant`]s. [`Instant`]s are opaque. There is no way to directly convert a timestamp
//!   (of any kind, not just Unix time) to an [`Instant`]. The hack in [`ticks`] may result in
//!   unexpected behavior in extreme conditions.
//!
//! - The tick duration is recomputed at every tick boundary so that fork transitions (e.g. from
//!   pre-Gloas 12-tick slots to post-Gloas 16-tick slots) are handled correctly without any
//!   accumulated error.
//!
//! - It is unclear how [`sleep_until`] behaves around leap seconds.
//!
//! # Possible alternatives
//!
//! There are several other crates we could choose from:
//! - [`clokwerk`]
//! - [`job_scheduler`]
//! - [`schedule`]
//! - [`timer`]
//! - [`white_rabbit`]
//!
//! The first 3 do not come with any timers or runtimes. They need to be driven manually:
//! ```ignore
//! loop {
//!     scheduler.run_pending();
//!     thread::sleep(duration);
//! }
//! ```
//! This would have some benefits:
//! - By varying the sleep duration, we could trade higher CPU usage for higher precision.
//! - Leap seconds should be handled correctly without any extra effort on our part.
//!
//! [`timer`] and [`white_rabbit`] use timers internally.
//! They are likely to be more efficient, but it is unclear if they handle leap seconds correctly.
//!
//! None of these libraries are designed to work with futures, but making them work together should
//! be as simple as using a channel.
//!
//! [`tokio::time`]:  tokio::time
//! [`Instant`]:      tokio::time::Instant
//! [`sleep_until`]:  tokio::time::sleep_until
//! [`try_unfold`]:   futures::stream::try_unfold
//!
//! [`clokwerk`]:      https://crates.io/crates/clokwerk
//! [`job_scheduler`]: https://crates.io/crates/job_scheduler
//! [`schedule`]:      https://crates.io/crates/schedule
//! [`timer`]:         https://crates.io/crates/timer
//! [`white_rabbit`]:  https://crates.io/crates/white_rabbit

use core::{error::Error, pin::Pin, time::Duration};
use std::time::{Instant, SystemTime, SystemTimeError};

use anyhow::Result;
use enum_iterator::Sequence;
use futures::stream::Stream;
use helper_functions::misc;
use serde::Deserialize;
use strum::AsRefStr;
use thiserror::Error;
use types::{
    config::Config,
    nonstandard::Phase,
    phase0::{
        consts::{BASIS_POINTS, GENESIS_SLOT},
        primitives::{Epoch, Slot, UnixSeconds},
    },
    preset::Preset,
    traits::{BeaconBlock as _, SignedBeaconBlock},
};

#[cfg(test)]
mod fake_time;

pub trait InstantLike: Sized {
    fn checked_add(self, duration: Duration) -> Option<Self>;
}

pub trait SystemTimeLike: Copy {
    type Error: Error + Send + Sync + 'static;

    const UNIX_EPOCH: Self;

    fn duration_since(self, earlier: Self) -> Result<Duration, Self::Error>;
}

impl InstantLike for Instant {
    fn checked_add(self, duration: Duration) -> Option<Self> {
        Self::checked_add(&self, duration)
    }
}

impl InstantLike for tokio::time::Instant {
    fn checked_add(self, duration: Duration) -> Option<Self> {
        Self::checked_add(&self, duration)
    }
}

impl SystemTimeLike for SystemTime {
    type Error = SystemTimeError;

    const UNIX_EPOCH: Self = Self::UNIX_EPOCH;

    fn duration_since(self, earlier: Self) -> Result<Duration, Self::Error> {
        Self::duration_since(&self, earlier)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize)]
pub struct Tick {
    #[serde(with = "serde_utils::string_or_native")]
    pub slot: Slot,
    pub kind: TickKind,
}

impl Tick {
    #[must_use]
    pub const fn start_of_slot(slot: Slot) -> Self {
        Self::new(slot, TickKind::Propose)
    }

    #[must_use]
    pub fn block_proposal<P: Preset>(block: &impl SignedBeaconBlock<P>) -> Self {
        Self::new(block.message().slot(), TickKind::Propose)
    }

    pub fn at_time<P: Preset>(
        config: &Config,
        time: UnixSeconds,
        genesis_time: UnixSeconds,
    ) -> Result<Self> {
        let duration_since_unix_epoch = Duration::from_secs(time);
        Self::from_duration::<P>(config, duration_since_unix_epoch, genesis_time)
    }

    pub fn at_time_in_ms<P: Preset>(
        config: &Config,
        time: u64,
        genesis_time: UnixSeconds,
    ) -> Result<Self> {
        let duration_since_unix_epoch = Duration::from_millis(time);
        Self::from_duration::<P>(config, duration_since_unix_epoch, genesis_time)
    }

    pub fn current<P: Preset>(config: &Config, genesis_time: UnixSeconds) -> Result<Self> {
        let duration_since_unix_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        Self::from_duration::<P>(config, duration_since_unix_epoch, genesis_time)
    }

    #[must_use]
    pub fn epoch<P: Preset>(self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.slot)
    }

    #[must_use]
    pub const fn is_before_attesting_interval(self) -> bool {
        matches!(
            self.kind,
            TickKind::Propose
                | TickKind::ProposeSecond
                | TickKind::ProposeThird
                | TickKind::ProposeFourth,
        )
    }

    #[must_use]
    pub fn is_before_aggregating_interval(self) -> bool {
        self.kind < TickKind::Aggregate
    }

    #[must_use]
    pub fn is_before_payload_attesting_interval(self) -> bool {
        self.kind < TickKind::PayloadAttest
    }

    #[must_use]
    pub const fn is_start_of_slot(self) -> bool {
        matches!(self.kind, TickKind::Propose)
    }

    #[must_use]
    pub fn is_start_of_epoch<P: Preset>(self) -> bool {
        misc::is_epoch_start::<P>(self.slot) && self.is_start_of_slot()
    }

    #[must_use]
    pub const fn is_start_of_interval(self) -> bool {
        matches!(
            self.kind,
            TickKind::Propose | TickKind::Attest | TickKind::Aggregate | TickKind::PayloadAttest,
        )
    }

    #[must_use]
    pub fn is_end_of_slot<P: Preset>(self, config: &Config) -> bool {
        if config.phase_at_slot::<P>(self.slot) >= Phase::Gloas {
            matches!(self.kind, TickKind::PayloadAttest)
        } else {
            matches!(self.kind, TickKind::Aggregate)
        }
    }

    #[must_use]
    pub fn is_last_tick<P: Preset>(self, config: &Config) -> bool {
        if config.phase_at_slot::<P>(self.slot) >= Phase::Gloas {
            matches!(self.kind, TickKind::PayloadAttestFourth)
        } else {
            matches!(self.kind, TickKind::AggregateFourth)
        }
    }

    #[must_use]
    pub const fn is_end_of_interval(self) -> bool {
        matches!(
            self.kind,
            TickKind::AttestFourth
                | TickKind::AggregateFourth
                | TickKind::ProposeFourth
                | TickKind::PayloadAttestFourth,
        )
    }

    // Only these ticks reach the application.
    const fn is_emitted(self) -> bool {
        self.is_start_of_interval() || self.is_end_of_interval()
    }

    pub fn delay<P: Preset>(self, config: &Config, genesis_time: UnixSeconds) -> Result<Duration> {
        let duration_since_unix_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let unix_epoch_to_genesis = Duration::from_secs(genesis_time);

        let duration_since_genesis =
            duration_since_unix_epoch.saturating_sub(unix_epoch_to_genesis);

        let slot_duration = config.slot_duration_ms;

        let duration_before_slot =
            slot_duration.saturating_mul(self.slot.saturating_sub(GENESIS_SLOT).try_into()?);

        let duration_after_slot = self.offset_in_slot::<P>(config);
        let duration_until_tick = duration_before_slot.saturating_add(duration_after_slot);

        Ok(duration_since_genesis.saturating_sub(duration_until_tick))
    }

    fn from_duration<P: Preset>(
        config: &Config,
        duration_since_unix_epoch: Duration,
        genesis_time: UnixSeconds,
    ) -> Result<Self> {
        let unix_epoch_to_genesis = Duration::from_secs(genesis_time);

        // `Duration` does not implement `Div<Duration>` or `Rem<Duration>`,
        // so we have to do arithmetic on nanoseconds.
        let nanos_since_genesis = duration_since_unix_epoch
            .saturating_sub(unix_epoch_to_genesis)
            .as_nanos();

        // First, determine the slot based on unix epoch
        let nanos_per_slot = config.slot_duration_ms.as_nanos();
        let slots_since_genesis = u64::try_from(
            nanos_since_genesis
                .checked_div(nanos_per_slot)
                .expect("slot duration must be at least one nanosecond"),
        )?;

        let slot = GENESIS_SLOT.saturating_add(slots_since_genesis);

        // Then, determine which tick within that slot
        let nanos_into_slot = u64::try_from(
            nanos_since_genesis
                .checked_rem(nanos_per_slot)
                .expect("slot duration must be at least one nanosecond"),
        )?;

        let duration_into_slot = Duration::from_nanos(nanos_into_slot);

        // The last tick that has already started.
        // Tick offsets grow through the slot, so `take_while` stops at the first future one.
        let kind = TickKind::all_at_slot::<P>(config, slot)
            .take_while(|kind| {
                Self::new(slot, *kind).offset_in_slot::<P>(config) <= duration_into_slot
            })
            .last()
            .expect("the first tick starts at the start of the slot");

        Ok(Self::new(slot, kind))
    }

    /// Time from the start of the slot to the start of this tick.
    ///
    /// Interval starts come from the `*_DUE_BPS` config values.
    /// Each interval is split into `TICKS_PER_INTERVAL` equal ticks.
    #[must_use]
    pub fn offset_in_slot<P: Preset>(self, config: &Config) -> Duration {
        let index = self.kind as u32;

        let interval = index
            .checked_div(TICKS_PER_INTERVAL)
            .expect("TICKS_PER_INTERVAL is not zero");

        let tick_in_interval = index
            .checked_rem(TICKS_PER_INTERVAL)
            .expect("TICKS_PER_INTERVAL is not zero");

        let start = interval_start::<P>(config, self.slot, interval);
        let end = interval_start::<P>(config, self.slot, interval.saturating_add(1));

        let offset_in_interval = end
            .saturating_sub(start)
            .saturating_mul(tick_in_interval)
            .checked_div(TICKS_PER_INTERVAL)
            .expect("TICKS_PER_INTERVAL is not zero");

        start.saturating_add(offset_in_interval)
    }

    /// Whether this tick ends no later than `due_bps` basis points into the slot.
    ///
    /// The tick ends where the next emitted tick starts, not the next tick in the sequence.
    /// The store holds a tick until the stream emits another one.
    #[must_use]
    pub fn ends_by_due_bps<P: Preset>(self, config: &Config, due_bps: u64) -> bool {
        self.emitted_end_offset_in_slot::<P>(config) <= config.slot_component_duration(due_bps)
    }

    /// Whether `due_bps` basis points into the slot fall within this emitted tick.
    ///
    /// Exactly one emitted tick per slot spans each due point.
    /// A due point at the very end of the slot belongs to the last emitted tick.
    #[must_use]
    pub fn spans_due_bps<P: Preset>(self, config: &Config, due_bps: u64) -> bool {
        if !self.is_emitted() {
            return false;
        }

        let due = config.slot_component_duration(due_bps);
        let end = self.emitted_end_offset_in_slot::<P>(config);

        self.offset_in_slot::<P>(config) <= due
            && (due < end || end == config.slot_duration_ms && due == end)
    }

    /// Whether this tick starts exactly `due_bps` basis points into the slot.
    #[must_use]
    pub fn starts_at_due_bps<P: Preset>(self, config: &Config, due_bps: u64) -> bool {
        self.offset_in_slot::<P>(config) == config.slot_component_duration(due_bps)
    }

    // Start-of-interval ticks last until the `*Fourth` tick of the interval.
    // Ending them at the `*Second` tick would make late messages look timely.
    fn emitted_end_offset_in_slot<P: Preset>(self, config: &Config) -> Duration {
        let mut kind = self.kind;

        while let Some(next_kind) = kind.next_at_slot::<P>(config, self.slot) {
            let next_tick = Self::new(self.slot, next_kind);

            if next_tick.is_emitted() {
                return next_tick.offset_in_slot::<P>(config);
            }

            kind = next_kind;
        }

        config.slot_duration_ms
    }

    fn end_offset_in_slot<P: Preset>(self, config: &Config) -> Duration {
        match self.kind.next_at_slot::<P>(config, self.slot) {
            Some(next_kind) => Self::new(self.slot, next_kind).offset_in_slot::<P>(config),
            None => config.slot_duration_ms,
        }
    }

    fn duration<P: Preset>(self, config: &Config) -> Duration {
        self.end_offset_in_slot::<P>(config)
            .saturating_sub(self.offset_in_slot::<P>(config))
    }

    const fn new(slot: Slot, kind: TickKind) -> Self {
        Self { slot, kind }
    }

    fn next<P: Preset>(self, config: &Config) -> Result<Self> {
        let Self { slot, kind } = self;

        let next_slot = match kind.next_at_slot::<P>(config, slot) {
            Some(_) => slot,
            None => slot.checked_add(1).ok_or(ClockError::RanOutOfSlots)?,
        };

        let next_kind = kind.next_cycle_at_slot::<P>(config, slot);

        Ok(Self::new(next_slot, next_kind))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Sequence, AsRefStr, Deserialize)]
pub enum TickKind {
    Propose,
    ProposeSecond,
    ProposeThird,
    ProposeFourth,
    Attest,
    AttestSecond,
    AttestThird,
    AttestFourth,
    Aggregate,
    AggregateSecond,
    AggregateThird,
    AggregateFourth,
    PayloadAttest,
    PayloadAttestSecond,
    PayloadAttestThird,
    PayloadAttestFourth,
}

impl TickKind {
    fn next_at_slot<P: Preset>(self, config: &Config, slot: Slot) -> Option<Self> {
        if config.phase_at_slot::<P>(slot) >= Phase::Gloas {
            self.next()
        } else {
            let current_idx = Self::pre_gloas_ticks().position(|k| k == self)?;
            let next_idx = current_idx.saturating_add(1);

            Self::pre_gloas_ticks().nth(next_idx)
        }
    }

    fn next_cycle_at_slot<P: Preset>(self, config: &Config, slot: Slot) -> Self {
        self.next_at_slot::<P>(config, slot)
            .unwrap_or(Self::Propose)
    }

    /// Returns the number of tick variants in use for a given slot.
    /// Pre-Gloas: 12 ticks (3 intervals * 4 ticks each)
    /// Post-Gloas: 16 ticks (4 intervals * 4 ticks each)
    pub fn ticks_per_slot<P: Preset>(config: &Config, slot: Slot) -> usize {
        if config.phase_at_slot::<P>(slot) >= Phase::Gloas {
            Self::CARDINALITY // 4 intervals of 4 ticks each
        } else {
            Self::pre_gloas_ticks().count() // 3 intervals of 4 ticks each
        }
    }

    fn all_at_slot<P: Preset>(config: &Config, slot: Slot) -> impl Iterator<Item = Self> {
        // Pre-Gloas ticks are a prefix of post-Gloas ones.
        enum_iterator::all::<Self>().take(Self::ticks_per_slot::<P>(config, slot))
    }

    fn pre_gloas_ticks() -> impl Iterator<Item = Self> {
        enum_iterator::all::<Self>().take_while(|t| !matches!(t, Self::PayloadAttest))
    }
}

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum ClockError {
    #[error("time of next tick overflowed")]
    NextInstantOverflow,
    #[error("ran out of slots")]
    RanOutOfSlots,
}

pub fn ticks<P: Preset>(
    config: &Config,
    genesis_time_in_ms: u64,
) -> Result<Pin<Box<dyn Stream<Item = Result<Tick>> + Send + '_>>> {
    // We assume the `Instant` and `SystemTime` obtained here correspond to the same point in time.
    // This is slightly inaccurate but the error will probably be negligible compared to clock
    // differences between different nodes in the network.
    let now_instant = tokio::time::Instant::now();
    let now_system_time = SystemTime::now();

    let (next_tick, next_instant) = next_tick_with_instant::<P, _, _>(
        config,
        now_instant,
        now_system_time,
        genesis_time_in_ms,
        false,
    )?;

    Ok(Box::pin(futures::stream::try_unfold(
        (next_tick, next_instant),
        move |(mut next_tick, mut deadline)| {
            async move {
                loop {
                    tokio::time::sleep_until(deadline).await;

                    let current_tick = next_tick;
                    next_tick = current_tick.next::<P>(config)?;

                    // Tick durations differ between intervals and change at the fork boundary.
                    deadline = deadline
                        .checked_add(current_tick.duration::<P>(config))
                        .ok_or(ClockError::NextInstantOverflow)?;

                    // Emit only ticks that the application currently uses.
                    if current_tick.is_emitted() {
                        return Ok(Some((current_tick, (next_tick, deadline))));
                    }
                }
            }
        },
    )))
}

/// Whether `time` falls in `slot`, less than `due_bps` basis points after its start.
///
/// Mirrors the spec's `time_into_slot_ms < due_ms` for the current slot.
/// `time` is measured from the Unix epoch.
///
/// Use this for deadlines that are not interval starts, like `PAYLOAD_DUE_BPS`.
/// The store only knows the current tick, which cannot place such deadlines exactly.
#[must_use]
pub fn is_before_due_bps_in_slot(
    config: &Config,
    genesis_time: UnixSeconds,
    slot: Slot,
    due_bps: u64,
    time: Duration,
) -> bool {
    let Some(slot_start) = slot_start(config, genesis_time, slot) else {
        return false;
    };

    // A sender whose clock runs ahead may deliver slightly before the slot starts.
    // Gossip accepts that much disparity, so it still counts as timely.
    if time.saturating_add(config.maximum_gossip_clock_disparity) < slot_start {
        return false;
    }

    time.saturating_sub(slot_start) < config.slot_component_duration(due_bps)
}

/// Time left from `time` until `due_bps` basis points into `slot`.
///
/// Zero once the due point has passed.
/// `time` is measured from the Unix epoch.
#[must_use]
pub fn duration_until_due_bps(
    config: &Config,
    genesis_time: UnixSeconds,
    slot: Slot,
    due_bps: u64,
    time: Duration,
) -> Duration {
    slot_start(config, genesis_time, slot)
        .and_then(|slot_start| slot_start.checked_add(config.slot_component_duration(due_bps)))
        .map(|due| due.saturating_sub(time))
        .unwrap_or_default()
}

// Time from the Unix epoch to the start of `slot`.
// `None` if it does not fit in a `Duration`.
fn slot_start(config: &Config, genesis_time: UnixSeconds, slot: Slot) -> Option<Duration> {
    let slots_since_genesis = u32::try_from(slot.saturating_sub(GENESIS_SLOT)).ok()?;

    config
        .slot_duration_ms
        .checked_mul(slots_since_genesis)?
        .checked_add(Duration::from_secs(genesis_time))
}

pub fn next_interval_with_remaining_time<P: Preset>(
    config: &Config,
    genesis_time: UnixSeconds,
) -> Result<(Tick, Duration)> {
    // We assume the `Instant` and `SystemTime` obtained here correspond to the same point in time.
    // This is slightly inaccurate but the error will probably be negligible compared to clock
    // differences between different nodes in the network.
    let now_instant = Instant::now();
    let now_system_time = SystemTime::now();

    let genesis_time_in_ms = genesis_time.saturating_mul(1000);
    let (next_interval, next_instant) = next_tick_with_instant::<P, _, _>(
        config,
        now_instant,
        now_system_time,
        genesis_time_in_ms,
        true,
    )?;

    let remaining_time = next_instant.duration_since(now_instant);

    Ok((next_interval, remaining_time))
}

fn next_tick_with_instant<P: Preset, I: InstantLike, S: SystemTimeLike>(
    config: &Config,
    now_instant: I,
    now_system_time: S,
    genesis_time_in_ms: u64,
    only_interval_ticks: bool,
) -> Result<(Tick, I)> {
    let unix_epoch_to_now = now_system_time.duration_since(S::UNIX_EPOCH)?;

    // Tick now operates in milliseconds, so to prevent precision loss by rounding down to unix seconds,
    // We pass genesis time in milliseconds to prevent rounding error and precision calculation and
    // comparison.
    let unix_epoch_to_genesis = Duration::from_millis(genesis_time_in_ms);

    // Some platforms do not support negative `Instant`s. Operations that would produce an `Instant`
    // corresponding to time before the epoch will panic on those platforms. The epoch in question
    // is not the Unix epoch but a platform dependent value, typically the system boot time.
    // This means we are not allowed to subtract `Duration`s from `Instant`s. The `InstantLike`
    // trait conveniently prevents us from doing so.

    let mut next_tick;
    let mut now_to_next_tick;

    // `consensus-specs` originally did not make it clear whether the number of the first slot after
    // genesis is 0 or 1. We assumed it was 1. That way every slot could have a block proposed in
    // it. Thanks to Lighthouse and several new functions in `consensus-specs`
    // (`compute_time_at_slot` and `get_slots_since_genesis`) we now know it's 0.

    if unix_epoch_to_now <= unix_epoch_to_genesis {
        next_tick = Tick::start_of_slot(GENESIS_SLOT);
        now_to_next_tick = unix_epoch_to_genesis
            .checked_sub(unix_epoch_to_now)
            .expect("the difference from genesis to now fits in Duration");
    } else {
        let genesis_to_now = unix_epoch_to_now
            .checked_sub(unix_epoch_to_genesis)
            .expect("the difference from now to genesis fits in Duration");

        let slots_since_genesis = genesis_to_now
            .as_secs()
            .checked_div(config.slot_duration_ms.as_secs())
            .expect("slot_duration must be at least one second");

        let genesis_to_current_slot = Duration::from_secs(
            slots_since_genesis.saturating_mul(config.slot_duration_ms.as_secs()),
        );

        let current_slot_to_now = genesis_to_now
            .checked_sub(genesis_to_current_slot)
            .expect("the difference from now to current slot fits in Duration");

        next_tick = Tick::start_of_slot(GENESIS_SLOT.saturating_add(slots_since_genesis));
        now_to_next_tick = Duration::ZERO;

        while now_to_next_tick < current_slot_to_now {
            now_to_next_tick = now_to_next_tick.saturating_add(next_tick.duration::<P>(config));
            next_tick = next_tick.next::<P>(config)?;
        }

        if only_interval_ticks {
            while !next_tick.is_start_of_interval() {
                now_to_next_tick = now_to_next_tick.saturating_add(next_tick.duration::<P>(config));
                next_tick = next_tick.next::<P>(config)?;
            }
        }

        now_to_next_tick = now_to_next_tick.saturating_sub(current_slot_to_now);
    }

    let next_instant = now_instant
        .checked_add(now_to_next_tick)
        .ok_or(ClockError::NextInstantOverflow)?;

    Ok((next_tick, next_instant))
}

const TICKS_PER_INTERVAL: u32 = 4;

// `interval` is 0-based.
// One past the last interval is the end of the slot.
fn interval_start<P: Preset>(config: &Config, slot: Slot, interval: u32) -> Duration {
    let phase = config.phase_at_slot::<P>(slot);

    let due_bps = match interval {
        0 => 0,
        1 => config.attestation_due_bps_at(phase),
        2 => config.aggregate_due_bps_at(phase),
        3 if phase >= Phase::Gloas => config.payload_attestation_due_bps,
        _ => BASIS_POINTS,
    };

    config.slot_component_duration(due_bps)
}

#[cfg(test)]
mod tests {
    use core::ops::Add as _;

    use futures::StreamExt as _;
    use futures::future::FutureExt as _;
    use itertools::Itertools as _;
    use test_case::test_case;
    use types::{
        gloas::consts::INTERVALS_PER_SLOT_GLOAS,
        phase0::consts::INTERVALS_PER_SLOT,
        preset::{Mainnet, Minimal},
    };

    use crate::fake_time::{FakeInstant, FakeSystemTime, Timespec};

    use super::*;

    #[test]
    fn tick_count_is_a_multiple_of_interval_count() {
        assert!(
            TickKind::pre_gloas_ticks()
                .count()
                .is_multiple_of(INTERVALS_PER_SLOT.into())
        );
        assert!(TickKind::CARDINALITY.is_multiple_of(INTERVALS_PER_SLOT_GLOAS.into()));
    }

    #[test]
    fn tick_count_is_a_multiple_of_interval_count_pre_gloas() {
        let config = Config::mainnet();
        let slot = GENESIS_SLOT;
        assert!(
            TickKind::ticks_per_slot::<Mainnet>(&config, slot)
                .is_multiple_of(INTERVALS_PER_SLOT.into())
        );
    }

    #[test]
    fn tick_count_is_a_multiple_of_interval_count_post_gloas() {
        let config = Config::mainnet().start_and_stay_in(Phase::Gloas);
        let slot = GENESIS_SLOT;
        assert!(
            TickKind::ticks_per_slot::<Mainnet>(&config, slot)
                .is_multiple_of(INTERVALS_PER_SLOT_GLOAS.into())
        );
    }

    #[test]
    fn tick_count_change_at_fork_boundary() {
        // activate Gloas at epoch 2
        let gloas_fork_epoch = 2;
        let config = Config::mainnet().upgrade_once(Phase::Gloas, gloas_fork_epoch);

        // slot before Gloas fork
        let pre_gloas_slot = 32;
        assert_eq!(
            TickKind::ticks_per_slot::<Mainnet>(&config, pre_gloas_slot),
            12
        );

        // first slot at Gloas fork
        let first_gloas_slot = 64;
        assert_eq!(
            TickKind::ticks_per_slot::<Mainnet>(&config, first_gloas_slot),
            16
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ticks_with_mainnet_config_produces_a_tick_every_second_pre_gloas() -> Result<()> {
        let genesis_time_in_ms = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis()
                .add(1000),
        )
        .expect("genesis_time_in_ms should fit in u64");

        let config = Config::mainnet();
        let mut ticks = ticks::<Mainnet>(&config, genesis_time_in_ms)?;
        let mut next_tick = || ticks.next().now_or_never().flatten().transpose();

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::Propose)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::ProposeFourth)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::Attest)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::AttestFourth)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::Aggregate)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::AggregateFourth)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(1, TickKind::Propose)));
        assert_eq!(next_tick()?, None);

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn ticks_adjusts_duration_at_gloas_fork() -> Result<()> {
        // This setup activates Gloas fork at epoch 1 with mainnet preset
        let config = Config::mainnet().upgrade_once(Phase::Gloas, 1);
        let one_second_duration = Duration::from_secs(1);
        let post_gloas_tick_duration = Duration::from_millis(750);

        // Genesis is 1 second from now
        let genesis_time_in_ms = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis()
                .add(1000),
        )
        .expect("genesis_time_in_ms should fit in u64");

        let mut ticks = ticks::<Mainnet>(&config, genesis_time_in_ms)?;

        assert_eq!(next_tick(&mut ticks)?, None);

        // Advance to genesis slot
        tokio::time::advance(one_second_duration).await;
        assert_eq!(
            next_tick(&mut ticks)?,
            Some(Tick::new(0, TickKind::Propose))
        );

        // Fast-forward through slots 0-31 (pre-Gloas)
        // Each slot is 12 000 ms.
        // Its 12 ticks follow the `*_DUE_BPS` values, so they are only roughly 1000 ms apart.
        // We skip 31 slots and 11 ticks in bulk and drain the stream.
        tokio::time::advance(Duration::from_secs(32 * 12 - 2)).await;
        drain(&mut ticks).await?;

        // Last tick in slot 31 (pre-Gloas)
        tokio::time::advance(one_second_duration).await;
        assert_eq!(
            next_tick(&mut ticks)?,
            Some(Tick::new(31, TickKind::AggregateFourth))
        );
        assert_eq!(next_tick(&mut ticks)?, None);

        // Fork transition to Gloas at slot 32
        // tokio::time::advance(one_second_duration).await;
        tokio::time::advance(post_gloas_tick_duration).await;
        assert_eq!(
            next_tick(&mut ticks)?,
            None,
            "Propose tick at slot 32 should not appear yet"
        );

        tokio::time::advance(Duration::from_millis(250)).await;
        assert_eq!(
            next_tick(&mut ticks)?,
            Some(Tick::new(32, TickKind::Propose))
        );
        assert_eq!(next_tick(&mut ticks)?, None);

        // Advance to next tick by 750ms (post-Gloas)
        tokio::time::advance(post_gloas_tick_duration).await;
        assert_eq!(next_tick(&mut ticks)?, None); // ProposeSecond

        tokio::time::advance(post_gloas_tick_duration).await;
        assert_eq!(next_tick(&mut ticks)?, None); // ProposeThird

        // End of propose interval (post-Gloas)
        tokio::time::advance(post_gloas_tick_duration).await;
        assert_eq!(
            next_tick(&mut ticks)?,
            Some(Tick::new(32, TickKind::ProposeFourth))
        );
        assert_eq!(next_tick(&mut ticks)?, None);

        // Then, Start of attest interval
        tokio::time::advance(post_gloas_tick_duration).await;
        assert_eq!(
            next_tick(&mut ticks)?,
            Some(Tick::new(32, TickKind::Attest))
        );
        assert_eq!(next_tick(&mut ticks)?, None);

        // ── Regression guard: advancing only 250 ms more must NOT emit anything ───
        // Under the old bug the interval would have fired at the 1000 ms mark (250 ms after Attest), producing a spurious tick.
        tokio::time::advance(Duration::from_millis(250)).await;
        assert_eq!(
            next_tick(&mut ticks)?,
            None,
            "spurious tick at old 1000 ms boundary must not appear post-fork"
        );

        Ok(())
    }

    // The stream must fire duty ticks at the `*_DUE_BPS` offsets, not at an equal split.
    // Checks a margin before and after each tick.
    // The margin absorbs the sub-millisecond gap between the genesis time and `SystemTime::now`.
    #[tokio::test(start_paused = true)]
    async fn ticks_follow_due_bps_post_gloas() -> Result<()> {
        let margin = Duration::from_millis(10);

        let genesis_time_in_ms = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis()
                .add(1000),
        )
        .expect("genesis_time_in_ms should fit in u64");

        let config = custom_due_bps_config();
        let mut ticks = ticks::<Mainnet>(&config, genesis_time_in_ms)?;

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(
            next_tick(&mut ticks)?,
            Some(Tick::new(0, TickKind::Propose))
        );

        let mut elapsed = Duration::ZERO;

        for (offset_in_ms, expected_tick) in [
            (1800, Tick::new(0, TickKind::ProposeFourth)),
            (2400, Tick::new(0, TickKind::Attest)),
            (4200, Tick::new(0, TickKind::AttestFourth)),
            (4800, Tick::new(0, TickKind::Aggregate)),
            (8400, Tick::new(0, TickKind::AggregateFourth)),
            (9600, Tick::new(0, TickKind::PayloadAttest)),
            (11_400, Tick::new(0, TickKind::PayloadAttestFourth)),
            (12_000, Tick::new(1, TickKind::Propose)),
        ] {
            let offset = Duration::from_millis(offset_in_ms);

            tokio::time::advance(offset.saturating_sub(elapsed).saturating_sub(margin)).await;

            assert_eq!(
                next_tick(&mut ticks)?,
                None,
                "{expected_tick:?} fired before {offset_in_ms} ms",
            );

            tokio::time::advance(margin.saturating_mul(2)).await;

            assert_eq!(
                next_tick(&mut ticks)?,
                Some(expected_tick),
                "{expected_tick:?} did not fire at {offset_in_ms} ms",
            );

            assert_eq!(next_tick(&mut ticks)?, None);

            elapsed = offset.saturating_add(margin);
        }

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn ticks_with_mainnet_config_iterate_through_every_tick_post_gloas() -> Result<()> {
        let genesis_time_in_ms = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis()
                .add(1000),
        )
        .expect("genesis_time_in_ms should fit in u64");

        let config = Config::mainnet().start_and_stay_in(Phase::Gloas);
        let tick_duration = Duration::from_millis(750);
        let mut ticks = ticks::<Mainnet>(&config, genesis_time_in_ms)?;
        let mut next_tick = || ticks.next().now_or_never().flatten().transpose();

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::Propose)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::ProposeFourth)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::Attest)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::AttestFourth)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::Aggregate)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::AggregateFourth)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::PayloadAttest)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(
            next_tick()?,
            Some(Tick::new(0, TickKind::PayloadAttestFourth))
        );
        assert_eq!(next_tick()?, None);

        tokio::time::advance(tick_duration).await;

        assert_eq!(next_tick()?, Some(Tick::new(1, TickKind::Propose)));
        assert_eq!(next_tick()?, None);

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn ticks_starts_with_tick_at_end_of_interval_when_just_past_genesis() -> Result<()> {
        let genesis_time_in_ms = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis(),
        )
        .expect("genesis_time_in_ms should fit in u64");

        let config = Config::mainnet();
        let mut ticks = ticks::<Mainnet>(&config, genesis_time_in_ms)?;
        let mut next_tick = || ticks.next().now_or_never().flatten().transpose();

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::ProposeFourth)));
        assert_eq!(next_tick()?, None);

        tokio::time::advance(Duration::from_secs(1)).await;

        assert_eq!(next_tick()?, Some(Tick::new(0, TickKind::Attest)));
        assert_eq!(next_tick()?, None);

        Ok(())
    }

    #[tokio::test]
    async fn ticks_does_not_panic() {
        let configs = [
            config_with_slot_duration(Duration::from_secs(1)),
            config_with_slot_duration(Duration::from_secs(2)),
            config_with_slot_duration(Duration::from_secs(3)),
            Config::minimal(),
            Config::mainnet(),
            config_with_slot_duration(Duration::from_secs(18)),
        ];

        let genesis_times = [
            UnixSeconds::MIN,
            777_000,
            UnixSeconds::MAX - 3,
            UnixSeconds::MAX - 2,
            UnixSeconds::MAX - 1,
            UnixSeconds::MAX,
        ];

        for (config, genesis_time_in_ms) in configs.iter().cartesian_product(genesis_times) {
            ticks::<Mainnet>(config, genesis_time_in_ms).ok();
        }
    }

    #[tokio::test]
    async fn ticks_does_not_panic_post_gloas() {
        let configs = [
            config_with_slot_duration(Duration::from_secs(1)).start_and_stay_in(Phase::Gloas),
            config_with_slot_duration(Duration::from_secs(2)).start_and_stay_in(Phase::Gloas),
            config_with_slot_duration(Duration::from_secs(3)).start_and_stay_in(Phase::Gloas),
            Config::minimal().start_and_stay_in(Phase::Gloas),
            Config::mainnet().start_and_stay_in(Phase::Gloas),
            config_with_slot_duration(Duration::from_secs(18)).start_and_stay_in(Phase::Gloas),
        ];

        let genesis_times = [
            UnixSeconds::MIN,
            777_000,
            UnixSeconds::MAX - 3,
            UnixSeconds::MAX - 2,
            UnixSeconds::MAX - 1,
            UnixSeconds::MAX,
        ];

        for (config, genesis_time_in_ms) in configs.iter().cartesian_product(genesis_times) {
            ticks::<Mainnet>(config, genesis_time_in_ms).ok();
        }
    }

    #[test_case(-24 => Tick::new(0, TickKind::Propose);             "24 seconds before genesis")]
    #[test_case(-12 => Tick::new(0, TickKind::Propose);             "12 seconds before genesis")]
    #[test_case( -1 => Tick::new(0, TickKind::Propose);             "1 second before genesis")]
    #[test_case(  0 => Tick::new(0, TickKind::Propose);             "at genesis")]
    #[test_case(  1 => Tick::new(0, TickKind::ProposeSecond);       "1 second after genesis")]
    #[test_case(  2 => Tick::new(0, TickKind::ProposeThird);        "2 second after genesis")]
    #[test_case(  3 => Tick::new(0, TickKind::ProposeFourth);       "3 seconds after genesis")]
    #[test_case(  4 => Tick::new(0, TickKind::Attest);              "4 seconds after genesis")]
    #[test_case(  5 => Tick::new(0, TickKind::AttestSecond);        "5 seconds after genesis")]
    #[test_case(  6 => Tick::new(0, TickKind::AttestThird);         "6 seconds after genesis")]
    #[test_case(  7 => Tick::new(0, TickKind::AttestFourth);        "7 seconds after genesis")]
    #[test_case(  8 => Tick::new(0, TickKind::Aggregate);           "8 seconds after genesis")]
    #[test_case(  9 => Tick::new(0, TickKind::AggregateSecond);     "9 seconds after genesis")]
    #[test_case( 10 => Tick::new(0, TickKind::AggregateThird);      "10 seconds after genesis")]
    #[test_case( 11 => Tick::new(0, TickKind::AggregateFourth);     "11 seconds after genesis")]
    #[test_case( 12 => Tick::new(1, TickKind::Propose);             "12 seconds after genesis")]
    #[test_case( 13 => Tick::new(1, TickKind::ProposeSecond);       "13 seconds after genesis")]
    #[test_case( 24 => Tick::new(2, TickKind::Propose);             "24 seconds after genesis")]
    #[test_case(384 => Tick::new(32, TickKind::Propose);            "at Gloas fork")]
    #[test_case(385 => Tick::new(32, TickKind::ProposeSecond);      "1 seconds after Gloas fork")]
    #[test_case(386 => Tick::new(32, TickKind::ProposeThird);       "2 seconds after Gloas fork")]
    #[test_case(387 => Tick::new(32, TickKind::Attest);             "3 seconds after Gloas fork")]
    #[test_case(388 => Tick::new(32, TickKind::AttestSecond);       "4 seconds after Gloas fork")]
    #[test_case(389 => Tick::new(32, TickKind::AttestThird);        "5 seconds after Gloas fork")]
    #[test_case(390 => Tick::new(32, TickKind::Aggregate);          "6 seconds after Gloas fork")]
    #[test_case(391 => Tick::new(32, TickKind::AggregateSecond);    "7 seconds after Gloas fork")]
    #[test_case(392 => Tick::new(32, TickKind::AggregateThird);     "8 seconds after Gloas fork")]
    #[test_case(393 => Tick::new(32, TickKind::PayloadAttest);      "9 seconds after Glaos fork")]
    #[test_case(394 => Tick::new(32, TickKind::PayloadAttestSecond); "10 seconds after Glaos fork")]
    #[test_case(395 => Tick::new(32, TickKind::PayloadAttestThird); "11 seconds after Glaos fork")]
    #[test_case(396 => Tick::new(33, TickKind::Propose);            "12 seconds after Glaos fork")]
    fn tick_at_time_relative_to_genesis_with_mainnet_config(offset: i64) -> Tick {
        tick_at_time_relative_to_genesis::<Mainnet>(
            &Config::mainnet().upgrade_once(Phase::Gloas, 1),
            offset,
        )
    }

    #[test_case(    0 => Tick::new(0, TickKind::Propose);               "at genesis")]
    #[test_case(  750 => Tick::new(0, TickKind::ProposeSecond);         "0.75 seconds after genesis")]
    #[test_case( 1500 => Tick::new(0, TickKind::ProposeThird);          "1.50 seconds after genesis")]
    #[test_case( 2250 => Tick::new(0, TickKind::ProposeFourth);         "2.25 seconds after genesis")]
    #[test_case( 3000 => Tick::new(0, TickKind::Attest);                "3.00 seconds after genesis")]
    #[test_case( 3750 => Tick::new(0, TickKind::AttestSecond);          "3.75 seconds after genesis")]
    #[test_case( 4500 => Tick::new(0, TickKind::AttestThird);           "4.50 seconds after genesis")]
    #[test_case( 5250 => Tick::new(0, TickKind::AttestFourth);          "5.25 seconds after genesis")]
    #[test_case( 6000 => Tick::new(0, TickKind::Aggregate);             "6.00 seconds after genesis")]
    #[test_case( 6750 => Tick::new(0, TickKind::AggregateSecond);       "6.75 seconds after genesis")]
    #[test_case( 7500 => Tick::new(0, TickKind::AggregateThird);        "7.50 seconds after genesis")]
    #[test_case( 8250 => Tick::new(0, TickKind::AggregateFourth);       "8.25 seconds after genesis")]
    #[test_case( 9000 => Tick::new(0, TickKind::PayloadAttest);         "9.00 seconds after genesis")]
    #[test_case( 9750 => Tick::new(0, TickKind::PayloadAttestSecond);   "9.75 seconds after genesis")]
    #[test_case(10500 => Tick::new(0, TickKind::PayloadAttestThird);    "10.50 seconds after genesis")]
    #[test_case(11250 => Tick::new(0, TickKind::PayloadAttestFourth);   "11.25 seconds after genesis")]
    #[test_case(12000 => Tick::new(1, TickKind::Propose);               "12.00 seconds after genesis")]
    #[test_case(24000 => Tick::new(2, TickKind::Propose);               "24.00 seconds after genesis")]
    fn tick_at_time_millis_relative_to_genesis_with_mainnet_config_post_gloas(
        offset: i128,
    ) -> Tick {
        tick_at_time_millis_relative_to_genesis::<Mainnet>(
            &Config::mainnet().start_and_stay_in(Phase::Gloas),
            offset,
        )
    }

    #[test_case(-12 => Tick::new(0, TickKind::Propose);             "12 seconds before genesis")]
    #[test_case( -6 => Tick::new(0, TickKind::Propose);             "6 seconds before genesis")]
    #[test_case( -1 => Tick::new(0, TickKind::Propose);             "1 second before genesis")]
    #[test_case(  0 => Tick::new(0, TickKind::Propose);             "at genesis")]
    #[test_case(  1 => Tick::new(0, TickKind::ProposeThird);        "1 second after genesis")]
    #[test_case(  2 => Tick::new(0, TickKind::Attest);              "2 seconds after genesis")]
    #[test_case(  3 => Tick::new(0, TickKind::AttestThird);         "3 seconds after genesis")]
    #[test_case(  4 => Tick::new(0, TickKind::Aggregate);           "4 seconds after genesis")]
    #[test_case(  5 => Tick::new(0, TickKind::AggregateThird);      "5 seconds after genesis")]
    #[test_case(  6 => Tick::new(1, TickKind::Propose);             "6 seconds after genesis")]
    #[test_case(  7 => Tick::new(1, TickKind::ProposeThird);        "7 seconds after genesis")]
    #[test_case( 12 => Tick::new(2, TickKind::Propose);             "12 seconds after genesis")]
    #[test_case( 48 => Tick::new(8, TickKind::Propose);             "at Gloas fork")]
    #[test_case( 49 => Tick::new(8, TickKind::ProposeThird);        "1 seconds after Gloas fork")]
    #[test_case( 50 => Tick::new(8, TickKind::AttestSecond);        "2 seconds after Gloas fork")]
    #[test_case( 51 => Tick::new(8, TickKind::Aggregate);           "3 seconds after Gloas fork")]
    #[test_case( 52 => Tick::new(8, TickKind::AggregateThird);      "4 seconds after Gloas fork")]
    #[test_case( 53 => Tick::new(8, TickKind::PayloadAttestSecond); "5 seconds after Gloas fork")]
    #[test_case( 54 => Tick::new(9, TickKind::Propose);             "6 seconds after Gloas fork")]
    #[test_case( 55 => Tick::new(9, TickKind::ProposeThird);        "7 seconds after Gloas fork")]
    #[test_case( 60 => Tick::new(10, TickKind::Propose);            "12 seconds after Gloas fork")]
    fn tick_at_time_relative_to_genesis_with_minimal_config(offset: i64) -> Tick {
        tick_at_time_relative_to_genesis::<Minimal>(
            &Config::minimal().upgrade_once(Phase::Gloas, 1),
            offset,
        )
    }

    #[test_case(    0 => Tick::new(0, TickKind::Propose);               "at genesis")]
    #[test_case(  375 => Tick::new(0, TickKind::ProposeSecond);         "0.375 seconds after genesis")]
    #[test_case(  750 => Tick::new(0, TickKind::ProposeThird);          "0.750 seconds after genesis")]
    #[test_case( 1125 => Tick::new(0, TickKind::ProposeFourth);         "1.125 seconds after genesis")]
    #[test_case( 1500 => Tick::new(0, TickKind::Attest);                "1.500 seconds after genesis")]
    #[test_case( 1875 => Tick::new(0, TickKind::AttestSecond);          "1.875 seconds after genesis")]
    #[test_case( 2250 => Tick::new(0, TickKind::AttestThird);           "2.250 seconds after genesis")]
    #[test_case( 2625 => Tick::new(0, TickKind::AttestFourth);          "2.625 seconds after genesis")]
    #[test_case( 3000 => Tick::new(0, TickKind::Aggregate);             "3.000 seconds after genesis")]
    #[test_case( 3375 => Tick::new(0, TickKind::AggregateSecond);       "3.375 seconds after genesis")]
    #[test_case( 3750 => Tick::new(0, TickKind::AggregateThird);        "3.750 seconds after genesis")]
    #[test_case( 4125 => Tick::new(0, TickKind::AggregateFourth);       "4.125 seconds after genesis")]
    #[test_case( 4500 => Tick::new(0, TickKind::PayloadAttest);         "4.500 seconds after genesis")]
    #[test_case( 4875 => Tick::new(0, TickKind::PayloadAttestSecond);   "4.875 seconds after genesis")]
    #[test_case( 5250 => Tick::new(0, TickKind::PayloadAttestThird);    "5.250 seconds after genesis")]
    #[test_case( 5625 => Tick::new(0, TickKind::PayloadAttestFourth);   "5.625 seconds after genesis")]
    #[test_case( 6000 => Tick::new(1, TickKind::Propose);               "6.000 seconds after genesis")]
    #[test_case(12000 => Tick::new(2, TickKind::Propose);               "12.000 seconds after genesis")]
    fn tick_at_time_millis_relative_to_genesis_with_minimal_config_post_gloas(
        offset: i128,
    ) -> Tick {
        tick_at_time_millis_relative_to_genesis::<Minimal>(
            &Config::minimal().start_and_stay_in(Phase::Gloas),
            offset,
        )
    }

    #[test_case(100 => (777_000, Tick::new(0, TickKind::Propose));         "long before genesis")]
    #[test_case(777 => (777_000, Tick::new(0, TickKind::Propose));         "at genesis")]
    #[test_case(778 => (778_999, Tick::new(0, TickKind::ProposeThird));    "1 second after genesis")]
    #[test_case(779 => (779_999, Tick::new(0, TickKind::ProposeFourth));   "2 seconds after genesis")]
    #[test_case(780 => (780_999, Tick::new(0, TickKind::Attest));          "3 seconds after genesis")]
    #[test_case(781 => (781_999, Tick::new(0, TickKind::AttestSecond));    "4 seconds after genesis")]
    #[test_case(782 => (782_999, Tick::new(0, TickKind::AttestThird));     "5 seconds after genesis")]
    #[test_case(783 => (783_999, Tick::new(0, TickKind::AttestFourth));    "6 seconds after genesis")]
    #[test_case(784 => (785_000, Tick::new(0, TickKind::Aggregate));       "7 seconds after genesis")]
    #[test_case(785 => (785_000, Tick::new(0, TickKind::Aggregate));       "8 seconds after genesis")]
    #[test_case(786 => (786_000, Tick::new(0, TickKind::AggregateSecond)); "9 seconds after genesis")]
    #[test_case(787 => (787_000, Tick::new(0, TickKind::AggregateThird));  "10 seconds after genesis")]
    #[test_case(788 => (788_000, Tick::new(0, TickKind::AggregateFourth)); "11 seconds after genesis")]
    #[test_case(789 => (789_000, Tick::new(1, TickKind::Propose));         "12 seconds after genesis")]
    fn next_tick_with_instant_with_mainnet_config(time: UnixSeconds) -> (u64, Tick) {
        next_tick_with_instant::<Mainnet>(&Config::mainnet(), time, false)
    }

    #[test_case(100 => (777_000, Tick::new(0, TickKind::Propose));   "long before genesis")]
    #[test_case(777 => (777_000, Tick::new(0, TickKind::Propose));   "at genesis")]
    #[test_case(778 => (780_999, Tick::new(0, TickKind::Attest));    "1 second after genesis")]
    #[test_case(779 => (780_999, Tick::new(0, TickKind::Attest));    "2 seconds after genesis")]
    #[test_case(780 => (780_999, Tick::new(0, TickKind::Attest));    "3 seconds after genesis")]
    #[test_case(781 => (785_000, Tick::new(0, TickKind::Aggregate)); "4 seconds after genesis")]
    #[test_case(782 => (785_000, Tick::new(0, TickKind::Aggregate)); "5 seconds after genesis")]
    #[test_case(783 => (785_000, Tick::new(0, TickKind::Aggregate)); "6 seconds after genesis")]
    #[test_case(784 => (785_000, Tick::new(0, TickKind::Aggregate)); "7 seconds after genesis")]
    #[test_case(785 => (785_000, Tick::new(0, TickKind::Aggregate)); "8 seconds after genesis")]
    #[test_case(786 => (789_000, Tick::new(1, TickKind::Propose));   "9 seconds after genesis")]
    #[test_case(787 => (789_000, Tick::new(1, TickKind::Propose));   "10 seconds after genesis")]
    #[test_case(788 => (789_000, Tick::new(1, TickKind::Propose));   "11 seconds after genesis")]
    #[test_case(789 => (789_000, Tick::new(1, TickKind::Propose));   "12 seconds after genesis")]
    fn next_tick_with_instant_with_mainnet_config_only_interval_ticks_pre_gloas(
        time: UnixSeconds,
    ) -> (u64, Tick) {
        next_tick_with_instant::<Mainnet>(&Config::mainnet(), time, true)
    }

    #[test_case(100 => (777_000, Tick::new(0, TickKind::Propose));       "long before genesis")]
    #[test_case(777 => (777_000, Tick::new(0, TickKind::Propose));       "at genesis")]
    #[test_case(778 => (780_000, Tick::new(0, TickKind::Attest));        "1 second after genesis")]
    #[test_case(779 => (780_000, Tick::new(0, TickKind::Attest));        "2 seconds after genesis")]
    #[test_case(780 => (780_000, Tick::new(0, TickKind::Attest));        "3 seconds after genesis")]
    #[test_case(781 => (783_000, Tick::new(0, TickKind::Aggregate));     "4 seconds after genesis")]
    #[test_case(782 => (783_000, Tick::new(0, TickKind::Aggregate));     "5 seconds after genesis")]
    #[test_case(783 => (783_000, Tick::new(0, TickKind::Aggregate));     "6 seconds after genesis")]
    #[test_case(784 => (786_000, Tick::new(0, TickKind::PayloadAttest)); "7 seconds after genesis")]
    #[test_case(785 => (786_000, Tick::new(0, TickKind::PayloadAttest)); "8 seconds after genesis")]
    #[test_case(786 => (786_000, Tick::new(0, TickKind::PayloadAttest)); "9 seconds after genesis")]
    #[test_case(787 => (789_000, Tick::new(1, TickKind::Propose));       "10 seconds after genesis")]
    #[test_case(788 => (789_000, Tick::new(1, TickKind::Propose));       "11 seconds after genesis")]
    #[test_case(789 => (789_000, Tick::new(1, TickKind::Propose));       "12 seconds after genesis")]
    fn next_tick_with_instant_with_mainnet_config_only_interval_ticks_post_gloas(
        time: UnixSeconds,
    ) -> (u64, Tick) {
        next_tick_with_instant::<Mainnet>(
            &Config::mainnet().start_and_stay_in(Phase::Gloas),
            time,
            true,
        )
    }

    #[test_case(100 => (777_000, Tick::new(0, TickKind::Propose));        "long before genesis")]
    #[test_case(777 => (777_000, Tick::new(0, TickKind::Propose));        "at genesis")]
    #[test_case(778 => (778_499, Tick::new(0, TickKind::ProposeFourth));  "1 second after genesis")]
    #[test_case(779 => (779_499, Tick::new(0, TickKind::AttestSecond));   "2 seconds after genesis")]
    #[test_case(780 => (780_499, Tick::new(0, TickKind::AttestFourth));   "3 seconds after genesis")]
    #[test_case(781 => (781_000, Tick::new(0, TickKind::Aggregate));      "4 seconds after genesis")]
    #[test_case(782 => (782_000, Tick::new(0, TickKind::AggregateThird)); "5 seconds after genesis")]
    #[test_case(783 => (783_000, Tick::new(1, TickKind::Propose));        "6 seconds after genesis")]
    fn next_tick_with_instant_with_minimal_config(time: UnixSeconds) -> (u64, Tick) {
        next_tick_with_instant::<Minimal>(&Config::minimal(), time, false)
    }

    #[test_case(100 => (777_000, Tick::new(0, TickKind::Propose));   "long before genesis")]
    #[test_case(777 => (777_000, Tick::new(0, TickKind::Propose));   "at genesis")]
    #[test_case(778 => (778_999, Tick::new(0, TickKind::Attest));    "1 second after genesis")]
    #[test_case(779 => (781_000, Tick::new(0, TickKind::Aggregate)); "2 seconds after genesis")]
    #[test_case(780 => (781_000, Tick::new(0, TickKind::Aggregate)); "3 seconds after genesis")]
    #[test_case(781 => (781_000, Tick::new(0, TickKind::Aggregate)); "4 seconds after genesis")]
    #[test_case(782 => (783_000, Tick::new(1, TickKind::Propose));   "5 seconds after genesis")]
    #[test_case(783 => (783_000, Tick::new(1, TickKind::Propose));   "6 seconds after genesis")]
    fn next_tick_with_instant_with_minimal_config_only_interval_ticks(
        time: UnixSeconds,
    ) -> (u64, Tick) {
        next_tick_with_instant::<Minimal>(&Config::minimal(), time, true)
    }

    // `ATTESTATION_DUE_BPS` is 3333, so the first interval is slightly shorter than a third.
    #[test_case(Duration::from_secs(3) => Duration::from_micros(249_750))]
    #[test_case(Config::minimal().slot_duration_ms => Duration::from_micros(499_750))]
    #[test_case(Config::mainnet().slot_duration_ms => Duration::from_micros(999_750))]
    #[test_case(Duration::from_secs(18) => Duration::from_micros(1_499_750))]
    fn tick_duration_with_custom_slot_duration_pre_gloas(slot_duration: Duration) -> Duration {
        let config = config_with_slot_duration(slot_duration);
        Tick::start_of_slot(GENESIS_SLOT).duration::<Mainnet>(&config)
    }

    #[test_case(Duration::from_secs(2) => Duration::from_millis(125))]
    #[test_case(Duration::from_secs(4) => Duration::from_millis(250))]
    #[test_case(Config::minimal().slot_duration_ms => Duration::from_millis(375))]
    #[test_case(Duration::from_secs(8) => Duration::from_millis(500))]
    #[test_case(Config::mainnet().slot_duration_ms => Duration::from_millis(750))]
    #[test_case(Duration::from_secs(16) => Duration::from_secs(1))]
    #[test_case(Duration::from_secs(18) => Duration::from_millis(1125))]
    fn tick_duration_with_seconds_per_slot_post_gloas(slot_duration: Duration) -> Duration {
        let config = config_with_slot_duration(slot_duration).start_and_stay_in(Phase::Gloas);
        Tick::start_of_slot(GENESIS_SLOT).duration::<Mainnet>(&config)
    }

    // Duty ticks follow the `*_DUE_BPS` config values.
    // They are not a fixed split of the slot.
    #[test_case(TickKind::Propose             => Duration::ZERO)]
    #[test_case(TickKind::ProposeSecond       => Duration::from_millis(600))]
    #[test_case(TickKind::Attest              => Duration::from_millis(2400))]
    #[test_case(TickKind::AttestSecond        => Duration::from_millis(3000))]
    #[test_case(TickKind::Aggregate           => Duration::from_millis(4800))]
    #[test_case(TickKind::PayloadAttest       => Duration::from_millis(9600))]
    #[test_case(TickKind::PayloadAttestFourth => Duration::from_millis(11_400))]
    fn offset_in_slot_follows_due_bps_post_gloas(kind: TickKind) -> Duration {
        Tick::new(GENESIS_SLOT, kind).offset_in_slot::<Mainnet>(&custom_due_bps_config())
    }

    #[test_case(    0 => Tick::new(0, TickKind::Propose);             "at genesis")]
    #[test_case( 2399 => Tick::new(0, TickKind::ProposeFourth);       "just before attestation due")]
    #[test_case( 2400 => Tick::new(0, TickKind::Attest);              "at attestation due")]
    #[test_case( 4800 => Tick::new(0, TickKind::Aggregate);           "at aggregate due")]
    #[test_case( 9599 => Tick::new(0, TickKind::AggregateFourth);     "just before payload attestation due")]
    #[test_case( 9600 => Tick::new(0, TickKind::PayloadAttest);       "at payload attestation due")]
    #[test_case(12000 => Tick::new(1, TickKind::Propose);             "at next slot")]
    fn tick_at_time_follows_due_bps_post_gloas(offset: i128) -> Tick {
        tick_at_time_millis_relative_to_genesis::<Mainnet>(&custom_due_bps_config(), offset)
    }

    #[test_case(778 => (779_400, Tick::new(0, TickKind::Attest));        "before attestation due")]
    #[test_case(780 => (781_800, Tick::new(0, TickKind::Aggregate));     "before aggregate due")]
    #[test_case(782 => (786_600, Tick::new(0, TickKind::PayloadAttest)); "before payload attestation due")]
    fn next_interval_follows_due_bps_post_gloas(time: UnixSeconds) -> (u64, Tick) {
        next_tick_with_instant::<Mainnet>(&custom_due_bps_config(), time, true)
    }

    // A tick meets a deadline only if it ends by it.
    // Start-of-interval ticks end at the `*Fourth` tick, the next one the stream emits.
    // `Aggregate` runs from 4800 to 8400 ms, so 5000 bps (6000 ms) falls inside it.
    #[test_case(TickKind::ProposeFourth,   2000 => true)]
    #[test_case(TickKind::Attest,          2000 => false)]
    #[test_case(TickKind::Aggregate,       5000 => false; "mid-interval due point")]
    #[test_case(TickKind::Aggregate,       7000 => true;  "due point at the end of the emitted tick")]
    #[test_case(TickKind::AggregateFourth, 8000 => true)]
    #[test_case(TickKind::PayloadAttest,   8000 => false)]
    fn ends_by_due_bps_follows_due_bps_post_gloas(kind: TickKind, due_bps: u64) -> bool {
        Tick::new(GENESIS_SLOT, kind).ends_by_due_bps::<Mainnet>(&custom_due_bps_config(), due_bps)
    }

    // Arrival time decides, not the tick.
    // 5000 bps of a 12 s slot is 6000 ms.
    // In `custom_due_bps_config` that is inside the `Aggregate` tick, which runs from 4800 to 8400 ms.
    // Genesis is at 777 s, so slot 2 starts at 801 s.
    // Gossip clock disparity is 500 ms.
    #[test_case(2, 801_000 => true;  "at slot start")]
    #[test_case(2, 806_000 => true;  "inside the aggregate tick, before the due point")]
    #[test_case(2, 806_999 => true;  "1 ms before the due point")]
    #[test_case(2, 807_000 => false; "at the due point")]
    #[test_case(2, 812_999 => false; "end of slot")]
    #[test_case(2, 800_500 => true;  "early by the clock disparity")]
    #[test_case(2, 800_499 => false; "earlier than the clock disparity")]
    #[test_case(1, 801_000 => false; "after the slot ends")]
    fn is_before_due_bps_in_slot_uses_arrival_time(slot: Slot, time_in_ms: u64) -> bool {
        is_before_due_bps_in_slot(
            &custom_due_bps_config(),
            777,
            slot,
            5000,
            Duration::from_millis(time_in_ms),
        )
    }

    // `Slot::MAX` fails the slot conversion.
    // `u64::MAX` genesis gets past it and overflows the slot start.
    #[test_case(777,      Slot::MAX;              "slot too large")]
    #[test_case(u64::MAX, Slot::from(u32::MAX);   "slot start overflows")]
    fn due_bps_helpers_do_not_overflow(genesis_time: UnixSeconds, slot: Slot) {
        let config = custom_due_bps_config();

        assert!(!is_before_due_bps_in_slot(
            &config,
            genesis_time,
            slot,
            5000,
            Duration::MAX,
        ));

        assert_eq!(
            duration_until_due_bps(&config, genesis_time, slot, 5000, Duration::ZERO),
            Duration::ZERO,
        );
    }

    #[test_case(800_000 => Duration::from_millis(7000); "before the slot")]
    #[test_case(805_000 => Duration::from_millis(2000); "before the due point")]
    #[test_case(807_000 => Duration::ZERO;              "at the due point")]
    #[test_case(808_000 => Duration::ZERO;              "after the due point")]
    fn duration_until_due_bps_counts_down_to_the_due_point(time_in_ms: u64) -> Duration {
        duration_until_due_bps(
            &custom_due_bps_config(),
            777,
            2,
            5000,
            Duration::from_millis(time_in_ms),
        )
    }

    // Each due point falls in exactly one emitted tick.
    // `custom_due_bps_config` emits ticks at 0, 1800, 2400, 4200, 4800, 8400, 9600 and 11 400 ms.
    #[test_case(0     => vec![TickKind::Propose];             "slot start")]
    #[test_case(1000  => vec![TickKind::Propose];             "inside the first tick")]
    #[test_case(2000  => vec![TickKind::Attest];              "attestation due point")]
    #[test_case(5000  => vec![TickKind::Aggregate];           "inside the aggregate tick")]
    #[test_case(7500  => vec![TickKind::AggregateFourth];     "inside the end of the aggregate interval")]
    #[test_case(10000 => vec![TickKind::PayloadAttestFourth]; "slot end")]
    fn exactly_one_emitted_tick_spans_a_due_point(due_bps: u64) -> Vec<TickKind> {
        let config = custom_due_bps_config();

        TickKind::all_at_slot::<Mainnet>(&config, GENESIS_SLOT)
            .filter(|kind| {
                Tick::new(GENESIS_SLOT, *kind).spans_due_bps::<Mainnet>(&config, due_bps)
            })
            .collect()
    }

    fn custom_due_bps_config() -> Config {
        Config {
            attestation_due_bps_gloas: 2000,
            aggregate_due_bps_gloas: 4000,
            payload_attestation_due_bps: 8000,
            ..Config::mainnet().start_and_stay_in(Phase::Gloas)
        }
    }

    fn tick_at_time_relative_to_genesis<P: Preset>(config: &Config, offset: i64) -> Tick {
        let genesis_time = config.min_genesis_time;

        let time = genesis_time
            .checked_add_signed(offset)
            .expect("offset should be small enough to make the resulting time fit in UnixSeconds");

        Tick::at_time::<P>(config, time, genesis_time)
            .expect("config should have a valid value of SECONDS_PER_SLOT")
    }

    fn tick_at_time_millis_relative_to_genesis<P: Preset>(
        config: &Config,
        offset_in_millis: i128,
    ) -> Tick {
        let genesis_time = config.min_genesis_time;

        let time = Duration::from_secs(genesis_time)
            .as_millis()
            .checked_add_signed(offset_in_millis)
            .expect("offset should be small enough to make the resulting time fit in UnixSeconds")
            .try_into()
            .expect("time should be small enough to fit into u64");

        Tick::from_duration::<P>(config, Duration::from_millis(time), genesis_time)
            .expect("config should have a valid value of SECONDS_PER_SLOT")
    }

    fn next_tick_with_instant<P: Preset>(
        config: &Config,
        time: UnixSeconds,
        only_interval_ticks: bool,
    ) -> (u64, Tick) {
        let genesis_time_in_ms = 777_000;
        let timespec = Timespec::from_secs(time);

        let (actual_tick, actual_instant) = super::next_tick_with_instant::<P, _, _>(
            config,
            FakeInstant(timespec),
            FakeSystemTime(timespec),
            genesis_time_in_ms,
            only_interval_ticks,
        )
        .expect("FakeSystemTime cannot represent times before the Unix epoch");

        let actual_instant_in_ms = actual_instant
            .0
            .as_millis()
            .try_into()
            .expect("test instants should fit in u64");

        (actual_instant_in_ms, actual_tick)
    }

    fn config_with_slot_duration(slot_duration: Duration) -> Config {
        Config {
            slot_duration_ms: slot_duration,
            ..Config::default()
        }
    }

    fn next_tick<S>(stream: &mut S) -> Result<Option<Tick>>
    where
        S: Stream<Item = Result<Tick>> + Unpin,
    {
        stream.next().now_or_never().flatten().transpose()
    }

    async fn drain<S>(stream: &mut S) -> Result<()>
    where
        S: Stream<Item = Result<Tick>> + Unpin,
    {
        // `FutureExt::now_or_never()` drives futures without ever yielding to the Tokio scheduler,
        // this would exhaust coop task budget. By using `timeout(Duration::ZERO, ...)` allows
        // driving the stream while yielding to the scheduler, and the task budget got reset every
        // await points.
        while tokio::time::timeout(Duration::ZERO, stream.next())
            .await
            .ok()
            .flatten()
            .transpose()?
            .is_some()
        {}

        Ok(())
    }
}
