//! A [`Stream`]-based timer for the Ethereum 2.0 Beacon Chain.
//!
//! # Implementation
//!
//! This is implemented using [`Interval`]. Some subtleties to keep in mind:
//!
//! - The API of [`Interval`] (as well as other timer utilities in [`tokio::time`]) uses
//!   [`Instant`]s. [`Instant`]s are opaque. There is no way to directly convert a timestamp
//!   (of any kind, not just Unix time) to an [`Instant`]. The hack in [`ticks`] may result in
//!   unexpected behavior in extreme conditions.
//!
//! - An [`Interval`] may produce items late, but the delays do not accumulate by default.
//!   The interval of time between consecutive items produced by [`Interval`] may be shorter than
//!   the [`Duration`] passed to [`interval_at`]. This can be changed by setting a different
//!   [`MissedTickBehavior`].
//!
//!   However, this doesn't always apply. If a consumer spends more than a third of a slot waiting
//!   on a [`Sleep`], all subsequent [`Tick`]s will be delayed. This can be prevented with the use
//!   of [`Timeout`].
//!
//! - It is unclear how [`Interval`] behaves around leap seconds.
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
//! [`tokio::time`]:        tokio::time
//! [`Instant`]:            tokio::time::Instant
//! [`Interval`]:           tokio::time::Interval
//! [`MissedTickBehavior`]: tokio::time::MissedTickBehavior
//! [`Sleep`]:              tokio::time::Sleep
//! [`Timeout`]:            tokio::time::Timeout
//! [`interval_at`]:        tokio::time::interval_at
//!
//! [`clokwerk`]:      https://crates.io/crates/clokwerk
//! [`job_scheduler`]: https://crates.io/crates/job_scheduler
//! [`schedule`]:      https://crates.io/crates/schedule
//! [`timer`]:         https://crates.io/crates/timer
//! [`white_rabbit`]:  https://crates.io/crates/white_rabbit

use core::{error::Error, time::Duration};
use std::time::{Instant, SystemTime, SystemTimeError};

use anyhow::Result;
use enum_iterator::Sequence;
use futures::stream::{Stream, StreamExt as _, TryStreamExt as _};
use helper_functions::misc;
use serde::Deserialize;
use strum::AsRefStr;
use thiserror::Error;
use tokio_stream::wrappers::IntervalStream;
use types::{
    config::Config,
    phase0::{
        consts::GENESIS_SLOT,
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

    pub fn at_time(config: &Config, time: UnixSeconds, genesis_time: UnixSeconds) -> Result<Self> {
        let duration_since_unix_epoch = Duration::from_secs(time);
        Self::from_duration(config, duration_since_unix_epoch, genesis_time)
    }

    pub fn current(config: &Config, genesis_time: UnixSeconds) -> Result<Self> {
        let duration_since_unix_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        Self::from_duration(config, duration_since_unix_epoch, genesis_time)
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
            TickKind::Propose | TickKind::Attest | TickKind::Aggregate,
        )
    }

    #[must_use]
    pub const fn is_end_of_interval(self) -> bool {
        matches!(
            self.kind,
            TickKind::AttestFourth | TickKind::AggregateFourth | TickKind::ProposeFourth,
        )
    }

    pub fn delay(self, config: &Config, genesis_time: UnixSeconds) -> Result<Duration> {
        let duration_since_unix_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let unix_epoch_to_genesis = Duration::from_secs(genesis_time);

        let duration_since_genesis =
            duration_since_unix_epoch.saturating_sub(unix_epoch_to_genesis);

        let Self { slot, kind } = self;
        let slot_duration = slot_duration(config);
        let tick_duration = tick_duration(config);
        let duration_before_slot = slot_duration.saturating_mul((slot - GENESIS_SLOT).try_into()?);
        let duration_after_slot = tick_duration.saturating_mul(kind as u32);
        let duration_until_tick = duration_before_slot + duration_after_slot;

        Ok(duration_since_genesis.saturating_sub(duration_until_tick))
    }

    fn from_duration(
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

        let nanos_per_tick = tick_duration(config).as_nanos();
        let ticks_per_slot = u128::try_from(TickKind::CARDINALITY)?;
        let ticks_since_genesis = nanos_since_genesis / nanos_per_tick;
        let slots_since_genesis = u64::try_from(ticks_since_genesis / ticks_per_slot)?;
        let ticks_since_slot = usize::try_from(ticks_since_genesis % ticks_per_slot)?;
        let slot = GENESIS_SLOT + slots_since_genesis;

        let kind = enum_iterator::all::<TickKind>()
            .nth(ticks_since_slot)
            .expect("more ticks would add up to additional slots");

        Ok(Self::new(slot, kind))
    }

    const fn new(slot: Slot, kind: TickKind) -> Self {
        Self { slot, kind }
    }

    fn next(self) -> Result<Self> {
        let Self { slot, kind } = self;

        let next_slot = match kind.next() {
            Some(_) => slot,
            None => slot.checked_add(1).ok_or(ClockError::RanOutOfSlots)?,
        };

        let next_kind = enum_iterator::next_cycle(&kind);

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
}

#[derive(Debug, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum ClockError {
    #[error("time of next tick overflowed")]
    NextInstantOverflow,
    #[error("ran out of slots")]
    RanOutOfSlots,
}

pub fn ticks(
    config: &Config,
    genesis_time: UnixSeconds,
) -> Result<impl Stream<Item = Result<Tick>>> {
    // We assume the `Instant` and `SystemTime` obtained here correspond to the same point in time.
    // This is slightly inaccurate but the error will probably be negligible compared to clock
    // differences between different nodes in the network.
    let now_instant = Instant::now();
    let now_system_time = SystemTime::now();

    let (mut next_tick, next_instant) =
        next_tick_with_instant(config, now_instant, now_system_time, genesis_time, false)?;

    let tick_duration = tick_duration(config);
    let interval = tokio::time::interval_at(next_instant.into(), tick_duration);

    Ok(IntervalStream::new(interval)
        .map(move |_| {
            let current_tick = next_tick;
            next_tick = current_tick.next()?;
            Ok(current_tick)
        })
        .try_filter(|tick| {
            // Emit only ticks that the application currently uses.
            //
            // This could be written as an `async` block, but that makes the stream `!Unpin`.
            core::future::ready(tick.is_start_of_interval() || tick.is_end_of_interval())
        }))
}

pub fn next_interval_with_remaining_time(
    config: &Config,
    genesis_time: UnixSeconds,
) -> Result<(Tick, Duration)> {
    // We assume the `Instant` and `SystemTime` obtained here correspond to the same point in time.
    // This is slightly inaccurate but the error will probably be negligible compared to clock
    // differences between different nodes in the network.
    let now_instant = Instant::now();
    let now_system_time = SystemTime::now();

    let (next_interval, next_instant) =
        next_tick_with_instant(config, now_instant, now_system_time, genesis_time, true)?;

    let remaining_time = next_instant.duration_since(now_instant);

    Ok((next_interval, remaining_time))
}

fn next_tick_with_instant<I: InstantLike, S: SystemTimeLike>(
    config: &Config,
    now_instant: I,
    now_system_time: S,
    genesis_time: UnixSeconds,
    only_interval_ticks: bool,
) -> Result<(Tick, I)> {
    let unix_epoch_to_now = now_system_time.duration_since(S::UNIX_EPOCH)?;
    let unix_epoch_to_genesis = Duration::from_secs(genesis_time);

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
        now_to_next_tick = unix_epoch_to_genesis - unix_epoch_to_now;
    } else {
        let tick_duration = tick_duration(config);
        let genesis_to_now = unix_epoch_to_now - unix_epoch_to_genesis;
        let slots_since_genesis = genesis_to_now.as_secs() / config.slot_duration_ms.as_secs();
        let genesis_to_current_slot =
            Duration::from_secs(slots_since_genesis * config.slot_duration_ms.as_secs());
        let current_slot_to_now = genesis_to_now - genesis_to_current_slot;

        next_tick = Tick::start_of_slot(GENESIS_SLOT + slots_since_genesis);
        now_to_next_tick = Duration::ZERO;

        while now_to_next_tick < current_slot_to_now {
            next_tick = next_tick.next()?;
            now_to_next_tick += tick_duration;
        }

        if only_interval_ticks {
            while !next_tick.is_start_of_interval() {
                next_tick = next_tick.next()?;
                now_to_next_tick += tick_duration;
            }
        }

        now_to_next_tick -= current_slot_to_now;
    }

    let next_instant = now_instant
        .checked_add(now_to_next_tick)
        .ok_or(ClockError::NextInstantOverflow)?;

    Ok((next_tick, next_instant))
}

fn tick_duration(config: &Config) -> Duration {
    let slot_duration = slot_duration(config);

    let ticks_per_slot_u32 =
        u32::try_from(TickKind::CARDINALITY).expect("number of ticks per slot fits in u32");

    slot_duration / ticks_per_slot_u32
}

// TODO: Remove this function and update all usages throughout the app to work with slot duration
//       in ms (instead of seconds) once `Config::seconds_per_slot` is removed from the Config.
const fn slot_duration(config: &Config) -> Duration {
    config.slot_duration_ms
}

#[cfg(test)]
mod tests {
    use core::{num::NonZeroU64, ops::Add as _};

    use futures::future::FutureExt as _;
    use itertools::Itertools as _;
    use nonzero_ext::nonzero;
    use test_case::test_case;
    use types::phase0::consts::INTERVALS_PER_SLOT;

    use crate::fake_time::{FakeInstant, FakeSystemTime, Timespec};

    use super::*;

    #[test]
    fn tick_count_is_a_multiple_of_interval_count() {
        assert!(TickKind::CARDINALITY.is_multiple_of(INTERVALS_PER_SLOT.into()));
    }

    #[tokio::test(start_paused = true)]
    async fn ticks_with_mainnet_config_produces_a_tick_every_second() -> Result<()> {
        let genesis_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
            .add(1);

        let mut ticks = ticks(&Config::mainnet(), genesis_time)?;
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
    async fn ticks_starts_with_tick_at_end_of_interval_when_just_past_genesis() -> Result<()> {
        let genesis_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();

        let mut ticks = ticks(&Config::mainnet(), genesis_time)?;
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
            config_with_seconds_per_slot(NonZeroU64::MIN),
            config_with_seconds_per_slot(nonzero!(2_u64)),
            config_with_seconds_per_slot(nonzero!(3_u64)),
            Config::minimal(),
            Config::mainnet(),
            config_with_seconds_per_slot(nonzero!(18_u64)),
        ];

        let genesis_times = [
            UnixSeconds::MIN,
            777,
            UnixSeconds::MAX - 3,
            UnixSeconds::MAX - 2,
            UnixSeconds::MAX - 1,
            UnixSeconds::MAX,
        ];

        for (config, genesis_time) in configs.iter().cartesian_product(genesis_times) {
            ticks(config, genesis_time).ok();
        }
    }

    #[test_case(-24 => Tick::new(0, TickKind::Propose);         "24 seconds before genesis")]
    #[test_case(-12 => Tick::new(0, TickKind::Propose);         "12 seconds before genesis")]
    #[test_case( -1 => Tick::new(0, TickKind::Propose);         "1 second before genesis")]
    #[test_case(  0 => Tick::new(0, TickKind::Propose);         "at genesis")]
    #[test_case(  1 => Tick::new(0, TickKind::ProposeSecond);   "1 second after genesis")]
    #[test_case(  2 => Tick::new(0, TickKind::ProposeThird);    "2 second after genesis")]
    #[test_case(  3 => Tick::new(0, TickKind::ProposeFourth);   "3 seconds after genesis")]
    #[test_case(  4 => Tick::new(0, TickKind::Attest);          "4 seconds after genesis")]
    #[test_case(  5 => Tick::new(0, TickKind::AttestSecond);    "5 seconds after genesis")]
    #[test_case(  6 => Tick::new(0, TickKind::AttestThird);     "6 seconds after genesis")]
    #[test_case(  7 => Tick::new(0, TickKind::AttestFourth);    "7 seconds after genesis")]
    #[test_case(  8 => Tick::new(0, TickKind::Aggregate);       "8 seconds after genesis")]
    #[test_case(  9 => Tick::new(0, TickKind::AggregateSecond); "9 seconds after genesis")]
    #[test_case( 10 => Tick::new(0, TickKind::AggregateThird);  "10 seconds after genesis")]
    #[test_case( 11 => Tick::new(0, TickKind::AggregateFourth); "11 seconds after genesis")]
    #[test_case( 12 => Tick::new(1, TickKind::Propose);         "12 seconds after genesis")]
    #[test_case( 13 => Tick::new(1, TickKind::ProposeSecond);   "13 seconds after genesis")]
    #[test_case( 24 => Tick::new(2, TickKind::Propose);         "24 seconds after genesis")]
    fn tick_at_time_relative_to_genesis_with_mainnet_config(offset: i64) -> Tick {
        tick_at_time_relative_to_genesis(&Config::mainnet(), offset)
    }

    #[test_case(-12 => Tick::new(0, TickKind::Propose);        "12 seconds before genesis")]
    #[test_case( -6 => Tick::new(0, TickKind::Propose);        "6 seconds before genesis")]
    #[test_case( -1 => Tick::new(0, TickKind::Propose);        "1 second before genesis")]
    #[test_case(  0 => Tick::new(0, TickKind::Propose);        "at genesis")]
    #[test_case(  1 => Tick::new(0, TickKind::ProposeThird);   "1 second after genesis")]
    #[test_case(  2 => Tick::new(0, TickKind::Attest);         "2 seconds after genesis")]
    #[test_case(  3 => Tick::new(0, TickKind::AttestThird);    "3 seconds after genesis")]
    #[test_case(  4 => Tick::new(0, TickKind::Aggregate);      "4 seconds after genesis")]
    #[test_case(  5 => Tick::new(0, TickKind::AggregateThird); "5 seconds after genesis")]
    #[test_case(  6 => Tick::new(1, TickKind::Propose);        "6 seconds after genesis")]
    #[test_case(  7 => Tick::new(1, TickKind::ProposeThird);   "7 seconds after genesis")]
    #[test_case( 12 => Tick::new(2, TickKind::Propose);        "12 seconds after genesis")]
    fn tick_at_time_relative_to_genesis_with_minimal_config(offset: i64) -> Tick {
        tick_at_time_relative_to_genesis(&Config::minimal(), offset)
    }

    #[test_case(100 => (777, Tick::new(0, TickKind::Propose));         "long before genesis")]
    #[test_case(777 => (777, Tick::new(0, TickKind::Propose));         "at genesis")]
    #[test_case(778 => (778, Tick::new(0, TickKind::ProposeSecond));   "1 second after genesis")]
    #[test_case(779 => (779, Tick::new(0, TickKind::ProposeThird));    "2 seconds after genesis")]
    #[test_case(780 => (780, Tick::new(0, TickKind::ProposeFourth));   "3 seconds after genesis")]
    #[test_case(781 => (781, Tick::new(0, TickKind::Attest));          "4 seconds after genesis")]
    #[test_case(782 => (782, Tick::new(0, TickKind::AttestSecond));    "5 seconds after genesis")]
    #[test_case(783 => (783, Tick::new(0, TickKind::AttestThird));     "6 seconds after genesis")]
    #[test_case(784 => (784, Tick::new(0, TickKind::AttestFourth));    "7 seconds after genesis")]
    #[test_case(785 => (785, Tick::new(0, TickKind::Aggregate));       "8 seconds after genesis")]
    #[test_case(786 => (786, Tick::new(0, TickKind::AggregateSecond)); "9 seconds after genesis")]
    #[test_case(787 => (787, Tick::new(0, TickKind::AggregateThird));  "10 seconds after genesis")]
    #[test_case(788 => (788, Tick::new(0, TickKind::AggregateFourth)); "11 seconds after genesis")]
    #[test_case(789 => (789, Tick::new(1, TickKind::Propose));         "12 seconds after genesis")]
    fn next_tick_with_instant_with_mainnet_config(time: UnixSeconds) -> (UnixSeconds, Tick) {
        next_tick_with_instant(&Config::mainnet(), time, false)
    }

    #[test_case(100 => (777, Tick::new(0, TickKind::Propose));   "long before genesis")]
    #[test_case(777 => (777, Tick::new(0, TickKind::Propose));   "at genesis")]
    #[test_case(778 => (781, Tick::new(0, TickKind::Attest));    "1 second after genesis")]
    #[test_case(779 => (781, Tick::new(0, TickKind::Attest));    "2 seconds after genesis")]
    #[test_case(780 => (781, Tick::new(0, TickKind::Attest));    "3 seconds after genesis")]
    #[test_case(781 => (781, Tick::new(0, TickKind::Attest));    "4 seconds after genesis")]
    #[test_case(782 => (785, Tick::new(0, TickKind::Aggregate)); "5 seconds after genesis")]
    #[test_case(783 => (785, Tick::new(0, TickKind::Aggregate)); "6 seconds after genesis")]
    #[test_case(784 => (785, Tick::new(0, TickKind::Aggregate)); "7 seconds after genesis")]
    #[test_case(785 => (785, Tick::new(0, TickKind::Aggregate)); "8 seconds after genesis")]
    #[test_case(786 => (789, Tick::new(1, TickKind::Propose));   "9 seconds after genesis")]
    #[test_case(787 => (789, Tick::new(1, TickKind::Propose));   "10 seconds after genesis")]
    #[test_case(788 => (789, Tick::new(1, TickKind::Propose));   "11 seconds after genesis")]
    #[test_case(789 => (789, Tick::new(1, TickKind::Propose));   "12 seconds after genesis")]
    fn next_tick_with_instant_with_mainnet_config_only_interval_ticks(
        time: UnixSeconds,
    ) -> (UnixSeconds, Tick) {
        next_tick_with_instant(&Config::mainnet(), time, true)
    }

    #[test_case(100 => (777, Tick::new(0, TickKind::Propose));        "long before genesis")]
    #[test_case(777 => (777, Tick::new(0, TickKind::Propose));        "at genesis")]
    #[test_case(778 => (778, Tick::new(0, TickKind::ProposeThird));   "1 second after genesis")]
    #[test_case(779 => (779, Tick::new(0, TickKind::Attest));         "2 seconds after genesis")]
    #[test_case(780 => (780, Tick::new(0, TickKind::AttestThird));    "3 seconds after genesis")]
    #[test_case(781 => (781, Tick::new(0, TickKind::Aggregate));      "4 seconds after genesis")]
    #[test_case(782 => (782, Tick::new(0, TickKind::AggregateThird)); "5 seconds after genesis")]
    #[test_case(783 => (783, Tick::new(1, TickKind::Propose));        "6 seconds after genesis")]
    fn next_tick_with_instant_with_minimal_config(time: UnixSeconds) -> (UnixSeconds, Tick) {
        next_tick_with_instant(&Config::minimal(), time, false)
    }

    #[test_case(100 => (777, Tick::new(0, TickKind::Propose));   "long before genesis")]
    #[test_case(777 => (777, Tick::new(0, TickKind::Propose));   "at genesis")]
    #[test_case(778 => (779, Tick::new(0, TickKind::Attest));    "1 second after genesis")]
    #[test_case(779 => (779, Tick::new(0, TickKind::Attest));    "2 seconds after genesis")]
    #[test_case(780 => (781, Tick::new(0, TickKind::Aggregate)); "3 seconds after genesis")]
    #[test_case(781 => (781, Tick::new(0, TickKind::Aggregate)); "4 seconds after genesis")]
    #[test_case(782 => (783, Tick::new(1, TickKind::Propose));   "5 seconds after genesis")]
    #[test_case(783 => (783, Tick::new(1, TickKind::Propose));   "6 seconds after genesis")]
    fn next_tick_with_instant_with_minimal_config_only_interval_ticks(
        time: UnixSeconds,
    ) -> (UnixSeconds, Tick) {
        next_tick_with_instant(&Config::minimal(), time, true)
    }

    #[test_case(nonzero!(3_u64) => Duration::from_millis(250))]
    #[test_case(NonZeroU64::new(Config::minimal().slot_duration_ms.as_secs()).expect("Config::minimal slot_duration_ms is nonzero") => Duration::from_millis(500))]
    #[test_case(NonZeroU64::new(Config::mainnet().slot_duration_ms.as_secs()).expect("Config::mainnet slot_duration_ms is nonzero") => Duration::from_secs(1))]
    #[test_case(nonzero!(18_u64) => Duration::from_millis(1500))]
    fn tick_duration_with_seconds_per_slot(seconds_per_slot: NonZeroU64) -> Duration {
        let config = config_with_seconds_per_slot(seconds_per_slot);
        tick_duration(&config)
    }

    fn tick_at_time_relative_to_genesis(config: &Config, offset: i64) -> Tick {
        let genesis_time = config.min_genesis_time;

        let time = genesis_time
            .checked_add_signed(offset)
            .expect("offset should be small enough to make the resulting time fit in UnixSeconds");

        Tick::at_time(config, time, genesis_time)
            .expect("config should have a valid value of SECONDS_PER_SLOT")
    }

    fn next_tick_with_instant(
        config: &Config,
        time: UnixSeconds,
        only_interval_ticks: bool,
    ) -> (UnixSeconds, Tick) {
        let genesis_time = 777;
        let timespec = Timespec::from_secs(time);

        let (actual_tick, actual_instant) = super::next_tick_with_instant(
            config,
            FakeInstant(timespec),
            FakeSystemTime(timespec),
            genesis_time,
            only_interval_ticks,
        )
        .expect("FakeSystemTime cannot represent times before the Unix epoch");

        assert_eq!(actual_instant.0.subsec_nanos(), 0);

        (actual_instant.0.as_secs(), actual_tick)
    }

    fn config_with_seconds_per_slot(seconds_per_slot: NonZeroU64) -> Config {
        #[expect(
            deprecated,
            reason = "seconds_per_slot is still present in the consensus specs as of v1.6.0-alpha.5"
        )]
        Config {
            seconds_per_slot,
            slot_duration_ms: Duration::from_secs(seconds_per_slot.get()),
            ..Config::default()
        }
    }
}
