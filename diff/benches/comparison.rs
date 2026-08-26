#![expect(
    unused_crate_dependencies,
    reason = "The `unused_crate_dependencies` lint checks every crate in a package separately. \
              See <https://github.com/rust-lang/rust/issues/57274>."
)]

mod common;
mod engines;

use core::{hint::black_box, time::Duration};
use std::time::Instant;

use bytesize::ByteSize;
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use tabled::{
    builder::Builder,
    settings::{
        Alignment, Border, Span, Style,
        object::Columns,
        style::HorizontalLine,
        themes::{BorderCorrection, Theme},
    },
};
use types::phase0::primitives::Slot;

use crate::{
    common::{PAIRS, state},
    engines::{
        DiffEngine, PatchSize as _, eth_state_diff::EthStateDiff, grandine::GrandineDiff,
        qbsdiff::QbsDiff, xdelta3::Xdelta3Diff,
    },
};

const COLUMN_COUNT: usize = 11;
const HEADER_ROW_COUNT: usize = 2;
const HEADER_ROW_COUNT_ISIZE: isize = 2;

struct TimeProfile {
    durations: Vec<Duration>,
}

impl TimeProfile {
    fn new(mut durations: Vec<Duration>) -> Self {
        durations.sort_unstable();
        Self { durations }
    }

    fn collect(mut sample: impl FnMut() -> Duration) -> Self {
        let start = Instant::now();
        let mut durations = Vec::new();

        while durations.len() < 10 || start.elapsed() < Duration::from_secs(10) {
            durations.push(sample());
        }

        Self::new(durations)
    }

    const fn samples(&self) -> usize {
        self.durations.len()
    }

    fn percentile(&self, percentile: usize) -> Duration {
        assert!(
            !self.durations.is_empty(),
            "time profile should have samples"
        );
        assert!(percentile <= 100, "percentile should be at most 100");
        let rank = self
            .durations
            .len()
            .saturating_mul(percentile)
            .div_ceil(100);
        self.durations[rank.saturating_sub(1)]
    }
}

struct ScenarioProfile {
    diff_time: TimeProfile,
    apply_time: TimeProfile,
    hash_root_time: TimeProfile,
    patch_size: usize,
}

fn bench_pair_scenario<E: DiffEngine>(engine: &E, base: Slot, changed: Slot) -> ScenarioProfile {
    let base = state(base);
    let changed = state(changed);
    // Prepare the base state once. This work can be done ahead of time and
    // cached because it is reused for every diff.
    let prepared_base = engine.prepare(base.clone_arc());

    let diff_time = TimeProfile::collect(|| {
        let start = Instant::now();

        let prepared_changed = black_box(engine.prepare(changed.clone_arc()));
        drop(black_box(engine.diff(
            black_box(&prepared_base),
            black_box(&prepared_changed),
        )));

        start.elapsed()
    });

    // Compute the patch once to measure its size and reuse it for apply samples.
    let prepared_changed = engine.prepare(changed);
    let patch = engine.diff(&prepared_base, &prepared_changed);
    let patch_size = patch.size();

    // Apply the serialized patch to the prepared base state and restore the
    // resulting state.
    let apply_time = TimeProfile::collect(|| {
        // `apply` consumes both arguments and the base has to survive for the
        // next sample, so both are cloned before the clock starts. Cloning is
        // setup rather than work an engine does, and charging for it would
        // favour engines whose prepared form is an `Arc` over engines that hold
        // the state in flat buffers.
        let base = prepared_base.clone();
        let patch = patch.clone();

        let start = Instant::now();

        let reconstructed = black_box(engine.apply(black_box(base), black_box(patch)));
        drop(black_box(engine.restore(reconstructed)));

        start.elapsed()
    });

    // Warm the base state's caches before measuring roots of reconstructed states.
    let _ = base.hash_tree_root();
    let prepared_base = engine.prepare(base);
    let hash_root_time = TimeProfile::collect(|| {
        // Reconstruct a fresh state so its hash-tree-root cache is not shared
        // with a previous iteration, apart from caches shared by the base.
        let changed = black_box(engine.apply(prepared_base.clone(), patch.clone()));
        let changed = engine.restore(changed);

        let start = Instant::now();
        let _ = black_box(changed.hash_tree_root());
        start.elapsed()
    });

    ScenarioProfile {
        diff_time,
        apply_time,
        hash_root_time,
        patch_size,
    }
}

#[expect(
    clippy::float_arithmetic,
    reason = "durations are scaled to a human-readable unit for the benchmark table"
)]
fn format_duration(duration: Duration) -> String {
    let (value, unit) = if duration >= Duration::from_secs(1) {
        (duration.as_secs_f64(), "s")
    } else if duration >= Duration::from_millis(1) {
        (duration.as_secs_f64() * 1_000.0f64, "ms")
    } else if duration >= Duration::from_micros(1) {
        (duration.as_secs_f64() * 1_000_000.0f64, "us")
    } else {
        (duration.as_secs_f64() * 1_000_000_000.0f64, "ns")
    };

    let value = if value >= 100.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.2}")
    };
    let value = value.trim_end_matches('0').trim_end_matches('.');
    format!("{value}{unit}")
}

fn format_size(size: usize) -> String {
    ByteSize::b(size as u64).display().iec().to_string()
}

fn scenario_row(name: &str) -> [String; COLUMN_COUNT] {
    [
        name.to_owned(),
        "samples".to_owned(),
        "P50".to_owned(),
        "P99".to_owned(),
        "samples".to_owned(),
        "P50".to_owned(),
        "P99".to_owned(),
        "samples".to_owned(),
        "P50".to_owned(),
        "P99".to_owned(),
        String::new(),
    ]
}

fn engine_row(name: &str, profile: &ScenarioProfile) -> [String; COLUMN_COUNT] {
    [
        name.to_owned(),
        profile.diff_time.samples().to_string(),
        format_duration(profile.diff_time.percentile(50)),
        format_duration(profile.diff_time.percentile(99)),
        profile.apply_time.samples().to_string(),
        format_duration(profile.apply_time.percentile(50)),
        format_duration(profile.apply_time.percentile(99)),
        profile.hash_root_time.samples().to_string(),
        format_duration(profile.hash_root_time.percentile(50)),
        format_duration(profile.hash_root_time.percentile(99)),
        format_size(profile.patch_size),
    ]
}

#[expect(
    clippy::print_stdout,
    reason = "the benchmark's output is the table it prints"
)]
fn print_table(builder: Builder) {
    let line = HorizontalLine::inherit(Style::modern());

    // `Style::horizontals` takes a fixed-size array, so use `Theme` to add rules
    // one at a time.
    let mut theme = Theme::from_style(Style::modern());
    theme.remove_horizontal_lines();

    // Separate the scenario row from the headers and engine rows.
    theme.insert_horizontal_line(1, line);
    theme.insert_horizontal_line(2, line);

    let mut table = builder.build();

    table
        .modify((0, 1), Span::column(3))
        .modify((0, 4), Span::column(3))
        .modify((0, 7), Span::column(3))
        .modify((0, COLUMN_COUNT - 1), Span::row(HEADER_ROW_COUNT_ISIZE))
        .modify(Columns::new(1..COLUMN_COUNT), Alignment::right())
        .modify((0, 1), Alignment::center())
        .modify((0, 4), Alignment::center())
        .modify((0, 7), Alignment::center())
        .modify(
            (0, COLUMN_COUNT - 1),
            (Alignment::center(), Alignment::center_vertical()),
        )
        .with(theme)
        // Remove junctions from the columns covered by the spanned headers.
        .with(BorderCorrection::span())
        // Restore the left corner of the rule below the header after removing
        // the border from the cell spanned by `size`.
        .modify(
            (1, COLUMN_COUNT - 1),
            Border::new().top(' ').left('│').corner_top_left('┤'),
        );

    // Trailing blank line keeps consecutive scenario tables apart.
    println!("{table}\n");
}

fn main() {
    // Print each scenario as soon as its engines finish so long runs show
    // progress incrementally.
    for (scenario, base, changed) in &PAIRS[..] {
        let mut builder = Builder::with_capacity(HEADER_ROW_COUNT + 4, COLUMN_COUNT);

        // Group the diff, apply, and hash metrics. The size column spans both
        // header rows because it has no sub-metrics.
        builder.push_record([
            "scenario", "diff", "", "", "apply", "", "", "hash", "", "", "size",
        ]);
        builder.push_record(scenario_row(scenario));

        builder.push_record(engine_row(
            "grandine",
            &bench_pair_scenario(&GrandineDiff, *base, *changed),
        ));
        builder.push_record(engine_row(
            "qbsdiff",
            &bench_pair_scenario(&QbsDiff, *base, *changed),
        ));
        builder.push_record(engine_row(
            "eth-state-diff",
            &bench_pair_scenario(&EthStateDiff, *base, *changed),
        ));
        builder.push_record(engine_row(
            "xdelta3",
            &bench_pair_scenario(&Xdelta3Diff, *base, *changed),
        ));

        print_table(builder);
    }
}
