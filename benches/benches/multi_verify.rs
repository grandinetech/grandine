use core::time::Duration;

use allocator as _;
use bls::{
    PublicKey, Signature,
    traits::{SecretKey as _, Signature as _},
};
use criterion::{
    Criterion, Throughput,
    measurement::{Measurement, ValueFormatter, WallTime},
};
use rustix::time::{ClockId, clock_gettime};
use types::phase0::primitives::H256;

// Criterion macros only add confusion.
fn main() {
    let mut wall_time = Criterion::default().configure_from_args();

    let mut cpu_time = Criterion::default()
        .with_measurement(ProcessCpuTime(WallTime))
        .configure_from_args();

    benchmark_multi_verify(&mut wall_time, "");
    benchmark_multi_verify(&mut cpu_time, " (CPU time)");

    wall_time.final_summary();
    cpu_time.final_summary();
}

fn benchmark_multi_verify(criterion: &mut Criterion<impl Measurement>, suffix: &str) {
    for batch_size in [64, 128] {
        let mut group = criterion.benchmark_group(format!(
            "Signature::multi_verify with {batch_size} triples{suffix}"
        ));

        group.throughput(Throughput::Elements(batch_size));

        for message_count in [1, 4, 8, 16, 32, 64, 128]
            .into_iter()
            .filter(|message_count| *message_count <= batch_size)
        {
            let triples = signed_triples(batch_size, message_count);

            assert!(multi_verify(&triples));

            group.bench_function(format!("{message_count} distinct messages"), |bencher| {
                bencher.iter(|| multi_verify(&triples))
            });
        }
    }
}

/// CPU time of every thread in the process, the quantity `GRANDINE_TOTAL_CPU_SECONDS` reports.
struct ProcessCpuTime(WallTime);

impl Measurement for ProcessCpuTime {
    type Intermediate = Duration;
    type Value = Duration;

    fn start(&self) -> Self::Intermediate {
        process_cpu_time()
    }

    fn end(&self, start: Self::Intermediate) -> Self::Value {
        process_cpu_time().saturating_sub(start)
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        v1.saturating_add(*v2)
    }

    fn zero(&self) -> Self::Value {
        Duration::ZERO
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        self.0.to_f64(value)
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        self.0.formatter()
    }
}

fn process_cpu_time() -> Duration {
    clock_gettime(ClockId::ProcessCPUTime)
        .try_into()
        .expect("process CPU time is never negative")
}

fn signed_triples(batch_size: u64, message_count: u64) -> Vec<(H256, Signature, PublicKey)> {
    (0..batch_size)
        .zip((0..message_count).cycle())
        .map(|(validator_index, message_index)| {
            let message = H256::from_low_u64_be(message_index);
            let secret_key = interop::secret_key(validator_index);
            (
                message,
                secret_key.sign(message),
                secret_key.to_public_key(),
            )
        })
        .collect()
}

fn multi_verify(triples: &[(H256, Signature, PublicKey)]) -> bool {
    Signature::multi_verify(
        triples.iter().map(|(message, _, _)| message.as_bytes()),
        triples.iter().map(|(_, signature, _)| signature),
        triples.iter().map(|(_, _, public_key)| public_key),
    )
}
