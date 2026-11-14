//! Run the manual export benchmark from the repository root:
//!
//! ```sh
//! cargo test -p operation_pools -p bls -p kzg_utils --release --locked \
//!   --features bls/blst,kzg_utils/blst --lib benchmark_attestation_pool_export \
//!   -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Synthetic Minimal-preset candidates contain real BLS points signed over data hashes,
//! not consensus-validated attestations. Both collectors run in the same executable.
//! Output includes raw wall-clock samples and min/median/max in nanoseconds.
//! These timings cover export only, not packing or production latency.

use core::{pin::pin, task::Poll};
use ssz::BitList;
use types::{
    phase0::containers::{AttestationData, Checkpoint},
    preset::Minimal,
};

use super::*;

fn key(index: u64, epoch: Epoch) -> AttestationKey {
    AttestationKey {
        data: AttestationData {
            slot: 8,
            beacon_block_root: H256::from_low_u64_be(index),
            target: Checkpoint {
                epoch,
                ..Default::default()
            },
            ..Default::default()
        },
        committee_index: 0,
    }
}

fn aggregate(bit: usize) -> Aggregate<Minimal> {
    let mut aggregation_bits = BitList::new(false, 8);
    aggregation_bits.set(bit, true);
    Aggregate {
        aggregation_bits,
        ..Default::default()
    }
}

#[tokio::test]
async fn export_collect_preserves_groups_order_and_updates() {
    let pool = Pool::<Minimal>::new(Arc::new(ChainConfig::minimal()));
    assert!(pool.aggregate_attestations_by_epoch(1).await.is_empty());
    for (index, count) in [(3, 2), (1, 1), (2, 0), (0, 4)] {
        pool.aggregates(key(index, 1))
            .await
            .lock()
            .await
            .extend((0..count).map(aggregate));
    }
    pool.aggregates(key(0, 2))
        .await
        .lock()
        .await
        .push(aggregate(7));
    for epoch in [0, 1, 2, 3] {
        assert_eq!(
            pool.collect_epoch_baseline(epoch).await,
            pool.aggregate_attestations_by_epoch(epoch).await
        );
    }
    let before = pool.aggregate_attestations_by_epoch(1).await;
    assert_eq!(before.len(), 7);
    assert_eq!(
        before.iter().map(PoolAttestation::key).collect_vec(),
        [key(0, 1); 4]
            .into_iter()
            .chain([key(1, 1), key(3, 1), key(3, 1)])
            .collect_vec()
    );
    pool.aggregates(key(1, 1))
        .await
        .lock()
        .await
        .push(aggregate(6));
    let after = pool.aggregate_attestations_by_epoch(1).await;
    assert_eq!(after.len(), 8);
    assert_eq!(after, pool.collect_epoch_baseline(1).await);
}

#[tokio::test]
async fn export_collect_preserves_signed_candidates() {
    use bls::{
        SecretKey, SecretKeyBytes, Signature,
        traits::{SecretKey as _, Signature as _},
    };

    let pool = Pool::<Minimal>::new(Arc::new(ChainConfig::minimal()));
    let mut bytes = SecretKeyBytes::default();
    bytes.as_mut()[31] = 1;
    let secret: SecretKey = bytes.try_into().expect("nonzero fixture key");
    for index in 0..3 {
        let key = key(index, 1);
        let mut value = aggregate(usize::try_from(index).expect("three fixture indices"));
        value
            .signature
            .aggregate_in_place(secret.sign(key.data.hash_tree_root()));
        pool.aggregates(key).await.lock().await.push(value);
    }
    let output = pool.aggregate_attestations_by_epoch(1).await;
    assert_eq!(output, pool.collect_epoch_baseline(1).await);
    for attestation in output {
        let signature: Signature = attestation.signature.try_into().expect("valid encoding");
        assert!(signature.verify(attestation.data.hash_tree_root(), &secret.to_public_key()));
        assert_eq!(
            pool.best_aggregate_attestation_by_data_root(attestation.data.hash_tree_root(), 1)
                .await,
            Some(attestation),
        );
    }
}

// A blocked group must not prevent observing a ready group before it changes.
#[tokio::test]
async fn export_collect_preserves_ready_tail_read_with_blocked_group() {
    for adaptive in [false, true] {
        for blocked in [0, 1] {
            let pool = Pool::<Minimal>::new(Arc::new(ChainConfig::minimal()));
            let first = pool.aggregates(key(0, 1)).await;
            let last = pool.aggregates(key(1, 1)).await;
            first.lock().await.push(aggregate(0));
            last.lock().await.push(aggregate(0));
            let (held, ready) = if blocked == 0 {
                (&first, &last)
            } else {
                (&last, &first)
            };
            let held = held.lock().await;
            let export = async {
                if adaptive {
                    pool.aggregate_attestations_by_epoch(1).await
                } else {
                    pool.collect_epoch_baseline(1).await
                }
            };
            let mut export = pin!(export);
            assert!(matches!(futures::poll!(&mut export), Poll::Pending));
            ready.lock().await[0] = aggregate(1);
            drop(held);
            let output = export.await;
            assert_eq!(output.len(), 2);
            assert!(
                output
                    .iter()
                    .all(|att| att.aggregation_bits.get(0).is_some_and(|bit| *bit))
            );
            assert!(
                pool.aggregate_attestations_by_epoch(1)
                    .await
                    .iter()
                    .any(|att| att.aggregation_bits.get(1).is_some_and(|bit| *bit))
            );
        }
    }
}

#[tokio::test]
async fn export_collect_defers_new_keys_and_releases_locks_on_cancel() {
    for adaptive in [false, true] {
        let pool = Pool::<Minimal>::new(Arc::new(ChainConfig::minimal()));
        let group = pool.aggregates(key(0, 1)).await;
        group.lock().await.push(aggregate(0));
        let held = group.lock().await;
        let mut export = Box::pin(async {
            if adaptive {
                pool.aggregate_attestations_by_epoch(1).await
            } else {
                pool.collect_epoch_baseline(1).await
            }
        });
        assert!(matches!(futures::poll!(&mut export), Poll::Pending));
        let insert = pool.aggregates(key(1, 1));
        let mut insert = pin!(insert);
        assert!(matches!(futures::poll!(&mut insert), Poll::Pending));
        drop(held);
        let output = export.await;
        assert_eq!(output.len(), 1);
        insert.await.lock().await.push(aggregate(1));
        assert_eq!(pool.aggregate_attestations_by_epoch(1).await.len(), 2);
        let held = group.lock().await;
        let mut cancelled = Box::pin(async {
            if adaptive {
                pool.aggregate_attestations_by_epoch(1).await
            } else {
                pool.collect_epoch_baseline(1).await
            }
        });
        assert!(matches!(futures::poll!(&mut cancelled), Poll::Pending));
        drop(cancelled);
        drop(
            pool.aggregates
                .try_write()
                .expect("cancel releases epoch read lock"),
        );
        drop(held);
    }
}

// A large ready workload must yield while retaining the epoch read lock.
#[tokio::test]
async fn export_collect_yields_with_epoch_read_lock_held() {
    for adaptive in [false, true] {
        let pool = Arc::new(Pool::<Minimal>::new(Arc::new(ChainConfig::minimal())));
        for index in 0..257 {
            pool.aggregates(key(index, 1))
                .await
                .lock()
                .await
                .push(aggregate(0));
        }
        tokio::spawn(async move {
            let mut export = Box::pin(async {
                if adaptive {
                    pool.aggregate_attestations_by_epoch(1).await
                } else {
                    pool.collect_epoch_baseline(1).await
                }
            });
            assert!(matches!(futures::poll!(&mut export), Poll::Pending));
            assert!(pool.aggregates.try_write().is_err());
            let output = export.await;
            assert_eq!(output.len(), 257);
            assert_eq!(output, pool.collect_epoch_baseline(1).await);
            drop(
                pool.aggregates
                    .try_write()
                    .expect("finished export unlocks epoch"),
            );
        })
        .await
        .expect("budget probe completes");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_collect_preserves_groups_with_concurrent_writers() {
    tokio::time::timeout(core::time::Duration::from_secs(10), async {
        for adaptive in [false, true] {
            let pool = Arc::new(Pool::<Minimal>::new(Arc::new(ChainConfig::minimal())));
            let mut groups = Vec::new();
            for index in 0..257 {
                let group = pool.aggregates(key(index, 1)).await;
                *group.lock().await = vec![aggregate(0); 3];
                groups.push(group);
            }
            let barrier = Arc::new(tokio::sync::Barrier::new(6));
            let mut writers = Vec::new();
            for lane in 0..4 {
                let groups = groups.clone();
                let barrier = barrier.clone_arc();
                writers.push(tokio::spawn(async move {
                    barrier.wait().await;
                    for generation in 1..=16 {
                        for group in groups.iter().skip(lane).step_by(4) {
                            *group.lock().await = vec![aggregate(generation % 7); 3];
                            tokio::task::yield_now().await;
                        }
                    }
                }));
            }
            let new_keys = pool.clone_arc();
            let insert_barrier = barrier.clone_arc();
            writers.push(tokio::spawn(async move {
                insert_barrier.wait().await;
                for index in 257..273 {
                    *new_keys.aggregates(key(index, 1)).await.lock().await = vec![aggregate(7); 3];
                    tokio::task::yield_now().await;
                }
            }));
            barrier.wait().await;
            for _ in 0..32 {
                let output = if adaptive {
                    pool.aggregate_attestations_by_epoch(1).await
                } else {
                    pool.collect_epoch_baseline(1).await
                };
                assert!((257 * 3..=273 * 3).contains(&output.len()));
                assert_eq!(output.len() % 3, 0);
                let mut previous = None;
                for group in output.as_chunks::<3>().0 {
                    let current = group[0].key();
                    assert!(previous.is_none_or(|prior| prior < current));
                    assert!(group.iter().all(|att| att == &group[0]));
                    previous = Some(current);
                }
                for (index, group) in output.as_chunks::<3>().0.iter().take(257).enumerate() {
                    assert_eq!(group[0].key(), key(index as u64, 1));
                }
                tokio::task::yield_now().await;
            }
            for writer in writers {
                writer.await.expect("writer completes");
            }
            let output = pool.aggregate_attestations_by_epoch(1).await;
            assert_eq!(output.len(), 273 * 3);
            assert_eq!(output, pool.collect_epoch_baseline(1).await);
        }
    })
    .await
    .expect("concurrent export and writers make progress");
}

// Deterministic shapes around the cooperative scheduling boundary, with an independent oracle.
#[tokio::test]
async fn export_collect_shape_matrix() {
    for groups in [0, 1, 2, 127, 128, 129, 257, 1024] {
        for seed in 0..16_u64 {
            let pool = Pool::<Minimal>::new(Arc::new(ChainConfig::minimal()));
            let mut expected = Vec::new();
            for index in (0..groups).rev() {
                let key = key(index, 1);
                let count = (index * 17 + seed * 13) % 9;
                let mut values = Vec::new();
                for bit in 0..count {
                    let value = aggregate(usize::try_from(bit % 8).expect("small bit"));
                    expected.push(PoolAttestation {
                        data: key.data,
                        committee_index: key.committee_index,
                        aggregation_bits: value.aggregation_bits.clone(),
                        signature: value.signature.into(),
                    });
                    values.push(value);
                }
                *pool.aggregates(key).await.lock().await = values;
            }
            expected.sort_by_key(PoolAttestation::key);
            assert_eq!(pool.aggregate_attestations_by_epoch(1).await, expected);
            assert_eq!(pool.collect_epoch_baseline(1).await, expected);
        }
    }
}

#[tokio::test]
async fn export_collect_pruning_waits_and_cancellation_unblocks_it() {
    for adaptive in [false, true] {
        for blocked in 0..8 {
            for cancel in [false, true] {
                let pool = Pool::<Minimal>::new(Arc::new(ChainConfig::minimal()));
                for index in 0..8 {
                    pool.aggregates(key(index, 1))
                        .await
                        .lock()
                        .await
                        .push(aggregate(0));
                }
                pool.aggregates(key(0, 2))
                    .await
                    .lock()
                    .await
                    .push(aggregate(1));
                let group = pool.aggregates(key(blocked, 1)).await;
                let held = group.lock().await;
                let mut export = Box::pin(async {
                    if adaptive {
                        pool.aggregate_attestations_by_epoch(1).await
                    } else {
                        pool.collect_epoch_baseline(1).await
                    }
                });
                assert!(matches!(futures::poll!(&mut export), Poll::Pending));
                // Minimal has eight slots per epoch: entering epoch 3 prunes epoch 1.
                let mut prune = Box::pin(pool.on_slot(24));
                assert!(matches!(futures::poll!(&mut prune), Poll::Pending));
                if cancel {
                    drop(export);
                    // The held group must not prevent pruning once the reader is cancelled.
                    tokio::time::timeout(core::time::Duration::from_secs(2), prune)
                        .await
                        .expect("cancel releases pruning writer");
                    drop(held);
                } else {
                    drop(held);
                    assert_eq!(export.await.len(), 8);
                    prune.await;
                }
                assert!(pool.aggregate_attestations_by_epoch(1).await.is_empty());
                assert_eq!(pool.aggregate_attestations_by_epoch(2).await.len(), 1);
            }
        }
    }
}

#[test]
fn export_collect_multi_reader_writer_stress() {
    for workers in [1, 2, 4, 8] {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .expect("stress runtime")
            .block_on(async {
                tokio::time::timeout(core::time::Duration::from_secs(20), async {
                    for adaptive in [false, true] {
                        let pool = Arc::new(Pool::<Minimal>::new(Arc::new(ChainConfig::minimal())));
                        let mut groups = Vec::new();
                        for index in 0..129 {
                            let group = pool.aggregates(key(index, 1)).await;
                            *group.lock().await = vec![aggregate(0); 3];
                            groups.push(group);
                        }
                        let barrier = Arc::new(tokio::sync::Barrier::new(11));
                        let mut tasks = Vec::new();
                        for lane in 0..4 {
                            let groups = groups.clone();
                            let barrier = barrier.clone_arc();
                            tasks.push(tokio::spawn(async move {
                                barrier.wait().await;
                                for generation in 0..64 {
                                    for group in groups.iter().skip(lane).step_by(4) {
                                        *group.lock().await = vec![aggregate(generation % 8); 3];
                                        tokio::task::yield_now().await;
                                    }
                                }
                            }));
                        }
                        for _ in 0..6 {
                            let pool = pool.clone_arc();
                            let barrier = barrier.clone_arc();
                            tasks.push(tokio::spawn(async move {
                                barrier.wait().await;
                                for _ in 0..64 {
                                    let output = if adaptive {
                                        pool.aggregate_attestations_by_epoch(1).await
                                    } else {
                                        pool.collect_epoch_baseline(1).await
                                    };
                                    assert_eq!(output.len(), 129 * 3);
                                    for (index, group) in
                                        output.as_chunks::<3>().0.iter().enumerate()
                                    {
                                        assert_eq!(
                                            group[0].key(),
                                            key(u64::try_from(index).expect("small index"), 1)
                                        );
                                        assert!(group.iter().all(|att| att == &group[0]));
                                    }
                                    tokio::task::yield_now().await;
                                }
                            }));
                        }
                        barrier.wait().await;
                        for task in tasks {
                            task.await.expect("reader or writer succeeds");
                        }
                        assert_eq!(
                            pool.aggregate_attestations_by_epoch(1).await,
                            pool.collect_epoch_baseline(1).await
                        );
                    }
                })
                .await
                .expect("all readers and writers make progress");
            });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Manual comparison of baseline and adaptive pool export"]
#[expect(
    clippy::print_stdout,
    reason = "manual benchmark reports samples and summaries"
)]
async fn benchmark_attestation_pool_export() {
    use std::time::Instant;

    use bls::{
        SecretKey, SecretKeyBytes,
        traits::{SecretKey as _, Signature as _},
    };

    let mut bytes = SecretKeyBytes::default();
    bytes.as_mut()[31] = 1;
    let secret: SecretKey = bytes.try_into().expect("nonzero fixture key");
    println!("\nsample,groups,candidates_per_group,pair,adaptive,elapsed_ns");
    println!("summary,groups,candidates_per_group,adaptive,min_ns,median_ns,max_ns");
    for (groups, per_group) in [(32, 16), (512, 1), (256, 16), (4096, 1)] {
        let pool = Pool::<Minimal>::new(Arc::new(ChainConfig::minimal()));
        for index in 0..groups {
            let key = key(index, 1);
            let mut values = Vec::new();
            for bit in 0..per_group {
                let mut value = aggregate(bit % 8);
                value
                    .signature
                    .aggregate_in_place(secret.sign(key.data.hash_tree_root()));
                values.push(value);
            }
            *pool.aggregates(key).await.lock().await = values;
        }
        let expected = pool.collect_epoch_baseline(1).await;
        let mut samples = Vec::with_capacity(62);
        // Three warm-up pairs, then 31 measured pairs with alternating execution order.
        for round in 0..34 {
            let order = if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for adaptive in order {
                let started = Instant::now();
                let output = if adaptive {
                    pool.aggregate_attestations_by_epoch(1).await
                } else {
                    pool.collect_epoch_baseline(1).await
                };
                let elapsed = started.elapsed().as_nanos();
                assert_eq!(output, expected);
                if round >= 3 {
                    samples.push((round - 3, adaptive, elapsed));
                }
            }
        }
        // Keep fixture creation, signing, output checks, drops, and printing outside timing.
        for &(pair, adaptive, elapsed) in &samples {
            println!("sample,{groups},{per_group},{pair},{adaptive},{elapsed}");
        }
        for adaptive in [false, true] {
            let mut times = samples
                .iter()
                .filter(|(_, selected, _)| *selected == adaptive)
                .map(|(_, _, elapsed)| *elapsed)
                .collect_vec();
            assert_eq!(times.len(), 31);
            times.sort_unstable();
            println!(
                "summary,{groups},{per_group},{adaptive},{},{},{}",
                times[0], times[15], times[30]
            );
        }
    }
}

impl<P: Preset> Pool<P> {
    async fn collect_epoch_baseline(&self, epoch: Epoch) -> Vec<PoolAttestation<P>> {
        self.aggregates
            .read()
            .await
            .get(&epoch)
            .into_iter()
            .flatten()
            .map(|(key, aggregates)| async {
                aggregates
                    .lock()
                    .await
                    .iter()
                    .cloned()
                    .map(|aggregate| {
                        let AttestationKey {
                            data,
                            committee_index,
                        } = *key;
                        let Aggregate {
                            aggregation_bits,
                            signature,
                        } = aggregate;

                        PoolAttestation {
                            aggregation_bits,
                            data,
                            committee_index,
                            signature: signature.into(),
                        }
                    })
                    .collect_vec()
            })
            .collect::<FuturesOrdered<_>>()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect_vec()
    }
}
