use core::{pin::pin, time::Duration};
use std::{
    sync::{Arc, RwLock},
    time::Instant,
};

use anyhow::Result;
use futures::{StreamExt as _, channel::mpsc::UnboundedSender, future::join_all};
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use tap::Pipe as _;
use thiserror::Error;
use tokio::time::sleep;
use types::{
    phase0::primitives::{Epoch, H256, Slot},
    preset::Preset,
};

use crate::{health::Health, messages::InternalMessage, remote_beacon_node::RemoteBeaconNode};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

const MAX_RECONNECT_DELAY: Duration = Duration::from_mins(1);

#[derive(Debug, Error)]
enum Error {
    #[error("cached head is at slot {head_slot}, past slot {at_slot} being signed for")]
    BeyondSlot { head_slot: Slot, at_slot: Slot },
}

#[derive(Clone, Copy)]
struct Head {
    slot: Slot,
    block_root: H256,
    /// When the node was seen holding this head.
    seen_at: Instant,
}

/// The roots the duties of an epoch and the next depend on, as reported with a head.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DependentRoots {
    /// The epoch of the head the roots were reported with.
    pub epoch: Epoch,
    pub current: H256,
    pub next: H256,
}

/// A head reported over the event stream, in either version of the event.
#[derive(Clone, Copy, Debug)]
pub struct HeadUpdate {
    pub slot: Slot,
    pub block: H256,
    pub execution_optimistic: bool,
    pub dependent_roots: DependentRoots,
}

/// What the event stream of a node delivers.
pub enum StreamEvent {
    Head(HeadUpdate),
    Finalized(Epoch),
}

/// What a cached head is worth at a slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeadStatus {
    /// Nothing has been reported yet.
    Unknown,
    /// The head to sign for.
    Usable(H256),
    /// Older than the empty slot limit allows.
    Stale { head_slot: Slot },
    /// Past the slot, which asking a node would not fix.
    Future { head_slot: Slot },
}

/// The head a beacon node last reported, over the event stream or when asked.
#[derive(Default)]
pub struct ChainHead {
    head: RwLock<Option<Head>>,
    dependent_roots: RwLock<Option<DependentRoots>>,
}

impl ChainHead {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            head: RwLock::new(None),
            dependent_roots: RwLock::new(None),
        }
    }

    pub fn dependent_root_for(&self, epoch: Epoch) -> Option<H256> {
        let roots = (*self
            .dependent_roots
            .read()
            .expect("dependent roots lock is never poisoned"))?;

        if epoch == roots.epoch {
            Some(roots.current)
        } else if epoch == roots.epoch.checked_add(1)? {
            Some(roots.next)
        } else {
            None
        }
    }

    pub fn record_dependent_roots(&self, roots: DependentRoots) {
        *self
            .dependent_roots
            .write()
            .expect("dependent roots lock is never poisoned") = Some(roots);
    }

    pub fn status(&self, at_slot: Slot, max_empty_slots: u64) -> HeadStatus {
        let Some(head) = *self.head.read().expect("chain head lock is never poisoned") else {
            return HeadStatus::Unknown;
        };

        if head.slot > at_slot {
            return HeadStatus::Future {
                head_slot: head.slot,
            };
        }

        // A head that predates a run of missed slots is still the one to vote for, held to the
        // same limit as the head of the built-in beacon node.
        if at_slot.saturating_sub(head.slot) > max_empty_slots {
            return HeadStatus::Stale {
                head_slot: head.slot,
            };
        }

        HeadStatus::Usable(head.block_root)
    }

    pub fn get(&self, at_slot: Slot, max_empty_slots: u64) -> Result<Option<H256>> {
        match self.status(at_slot, max_empty_slots) {
            HeadStatus::Usable(block_root) => Ok(Some(block_root)),
            HeadStatus::Unknown => Ok(None),
            HeadStatus::Stale { head_slot } => {
                debug_with_peers!(
                    "cached head at slot {head_slot} is too old to sign for slot {at_slot}",
                );

                Ok(None)
            }
            // Asking a beacon node would not fix a head past the slot being signed for.
            HeadStatus::Future { head_slot } => {
                Err(Error::BeyondSlot { head_slot, at_slot }.into())
            }
        }
    }

    pub fn cached(&self) -> Option<(Slot, H256)> {
        self.head
            .read()
            .expect("chain head lock is never poisoned")
            .map(|head| (head.slot, head.block_root))
    }

    pub fn update(&self, slot: Slot, block_root: H256) {
        // The latest report is the node's head whatever its slot; a reorg can move it back.
        *self
            .head
            .write()
            .expect("chain head lock is never poisoned") = Some(Head {
            slot,
            block_root,
            seen_at: Instant::now(),
        });
    }

    /// [`update`] for a head a node was asked for at `asked_at`: the node held it then, not when
    /// it answered, so a head delivered since is the newer one and stays.
    pub fn update_seen_at(&self, asked_at: Instant, slot: Slot, block_root: H256) -> bool {
        let mut head = self
            .head
            .write()
            .expect("chain head lock is never poisoned");

        if head.is_some_and(|head| head.seen_at >= asked_at) {
            return false;
        }

        *head = Some(Head {
            slot,
            block_root,
            seen_at: asked_at,
        });
        true
    }
}

pub async fn stream_events<P: Preset>(
    nodes: Vec<Arc<RemoteBeaconNode>>,
    internal_tx: UnboundedSender<InternalMessage>,
) {
    nodes
        .into_iter()
        .map(|node| follow::<P>(node, internal_tx.clone()))
        .pipe(join_all)
        .await;
}

async fn follow<P: Preset>(
    node: Arc<RemoteBeaconNode>,
    internal_tx: UnboundedSender<InternalMessage>,
) {
    let mut delay = RECONNECT_DELAY;
    let mut subscribed_before = false;

    loop {
        let delivered = match node.events::<P>().await {
            Ok(events) => {
                let mut events = pin!(events);

                if subscribed_before {
                    info_with_peers!("resubscribed to events from {node}");
                } else {
                    info_with_peers!("subscribed to events from {node}");
                    subscribed_before = true;
                }

                let mut delivered = false;

                while let Some(event) = events.next().await {
                    match event {
                        Ok(event) => {
                            delivered = true;

                            // A node on a different network would otherwise report a head from
                            // another chain.
                            if node.health() == Health::Incompatible {
                                warn_with_peers!(
                                    "received an event from an incompatible node: {node}"
                                );

                                continue;
                            }

                            match event {
                                StreamEvent::Head(update) => {
                                    accept(&node, update);
                                }
                                StreamEvent::Finalized(epoch) => {
                                    InternalMessage::FinalizedCheckpoint(epoch).send(&internal_tx);
                                }
                            }
                        }
                        Err(error) => {
                            warn_with_peers!("event stream from {node} failed: {error:?}");
                            break;
                        }
                    }
                }

                // Answering without streaming anything is indistinguishable from never
                // having been asked.
                if !delivered {
                    warn_with_peers!("event stream from {node} ended without any event");
                }

                delivered
            }
            Err(error) => {
                warn_with_peers!("unable to stream events from {node}: {error:?}");
                false
            }
        };

        // Connecting to a node that streams nothing fails as surely as not connecting at all,
        // so only events that arrive shorten the wait again.
        if delivered {
            delay = RECONNECT_DELAY;
        }

        sleep(delay).await;

        delay = delay.saturating_mul(2).min(MAX_RECONNECT_DELAY);
    }
}

fn accept(node: &RemoteBeaconNode, event: HeadUpdate) {
    // A node on a different network would otherwise report a head from another chain.
    if node.health() == Health::Incompatible {
        return;
    }

    // The roots only decide whether duties are fetched again, so an optimistic head may report
    // them; nothing is signed by them.
    node.chain_head()
        .record_dependent_roots(event.dependent_roots);

    // An optimistic validator must not sign across the sync committee domains.
    if event.execution_optimistic {
        return;
    }

    node.chain_head().update(event.slot, event.block);
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_EMPTY_SLOTS: u64 = 8;

    #[test]
    fn a_head_at_or_before_the_slot_is_signed_for() -> Result<()> {
        let chain_head = ChainHead::default();

        assert_eq!(chain_head.get(6, MAX_EMPTY_SLOTS)?, None);

        chain_head.update(6, H256::repeat_byte(1));

        assert_eq!(
            chain_head.get(6, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(1))
        );
        assert_eq!(
            chain_head.get(7, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(1))
        );

        chain_head
            .get(5, MAX_EMPTY_SLOTS)
            .expect_err("the tracker has moved past slot 5");

        Ok(())
    }

    #[test]
    fn a_head_further_behind_than_max_empty_slots_is_not_signed_for() -> Result<()> {
        let chain_head = ChainHead::default();

        chain_head.update(6, H256::repeat_byte(1));

        assert!(chain_head.get(14, MAX_EMPTY_SLOTS)?.is_some());
        assert_eq!(chain_head.get(15, MAX_EMPTY_SLOTS)?, None);

        Ok(())
    }

    #[test]
    fn a_polled_head_replaces_a_cached_one_from_the_future() -> Result<()> {
        let chain_head = ChainHead::default();

        chain_head.update(u64::MAX, H256::repeat_byte(1));

        chain_head
            .get(6, MAX_EMPTY_SLOTS)
            .expect_err("the cached head is past slot 6");

        chain_head.update(5, H256::repeat_byte(2));

        assert_eq!(
            chain_head.get(6, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(2))
        );

        Ok(())
    }

    // A poll answered after the stream moved the head must not move it back.
    #[test]
    fn a_head_delivered_since_a_poll_was_sent_outlives_the_answer() -> Result<()> {
        let chain_head = ChainHead::default();
        chain_head.update(5, H256::repeat_byte(1));

        let asked_at = Instant::now();
        chain_head.update(6, H256::repeat_byte(2));

        assert!(!chain_head.update_seen_at(asked_at, 5, H256::repeat_byte(1)));
        assert_eq!(
            chain_head.get(6, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(2))
        );

        // Asked after the last delivery, the answer stands, even for an earlier slot.
        assert!(chain_head.update_seen_at(Instant::now(), 5, H256::repeat_byte(3)));
        assert_eq!(
            chain_head.get(6, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(3))
        );

        Ok(())
    }

    #[test]
    fn dependent_roots_serve_the_reported_epoch_and_the_next() {
        let chain_head = ChainHead::default();

        assert_eq!(chain_head.dependent_root_for(5), None);

        chain_head.record_dependent_roots(DependentRoots {
            epoch: 5,
            current: H256::repeat_byte(1),
            next: H256::repeat_byte(2),
        });

        assert_eq!(chain_head.dependent_root_for(4), None);
        assert_eq!(chain_head.dependent_root_for(5), Some(H256::repeat_byte(1)));
        assert_eq!(chain_head.dependent_root_for(6), Some(H256::repeat_byte(2)));
        assert_eq!(chain_head.dependent_root_for(7), None);
    }

    // A reorg into the previous epoch replaces the orphaned branch's roots, so the latest report
    // wins even when it is for an earlier epoch.
    #[test]
    fn the_latest_dependent_roots_win_regardless_of_epoch() {
        let chain_head = ChainHead::default();

        chain_head.record_dependent_roots(DependentRoots {
            epoch: 5,
            current: H256::repeat_byte(1),
            next: H256::repeat_byte(2),
        });

        chain_head.record_dependent_roots(DependentRoots {
            epoch: 4,
            current: H256::repeat_byte(3),
            next: H256::repeat_byte(4),
        });

        assert_eq!(chain_head.dependent_root_for(4), Some(H256::repeat_byte(3)));
        assert_eq!(chain_head.dependent_root_for(5), Some(H256::repeat_byte(4)));
        assert_eq!(chain_head.dependent_root_for(6), None);
    }

    // A node reorging to a shorter branch reports a lower head, which must not be left behind.
    #[test]
    fn a_reorg_to_a_lower_slot_replaces_the_cached_head() -> Result<()> {
        let chain_head = ChainHead::default();

        chain_head.update(6, H256::repeat_byte(1));
        chain_head.update(5, H256::repeat_byte(2));

        assert_eq!(
            chain_head.get(6, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(2))
        );

        Ok(())
    }

    #[test]
    fn an_empty_cache_is_unknown_rather_than_stale() {
        assert_eq!(ChainHead::new().status(100, 5), HeadStatus::Unknown);
    }

    #[test]
    fn a_head_within_the_empty_slot_limit_is_not_stale() {
        let chain_head = ChainHead::new();
        chain_head.update(95, H256::repeat_byte(1));

        assert_eq!(
            chain_head.status(100, 5),
            HeadStatus::Usable(H256::repeat_byte(1))
        );
    }

    #[test]
    fn a_head_beyond_the_empty_slot_limit_is_stale() {
        let chain_head = ChainHead::new();
        chain_head.update(61, H256::repeat_byte(1));

        assert_eq!(
            chain_head.status(143, 32),
            HeadStatus::Stale { head_slot: 61 }
        );
    }
}
