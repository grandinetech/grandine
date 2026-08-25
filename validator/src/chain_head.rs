use core::time::Duration;
use std::sync::{Arc, RwLock};

use anyhow::{Result, ensure};
use fork_choice_control::HeadEvent;
use futures::{StreamExt as _, future::join_all};
use logging::{debug_with_peers, info_with_peers};
use tap::Pipe as _;
use thiserror::Error;
use tokio::time::sleep;
use types::phase0::primitives::{H256, Slot};

use crate::{health::Health, remote_beacon_node::RemoteBeaconNode};

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
}

/// The head a beacon node last reported, over the event stream or when asked.
#[derive(Default)]
pub struct ChainHead {
    head: RwLock<Option<Head>>,
}

impl ChainHead {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            head: RwLock::new(None),
        }
    }

    /// [`None`] when nothing usable is cached and a beacon node has to be asked instead, and an
    /// error when the cached head is past `at_slot`, which asking would not fix.
    pub fn get(&self, at_slot: Slot, max_empty_slots: u64) -> Result<Option<H256>> {
        let cached = *self.head.read().expect("chain head lock is never poisoned");

        let Some(head) = cached else {
            return Ok(None);
        };

        ensure!(
            head.slot <= at_slot,
            Error::BeyondSlot {
                head_slot: head.slot,
                at_slot,
            },
        );

        // A head that predates a run of missed slots is still the one to vote for, held to the
        // same limit as the head of the built-in beacon node.
        if at_slot.saturating_sub(head.slot) > max_empty_slots {
            debug_with_peers!(
                "cached head at slot {} is too old to sign for slot {at_slot}",
                head.slot,
            );

            return Ok(None);
        }

        Ok(Some(head.block_root))
    }

    pub fn update(&self, slot: Slot, block_root: H256) {
        let mut head = self
            .head
            .write()
            .expect("chain head lock is never poisoned");

        if head.is_none_or(|current| slot >= current.slot) {
            *head = Some(Head { slot, block_root });
        }
    }

    /// [`Self::update`], also replacing a cached head past `at_slot`, which no honest node
    /// reports.
    pub fn overwrite(&self, at_slot: Slot, slot: Slot, block_root: H256) {
        let mut head = self
            .head
            .write()
            .expect("chain head lock is never poisoned");

        if head.is_none_or(|current| slot >= current.slot || current.slot > at_slot) {
            *head = Some(Head { slot, block_root });
        }
    }

    pub fn can_serve(&self, at_slot: Slot, max_empty_slots: u64) -> bool {
        self.get(at_slot, max_empty_slots)
            .is_ok_and(|block_root| block_root.is_some())
    }
}

pub async fn stream_head_events(nodes: Vec<Arc<RemoteBeaconNode>>) {
    nodes.into_iter().map(follow).pipe(join_all).await;
}

async fn follow(node: Arc<RemoteBeaconNode>) {
    let mut delay = RECONNECT_DELAY;
    let mut subscribed_before = false;

    loop {
        let delivered = match node.head_events().await {
            Ok(mut events) => {
                if subscribed_before {
                    debug_with_peers!("resubscribed to head events from {node}");
                } else {
                    info_with_peers!("subscribed to head events from {node}");
                    subscribed_before = true;
                }

                let mut delivered = false;

                while let Some(event) = events.next().await {
                    match event {
                        Ok(event) => {
                            delivered = true;
                            accept(&node, event);
                        }
                        Err(error) => {
                            debug_with_peers!("head event stream from {node} failed: {error:?}");
                            break;
                        }
                    }
                }

                // Answering without streaming anything is indistinguishable from never
                // having been asked.
                if !delivered {
                    debug_with_peers!("head event stream from {node} ended without any event");
                }

                delivered
            }
            Err(error) => {
                debug_with_peers!("unable to stream head events from {node}: {error:?}");
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

fn accept(node: &RemoteBeaconNode, event: HeadEvent) {
    // A node on a different network would otherwise report a head from another chain.
    if node.health() == Health::Incompatible {
        return;
    }

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

        chain_head.overwrite(6, 5, H256::repeat_byte(2));

        assert_eq!(
            chain_head.get(6, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(2))
        );

        Ok(())
    }

    #[test]
    fn only_a_later_head_replaces_the_cached_one() -> Result<()> {
        let chain_head = ChainHead::default();

        chain_head.update(6, H256::repeat_byte(1));
        chain_head.update(5, H256::repeat_byte(2));

        assert_eq!(
            chain_head.get(6, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(1))
        );

        chain_head.update(6, H256::repeat_byte(3));

        assert_eq!(
            chain_head.get(6, MAX_EMPTY_SLOTS)?,
            Some(H256::repeat_byte(3))
        );

        Ok(())
    }
}
