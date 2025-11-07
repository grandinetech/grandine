use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::Result;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::misc;
use logging::{debug_with_peers, warn_with_peers};
use types::{
    altair::containers::SyncCommitteeMessage,
    phase0::primitives::{Epoch, H256, Slot, ValidatorIndex},
    preset::Preset,
    traits::SignedBeaconBlock as _,
};

#[derive(Debug)]
#[cfg_attr(test, derive(Default))]
pub struct ValidatorVote {
    pub validator_index: ValidatorIndex,
    pub beacon_block_root: H256,
    pub slot: Slot,
}

pub type VoteSummaries = BTreeMap<VoteSummary, BTreeSet<ValidatorIndex>>;

pub struct VoteReport {
    pub vote_summaries: VoteSummaries,
    pub canonical_votes: usize,
    pub total_votes: usize,
}

#[derive(Default)]
pub struct ValidatorVotes {
    votes: HashMap<Epoch, HashMap<Slot, HashMap<H256, HashSet<ValidatorIndex>>>>,
}

impl ValidatorVotes {
    pub fn get(
        &self,
        epoch: Epoch,
    ) -> Option<&HashMap<Slot, HashMap<H256, HashSet<ValidatorIndex>>>> {
        self.votes.get(&epoch)
    }

    pub fn insert_vote(&mut self, epoch: Epoch, vote: &ValidatorVote) -> bool {
        let ValidatorVote {
            validator_index,
            beacon_block_root,
            slot,
        } = vote;

        self.votes
            .entry(epoch)
            .or_default()
            .entry(*slot)
            .or_default()
            .entry(*beacon_block_root)
            .or_default()
            .insert(*validator_index)
    }

    pub fn prune_older_than(&mut self, epoch: Epoch) {
        self.votes.retain(|vote_epoch, _| *vote_epoch >= epoch);
    }

    pub fn len(&self) -> usize {
        self.votes
            .values()
            .flat_map(|epoch_votes| epoch_votes.values())
            .flat_map(|slot_votes| slot_votes.values())
            .map(HashSet::len)
            .sum()
    }

    pub fn vote_report<P: Preset, W: Wait>(
        &self,
        controller: &ApiController<P, W>,
        epoch: Epoch,
    ) -> Result<Option<VoteReport>> {
        let Some(validator_votes) = self.votes.get(&epoch) else {
            return Ok(None);
        };

        let previous_epoch = misc::previous_epoch(epoch);

        // Take beacon blocks from `epoch` and the epoch before it in case the first
        // slot(s) of `epoch` are empty.
        let start_slot = misc::compute_start_slot_at_epoch::<P>(previous_epoch);
        let end_slot = misc::compute_start_slot_at_epoch::<P>(epoch + 1);

        // We assume that stored blocks from previous epoch do reflect canonical chain
        let canonical_blocks_with_roots = controller.blocks_by_range(start_slot..end_slot)?;

        let root_to_block_map = canonical_blocks_with_roots
            .iter()
            .map(|block_with_root| (block_with_root.root, block_with_root))
            .collect::<HashMap<_, _>>();

        let slot_to_block_map = canonical_blocks_with_roots
            .iter()
            .map(|block_with_root| (block_with_root.block.message().slot(), block_with_root))
            .collect::<HashMap<_, _>>();

        let mut canonical_votes = 0;
        let mut total_votes = 0;
        let mut vote_summaries: VoteSummaries = BTreeMap::new();

        debug_with_peers!(
            "{} total votes for {epoch} epoch",
            validator_votes
                .values()
                .flat_map(|slot_votes| slot_votes.values())
                .map(HashSet::len)
                .sum::<usize>()
        );

        for (voted_slot, block_votes) in validator_votes {
            let total_votes_for_slot = block_votes.values().map(HashSet::len).sum();

            total_votes += total_votes_for_slot;

            for (voted_root, voter_indices) in block_votes {
                let canonical_block_at_slot_or_closest = (start_slot..=*voted_slot)
                    .rev()
                    .find_map(|s| slot_to_block_map.get(&s));

                let summary = match canonical_block_at_slot_or_closest {
                    Some(canonical_block) if canonical_block.root == *voted_root => {
                        canonical_votes += voter_indices.len();

                        VoteSummary::Correct {
                            slot: *voted_slot,
                            total: total_votes_for_slot,
                        }
                    }
                    Some(canonical_block) => {
                        let mut ancestors =
                            core::iter::successors(Some(canonical_block), |block_with_root| {
                                root_to_block_map
                                    .get(&block_with_root.block.message().parent_root())
                            });

                        let canonical_ancestor =
                            ancestors.find(|block_with_root| block_with_root.root == *voted_root);

                        let canonical_root = canonical_block.root;

                        if let Some(&ancestor_with_root) = canonical_ancestor {
                            let ancestor_slot = ancestor_with_root.block.message().slot();
                            let slot_diff = voted_slot - ancestor_slot;

                            VoteSummary::Outdated {
                                voted_root: *voted_root,
                                voted_slot: *voted_slot,
                                canonical_root,
                                slot_diff,
                            }
                        } else {
                            VoteSummary::NonCanonical {
                                voted_root: *voted_root,
                                voted_slot: *voted_slot,
                                canonical_root,
                            }
                        }
                    }
                    None => VoteSummary::MissingBlock {
                        voted_root: *voted_root,
                        voted_slot: *voted_slot,
                    },
                };

                vote_summaries
                    .entry(summary)
                    .or_default()
                    .extend(voter_indices);
            }
        }

        Ok(Some(VoteReport {
            vote_summaries,
            canonical_votes,
            total_votes,
        }))
    }
}

impl From<SyncCommitteeMessage> for ValidatorVote {
    fn from(sync_committee_message: SyncCommitteeMessage) -> Self {
        let SyncCommitteeMessage {
            slot,
            beacon_block_root,
            validator_index,
            ..
        } = sync_committee_message;

        Self {
            validator_index,
            beacon_block_root,
            slot,
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum VoteSummary {
    Correct {
        slot: Slot,
        total: usize,
    },
    MissingBlock {
        voted_slot: Slot,
        voted_root: H256,
    },
    NonCanonical {
        voted_slot: Slot,
        voted_root: H256,
        canonical_root: H256,
    },
    Outdated {
        voted_slot: Slot,
        voted_root: H256,
        canonical_root: H256,
        slot_diff: u64,
    },
}

pub fn report_attestation_votes(vote_summaries: VoteSummaries) {
    for (summary, validator_indices) in vote_summaries {
        match summary {
            VoteSummary::Correct { slot, total } => {
                debug_with_peers!(
                    "{} of {total} validators voted correctly in slot {slot}",
                    validator_indices.len()
                );
            }
            VoteSummary::MissingBlock {
                voted_slot,
                voted_root,
            } => {
                warn_with_peers!(
                    "cannot find beacon block that validators {validator_indices:?} voted for \
                    at slot {voted_slot} (voted for block {voted_root:?})",
                );
            }
            VoteSummary::NonCanonical {
                voted_slot,
                voted_root,
                canonical_root,
            } => {
                warn_with_peers!(
                    "validators {validator_indices:?} voted for \
                    non-canonical block {voted_root:?} at slot {voted_slot} \
                    (expected to vote for block {canonical_root:?})",
                );
            }
            VoteSummary::Outdated {
                voted_slot,
                voted_root,
                canonical_root,
                slot_diff,
            } => {
                warn_with_peers!(
                    "validators {validator_indices:?} voted for \
                    outdated head {voted_root:?} (by {slot_diff} slots) at slot {voted_slot} \
                    (expected to vote for block {canonical_root:?})",
                );
            }
        }
    }
}

pub fn report_sync_committee_votes(vote_summaries: VoteSummaries) {
    for (summary, validator_indices) in vote_summaries {
        match summary {
            VoteSummary::Correct { slot, total } => {
                debug_with_peers!(
                    "{} of {total} validators participated in sync committees \
                    correctly in slot {slot}",
                    validator_indices.len()
                );
            }
            VoteSummary::MissingBlock {
                voted_slot,
                voted_root,
            } => {
                warn_with_peers!(
                    "cannot find beacon block that validators {validator_indices:?} sent \
                    sync committee messages for at slot {voted_slot} \
                    (sent sync committee messages for block {voted_root:?})",
                );
            }
            VoteSummary::NonCanonical {
                voted_slot,
                voted_root,
                canonical_root,
            } => {
                warn_with_peers!(
                    "validators {validator_indices:?} sent sync committee messages for \
                    non-canonical block {voted_root:?} at slot {voted_slot} \
                    (expected to sent sync committee messages for block {canonical_root:?})",
                );
            }
            VoteSummary::Outdated {
                voted_slot,
                voted_root,
                canonical_root,
                slot_diff,
            } => {
                warn_with_peers!(
                    "validators {validator_indices:?} sent sync committee messages for \
                    outdated head {voted_root:?} (by {slot_diff} slots) at slot {voted_slot} \
                    (expected to sent sync committee messages for block {canonical_root:?})",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ValidatorVote, ValidatorVotes};

    #[test]
    fn test_votes() {
        let mut votes = ValidatorVotes::default();

        let vote = ValidatorVote::default();

        assert!(votes.insert_vote(1, &vote));
        assert!(!votes.insert_vote(1, &vote));
        assert_eq!(votes.len(), 1);
    }
}
