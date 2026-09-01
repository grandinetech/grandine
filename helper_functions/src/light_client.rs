use crate::misc::{compute_epoch_at_slot, sync_committee_period};
use anyhow::{Ok, Result, bail, ensure};
use hashing::ZERO_HASHES;
use itertools::Itertools as _;
use ssz::{ContiguousVector, SszHash as _};
use thiserror::Error;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    altair::{
        beacon_state::BeaconState as AltairBeaconState, consts::{CurrentSyncCommitteeIndex, FinalizedRootIndex, NextSyncCommitteeIndex}, containers::{LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate, LightClientUpdate, SyncCommittee},
    }, phase0::{
        consts::GENESIS_SLOT,
        containers::Checkpoint,
        primitives::{H256, Slot},
    }, preset::Preset, traits::{BeaconBlock as _, BeaconState, SignedBeaconBlock},
};

pub fn block_to_light_client_header<P: Preset>(
    block: &impl SignedBeaconBlock<P>,
) -> LightClientHeader {
    LightClientHeader {
        beacon: block.message().to_header(),
    }
}

// `consensus-specs` builds light client proofs with `compute_merkle_proof(object, gindex)`, which
// walks an arbitrary generalized index over an arbitrary SSZ object at runtime. We cannot express
// the `object` half of that: `ssz_derive` unrolls merkleization into a single nested expression at
// compile time, and Rust has no runtime reflection over struct fields, so there is no way to ask a
// value for its chunks generically.
//
// We can express everything else. `container_proof` walks any generalized index over any list of
// chunks, and `compute_merkle_proof` supplies the chunks for the Altair `BeaconState` and recurses
// into nested containers. Only `state_chunks` has to be written out by hand, and only its field
// order can be wrong -- which is checkable against the struct at a glance, unlike the sibling
// arithmetic it replaces.

/// The Merkle proof for `gindex` within a container whose chunks are `chunks`.
///
/// `chunks` is padded to a power of two with zero leaves, so the zero subtrees fall out of the
/// hashing rather than having to be named.
fn container_proof(chunks: &[H256], gindex: u64) -> Result<Vec<H256>> {
    let leaves = chunks.len().next_power_of_two();
    let depth = leaves.ilog2();

    ensure!(
        gindex.ilog2() == depth,
        Error::GeneralizedIndexNotALeaf { gindex, depth },
    );

    let mut index = usize::try_from(gindex)?
        .checked_sub(leaves)
        .ok_or(Error::GeneralizedIndexNotALeaf { gindex, depth })?;

    let mut level = chunks
        .iter()
        .copied()
        .chain(core::iter::repeat(ZERO_HASHES[0]))
        .take(leaves)
        .collect_vec();

    let mut proof = Vec::with_capacity(depth.try_into()?);

    for _ in 0..depth {
        proof.push(level[index ^ 1]);

        level = level
            .into_iter()
            .tuples()
            .map(|(left, right)| hashing::hash_256_256(left, right))
            .collect();

        index /= 2;
    }

    Ok(proof)
}

/// The chunks of an Altair [`BeaconState`], in SSZ field order.
///
/// This is the only part of proof construction that is written out by hand. Keep it in sync with
/// [`BeaconState`]; the generalized indices in [`types::altair::consts`] assume this exact order and
/// count.
///
/// [`BeaconState`]: AltairBeaconState
fn state_chunks<P: Preset>(state: &AltairBeaconState<P>) -> [H256; 24] {
    [
        state.genesis_time.hash_tree_root(),
        state.genesis_validators_root.hash_tree_root(),
        state.slot.hash_tree_root(),
        state.fork.hash_tree_root(),
        state.latest_block_header.hash_tree_root(),
        state.block_roots.hash_tree_root(),
        state.state_roots.hash_tree_root(),
        state.historical_roots.hash_tree_root(),
        state.eth1_data.hash_tree_root(),
        state.eth1_data_votes.hash_tree_root(),
        state.eth1_deposit_index.hash_tree_root(),
        state.validators.hash_tree_root(),
        state.balances.hash_tree_root(),
        state.randao_mixes.hash_tree_root(),
        state.slashings.hash_tree_root(),
        state.previous_epoch_participation.hash_tree_root(),
        state.current_epoch_participation.hash_tree_root(),
        state.justification_bits.hash_tree_root(),
        state.previous_justified_checkpoint.hash_tree_root(),
        state.current_justified_checkpoint.hash_tree_root(),
        state.finalized_checkpoint.hash_tree_root(),
        state.inactivity_scores.hash_tree_root(),
        state.current_sync_committee.hash_tree_root(),
        state.next_sync_committee.hash_tree_root(),
    ]
}

fn checkpoint_chunks(checkpoint: Checkpoint) -> [H256; 2] {
    [
        checkpoint.epoch.hash_tree_root(),
        checkpoint.root.hash_tree_root(),
    ]
}

/// [`compute_merkle_proof`](https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/altair/light-client/full-node.md)
/// specialized to the Altair [`BeaconState`].
///
/// Handles generalized indices that name a field of the state directly, and ones that descend into
/// a nested container. `consensus-specs` composes the latter with `concat_generalized_indices`; we
/// undo that composition here, which is why the sub-proof is emitted first: proofs run from the leaf
/// upwards, so the deeper siblings come first.
///
/// [`BeaconState`]: AltairBeaconState
pub fn compute_merkle_proof<P: Preset>(
    state: &AltairBeaconState<P>,
    gindex: u64,
) -> Result<Vec<H256>> {
    let chunks = state_chunks(state);
    let leaves = chunks.len().next_power_of_two();
    let depth = leaves.ilog2();
    let path_length = gindex.ilog2();

    if path_length == depth {
        return container_proof(&chunks, gindex);
    }

    ensure!(
        path_length > depth,
        Error::GeneralizedIndexNotALeaf { gindex, depth },
    );

    // Split `gindex` into the path through the state and the path through the nested container.
    let remaining = path_length - depth;
    let in_state = gindex >> remaining;
    let in_child = (gindex & ((1 << remaining) - 1)) | (1 << remaining);

    let field_index = usize::try_from(in_state)?
        .checked_sub(leaves)
        .ok_or(Error::GeneralizedIndexNotALeaf { gindex, depth })?;

    let child_chunks = match field_index {
        18 => checkpoint_chunks(state.previous_justified_checkpoint),
        19 => checkpoint_chunks(state.current_justified_checkpoint),
        20 => checkpoint_chunks(state.finalized_checkpoint),
        _ => bail!(Error::NoProofGeneratorForField {
            field_index,
            gindex
        }),
    };

    let child_proof = container_proof(&child_chunks, in_child)?;
    let state_proof = container_proof(&chunks, in_state)?;

    Ok(child_proof.into_iter().chain(state_proof).collect())
}

pub fn create_light_client_bootstrap<P: Preset>(
    state: &AltairBeaconState<P>,
    block: &impl SignedBeaconBlock<P>,
) -> Result<LightClientBootstrap<P>> {
    ensure!(
        state.slot == state.latest_block_header.slot,
        Error::StateSlotDoesNotMatchLatestBlockHeader {
            state_slot: state.slot,
            header_slot: state.latest_block_header.slot,
        },
    );

    let mut header = state.latest_block_header;
    header.state_root = state.hash_tree_root();

    let header_root = header.hash_tree_root();
    let block_root = block.message().hash_tree_root();

    ensure!(
        header_root == block_root,
        Error::StateIsNotPostStateOfBlock {
            header_root,
            block_root,
        },
    );

    let branch = compute_merkle_proof(state, CurrentSyncCommitteeIndex::U64)?;

    Ok(LightClientBootstrap {
        header: block_to_light_client_header(block),
        current_sync_committee: (**state.current_sync_committee).clone(),
        current_sync_committee_branch: ContiguousVector::try_from_iter(branch)?,
    })
}

pub fn create_light_client_update<P: Preset>(
    state: &AltairBeaconState<P>,
    block: &impl SignedBeaconBlock<P>,
    attested_state: &AltairBeaconState<P>,
    attested_block: &impl SignedBeaconBlock<P>,
    finalized_block: Option<&impl SignedBeaconBlock<P>>,
) -> Result<LightClientUpdate<P>> {
    let sync_aggregate = block
        .message()
        .body()
        .with_sync_aggregate()
        .ok_or(Error::BlockHasNoSyncAggregate)?
        .sync_aggregate();

    let participants = sync_aggregate.sync_committee_bits.count_ones();

    ensure!(
        participants >= P::MIN_SYNC_COMMITTEE_PARTICIPANTS,
        Error::InsufficientSyncCommitteeParticipants {
            participants,
            minimum: P::MIN_SYNC_COMMITTEE_PARTICIPANTS,
        },
    );

    ensure!(
        state.slot == state.latest_block_header.slot,
        Error::StateSlotDoesNotMatchLatestBlockHeader {
            state_slot: state.slot,
            header_slot: state.latest_block_header.slot,
        },
    );

    let mut header = state.latest_block_header;
    header.state_root = state.hash_tree_root();

    let header_root = header.hash_tree_root();
    let block_root = block.message().hash_tree_root();

    ensure!(
        header_root == block_root,
        Error::StateIsNotPostStateOfBlock {
            header_root,
            block_root,
        },
    );

    ensure!(
        attested_state.slot() == attested_state.latest_block_header().slot,
        Error::StateSlotDoesNotMatchLatestBlockHeader {
            state_slot: attested_state.slot(),
            header_slot: attested_state.latest_block_header().slot,
        },
    );

    let mut attested_header = attested_state.latest_block_header();
    attested_header.state_root = attested_state.hash_tree_root();

    let attested_header_root = attested_header.hash_tree_root();
    let attested_block_root = attested_block.message().hash_tree_root();

    ensure!(
        attested_header_root == attested_block_root,
        Error::StateIsNotPostStateOfBlock {
            header_root: attested_header_root,
            block_root: attested_block_root,
        },
    );

    let parent_root = block.message().parent_root();

    ensure!(
        attested_header_root == parent_root,
        Error::AttestedBlockIsNotParentOfBlock {
            attested_block_root: attested_header_root,
            parent_root,
        },
    );

    let signature_period =
        sync_committee_period::<P>(compute_epoch_at_slot::<P>(block.message().slot()));
    let attested_period =
        sync_committee_period::<P>(compute_epoch_at_slot::<P>(attested_block.message().slot()));

    let (next_sync_committee, next_sync_committee_branch) = if attested_period == signature_period {
        let branch = compute_merkle_proof(attested_state, NextSyncCommitteeIndex::U64)?;

        (
            (**attested_state.next_sync_committee).clone(),
            ContiguousVector::try_from_iter(branch)?,
        )
    } else {
        (SyncCommittee::default(), ContiguousVector::default())
    };

    let (finalized_header, finality_branch) = if let Some(finalized_block) = finalized_block {
        let checkpoint_root = attested_state.finalized_checkpoint.root;

        let finalized_header = if finalized_block.message().slot() == GENESIS_SLOT {
            ensure!(
                checkpoint_root.is_zero(),
                Error::GenesisFinalizedBlockWithNonZeroCheckpoint { checkpoint_root },
            );

            LightClientHeader::default()
        } else {
            let finalized_header = block_to_light_client_header(finalized_block);
            let finalized_header_root = finalized_header.beacon.hash_tree_root();

            ensure!(
                finalized_header_root == checkpoint_root,
                Error::FinalizedBlockDoesNotMatchCheckpoint {
                    finalized_header_root,
                    checkpoint_root,
                },
            );

            finalized_header
        };

        let branch = compute_merkle_proof(attested_state, FinalizedRootIndex::U64)?;

        (finalized_header, ContiguousVector::try_from_iter(branch)?)
    } else {
        (LightClientHeader::default(), ContiguousVector::default())
    };

    Ok(LightClientUpdate {
        attested_header: block_to_light_client_header(attested_block),
        next_sync_committee,
        next_sync_committee_branch,
        finalized_header,
        finality_branch,
        sync_aggregate,
        signature_slot: block.message().slot(),
    })
}

pub fn create_light_client_finality_update<P: Preset>(update: LightClientUpdate<P>) -> Result<LightClientFinalityUpdate<P>> {
    Ok(LightClientFinalityUpdate{
        attested_header: update.attested_header,
        finalized_header: update.finalized_header,
        finality_branch: update.finality_branch,
        sync_aggregate: update.sync_aggregate,
        signature_slot: update.signature_slot
    })
}

pub fn create_light_client_optimistic_update<P: Preset>(update: LightClientUpdate<P>) -> Result<LightClientOptimisticUpdate<P>> {
    Ok(LightClientOptimisticUpdate { attested_header: update.attested_header, sync_aggregate: update.sync_aggregate, signature_slot: update.signature_slot })
}

#[derive(Debug, Error)]
enum Error {
    #[error("generalized index {gindex} is not a leaf of a tree of depth {depth}")]
    GeneralizedIndexNotALeaf { gindex: u64, depth: u32 },
    #[error(
        "no proof generator for generalized index {gindex} \
         (descends into BeaconState field {field_index})"
    )]
    NoProofGeneratorForField { field_index: usize, gindex: u64 },
    #[error("state slot {state_slot} does not match latest block header slot {header_slot}")]
    StateSlotDoesNotMatchLatestBlockHeader { state_slot: Slot, header_slot: Slot },
    #[error(
        "state with block header root {header_root:?} is not the post state of block {block_root:?}"
    )]
    StateIsNotPostStateOfBlock { header_root: H256, block_root: H256 },
    #[error("block body has no sync aggregate")]
    BlockHasNoSyncAggregate,
    #[error("sync aggregate has {participants} participants, expected at least {minimum}")]
    InsufficientSyncCommitteeParticipants { participants: usize, minimum: usize },
    #[error(
        "attested block root {attested_block_root:?} does not match block parent root {parent_root:?}"
    )]
    AttestedBlockIsNotParentOfBlock {
        attested_block_root: H256,
        parent_root: H256,
    },
    #[error(
        "finalized header root {finalized_header_root:?} does not match checkpoint root {checkpoint_root:?}"
    )]
    FinalizedBlockDoesNotMatchCheckpoint {
        finalized_header_root: H256,
        checkpoint_root: H256,
    },
    #[error(
        "finalized block is the genesis block but checkpoint root {checkpoint_root:?} is not zero"
    )]
    GenesisFinalizedBlockWithNonZeroCheckpoint { checkpoint_root: H256 },
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arithmetic::U64Ext as _;
    use bls::{AggregatePublicKeyBytes, PublicKeyBytes};
    use ssz::{ContiguousVector, Hc};
    use try_from_iterator::TryFromIterator as _;
    use typenum::Unsigned as _;
    use types::{
        altair::{
            consts::{CurrentSyncCommitteeIndex, FinalizedRootIndex, NextSyncCommitteeIndex},
            containers::SyncCommittee,
        },
        phase0::containers::{BeaconBlockHeader, Eth1Data, Fork, Validator},
        preset::Minimal,
    };

    use crate::predicates::is_valid_merkle_branch;

    use super::*;

    fn distinct_sync_committee(byte: u8) -> Arc<Hc<SyncCommittee<Minimal>>> {
        Arc::new(Hc::from(SyncCommittee {
            pubkeys: Box::new(
                ContiguousVector::try_from_iter(core::iter::repeat_n(
                    PublicKeyBytes::repeat_byte(byte),
                    <Minimal as Preset>::SyncCommitteeSize::USIZE,
                ))
                .expect("length matches SyncCommitteeSize"),
            ),
            aggregate_pubkey: AggregatePublicKeyBytes::repeat_byte(byte),
        }))
    }

    /// A state whose every field relevant to a light client proof is distinguishable, so that a
    /// transposed chunk changes the computed root.
    fn nontrivial_state() -> AltairBeaconState<Minimal> {
        AltairBeaconState {
            genesis_time: 1,
            genesis_validators_root: H256::repeat_byte(2),
            slot: 3,
            fork: Fork {
                epoch: 4,
                ..Fork::default()
            },
            latest_block_header: BeaconBlockHeader {
                slot: 5,
                ..BeaconBlockHeader::default()
            },
            eth1_data: Eth1Data {
                deposit_count: 6,
                ..Eth1Data::default()
            },
            eth1_deposit_index: 7,
            validators: [Validator {
                effective_balance: 8,
                ..Validator::default()
            }]
            .try_into()
            .expect("one validator fits"),
            balances: [9].try_into().expect("one balance fits"),
            previous_justified_checkpoint: Checkpoint {
                epoch: 10,
                root: H256::repeat_byte(10),
            },
            current_justified_checkpoint: Checkpoint {
                epoch: 11,
                root: H256::repeat_byte(11),
            },
            finalized_checkpoint: Checkpoint {
                epoch: 12,
                root: H256::repeat_byte(12),
            },
            inactivity_scores: [13].try_into().expect("one score fits"),
            current_sync_committee: distinct_sync_committee(14),
            next_sync_committee: distinct_sync_committee(15),
            ..AltairBeaconState::default()
        }
    }

    /// `is_valid_merkle_branch` wants an index into the leaves, not a generalized index.
    fn index_at_leaf_depth(gindex: u64) -> u64 {
        gindex - gindex.prev_power_of_two()
    }

    #[test]
    fn sync_committee_proofs_reconstruct_the_state_root() {
        let state = nontrivial_state();
        let root = state.hash_tree_root();

        assert!(is_valid_merkle_branch(
            state.current_sync_committee.hash_tree_root(),
            compute_merkle_proof(&state, CurrentSyncCommitteeIndex::U64)
                .expect("proof is constructible"),
            index_at_leaf_depth(CurrentSyncCommitteeIndex::U64),
            root,
        ));

        assert!(is_valid_merkle_branch(
            state.next_sync_committee.hash_tree_root(),
            compute_merkle_proof(&state, NextSyncCommitteeIndex::U64)
                .expect("proof is constructible"),
            index_at_leaf_depth(NextSyncCommitteeIndex::U64),
            root,
        ));
    }

    #[test]
    fn finality_proof_reconstructs_the_state_root() {
        let state = nontrivial_state();

        assert!(is_valid_merkle_branch(
            state.finalized_checkpoint.root,
            compute_merkle_proof(&state, FinalizedRootIndex::U64).expect("proof is constructible"),
            index_at_leaf_depth(FinalizedRootIndex::U64),
            state.hash_tree_root(),
        ));
    }

    /// The point of taking a generalized index at runtime: indices the light client protocol does
    /// not use work too, with no code written for them.
    #[test]
    fn arbitrary_generalized_indices_verify() {
        let state = nontrivial_state();
        let root = state.hash_tree_root();

        // `BeaconState.validators`, field 11, a direct leaf.
        assert!(is_valid_merkle_branch(
            state.validators.hash_tree_root(),
            compute_merkle_proof(&state, 43).expect("43 is a state field"),
            index_at_leaf_depth(43),
            root,
        ));

        // `BeaconState.current_justified_checkpoint.root`, descending into a nested container that
        // no light client container references.
        assert!(is_valid_merkle_branch(
            state.current_justified_checkpoint.root,
            compute_merkle_proof(&state, 103).expect("103 descends into a checkpoint"),
            index_at_leaf_depth(103),
            root,
        ));

        // `BeaconState.previous_justified_checkpoint.epoch`.
        assert!(is_valid_merkle_branch(
            state.previous_justified_checkpoint.epoch.hash_tree_root(),
            compute_merkle_proof(&state, 100).expect("100 descends into a checkpoint"),
            index_at_leaf_depth(100),
            root,
        ));
    }

    #[test]
    fn rejects_a_generalized_index_that_is_not_a_leaf() {
        let state = nontrivial_state();

        assert!(compute_merkle_proof(&state, 1).is_err());
        assert!(compute_merkle_proof(&state, 5).is_err());
    }

    #[test]
    fn rejects_descending_into_a_field_without_a_generator() {
        let state = nontrivial_state();

        // `BeaconState.fork` is field 3 (gindex 35); descending into it is unsupported.
        assert!(compute_merkle_proof(&state, 70).is_err());
    }

    /// The proofs must depend on the state; a proof of the right shape but wrong contents would
    /// pass the tests above if they verified against a root they derived themselves.
    #[test]
    fn proofs_reject_a_mismatched_leaf() {
        let state = nontrivial_state();

        assert!(!is_valid_merkle_branch(
            state.next_sync_committee.hash_tree_root(),
            compute_merkle_proof(&state, CurrentSyncCommitteeIndex::U64)
                .expect("proof is constructible"),
            index_at_leaf_depth(CurrentSyncCommitteeIndex::U64),
            state.hash_tree_root(),
        ));
    }
}

#[cfg(test)]
mod spec_tests {
    use duplicate::duplicate_item;
    use serde::Deserialize;
    use spec_test_utils::Case;
    use ssz::SszHash as _;
    use test_generator::test_resources;
    use typenum::Unsigned as _;
    use types::{
        altair::consts::{CurrentSyncCommitteeIndex, FinalizedRootIndex, NextSyncCommitteeIndex},
        preset::{Mainnet, Minimal},
    };

    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Proof {
        leaf: H256,
        leaf_index: u64,
        branch: Vec<H256>,
    }

    #[duplicate_item(
        glob                                                                                    function_name     preset;
        ["consensus-spec-tests/tests/mainnet/altair/light_client/single_merkle_proof/BeaconState/*"] [mainnet_state] [Mainnet];
        ["consensus-spec-tests/tests/minimal/altair/light_client/single_merkle_proof/BeaconState/*"] [minimal_state] [Minimal];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_state_proof_case::<preset>(case);
    }

    /// Checks the branches we construct against the ones `consensus-specs` publishes.
    ///
    /// `predicates::spec_tests` runs the same cases but only verifies the provided proof, because
    /// there was no code to generate one. These indices now have generators, so we can also make
    /// the assertion the test format asks for:
    ///
    /// > If the implementation supports generating merkle proofs, check that the self-generated
    /// > proof matches the `proof` provided with the test.
    fn run_state_proof_case<P: Preset>(case: Case) {
        let Proof {
            leaf,
            leaf_index,
            branch,
        } = case.yaml("proof");

        let state = case.ssz_default::<AltairBeaconState<P>>("object");

        // Unlike the name suggests, `leaf_index` is a generalized index, which is exactly what
        // `compute_merkle_proof` takes. The match only picks the leaf to check it against.
        let generated = compute_merkle_proof(&state, leaf_index).expect("proof is constructible");

        let (expected_leaf, generated) = match leaf_index {
            index if index == CurrentSyncCommitteeIndex::U64 => {
                (state.current_sync_committee.hash_tree_root(), generated)
            }
            index if index == NextSyncCommitteeIndex::U64 => {
                (state.next_sync_committee.hash_tree_root(), generated)
            }
            index if index == FinalizedRootIndex::U64 => {
                (state.finalized_checkpoint.root, generated)
            }
            index => panic!("unexpected generalized index {index}"),
        };

        assert_eq!(expected_leaf, leaf);
        assert_eq!(generated, branch);
    }
}
