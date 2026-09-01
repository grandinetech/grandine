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
        beacon_state::BeaconState as AltairBeaconState,
        consts::{CurrentSyncCommitteeIndex, FinalizedRootIndex, NextSyncCommitteeIndex},
        containers::{
            LightClientBootstrap, LightClientFinalityUpdate, LightClientHeader,
            LightClientOptimisticUpdate, LightClientUpdate, SyncCommittee,
        },
    },
    phase0::{
        consts::GENESIS_SLOT,
        containers::Checkpoint,
        primitives::{H256, Slot},
    },
    preset::Preset,
    traits::{BeaconBlock as _, SignedBeaconBlock},
};

pub fn block_to_light_client_header<P: Preset>(
    block: &impl SignedBeaconBlock<P>,
) -> LightClientHeader {
    LightClientHeader {
        beacon: block.message().to_header(),
    }
}

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
        attested_state.slot == attested_state.latest_block_header.slot,
        Error::StateSlotDoesNotMatchLatestBlockHeader {
            state_slot: attested_state.slot,
            header_slot: attested_state.latest_block_header.slot,
        },
    );

    let mut attested_header = attested_state.latest_block_header;
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
        attested_header: LightClientHeader {
            beacon: attested_header,
        },
        next_sync_committee,
        next_sync_committee_branch,
        finalized_header,
        finality_branch,
        sync_aggregate,
        signature_slot: block.message().slot(),
    })
}

pub fn create_light_client_finality_update<P: Preset>(
    update: LightClientUpdate<P>,
) -> LightClientFinalityUpdate<P> {
    LightClientFinalityUpdate {
        attested_header: update.attested_header,
        finalized_header: update.finalized_header,
        finality_branch: update.finality_branch,
        sync_aggregate: update.sync_aggregate,
        signature_slot: update.signature_slot,
    }
}

pub fn create_light_client_optimistic_update<P: Preset>(
    update: LightClientUpdate<P>,
) -> LightClientOptimisticUpdate<P> {
    LightClientOptimisticUpdate {
        attested_header: update.attested_header,
        sync_aggregate: update.sync_aggregate,
        signature_slot: update.signature_slot,
    }
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
mod extra_tests {
    use arithmetic::U64Ext as _;
    use types::{
        altair::containers::SignedBeaconBlock as AltairSignedBeaconBlock,
        combined::SignedBeaconBlock as CombinedSignedBeaconBlock,
        phase0::{
            containers::{BeaconBlockHeader, Eth1Data, Fork, Validator},
            primitives::Slot,
        },
        preset::Minimal,
    };

    use crate::predicates::is_valid_merkle_branch;

    use super::*;

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
            ..AltairBeaconState::default()
        }
    }

    fn block_with_post_state(
        mut state: AltairBeaconState<Minimal>,
        slot: Slot,
        parent_root: H256,
    ) -> (
        CombinedSignedBeaconBlock<Minimal>,
        AltairBeaconState<Minimal>,
    ) {
        let mut block = AltairSignedBeaconBlock::<Minimal>::default();

        block.message.slot = slot;
        block.message.parent_root = parent_root;
        block
            .message
            .body
            .sync_aggregate
            .sync_committee_bits
            .set(0, true);

        state.slot = slot;
        state.latest_block_header = block.message.to_header();
        block.message.state_root = state.hash_tree_root();

        (CombinedSignedBeaconBlock::Altair(block), state)
    }

    fn index_at_leaf_depth(gindex: u64) -> u64 {
        gindex - gindex.prev_power_of_two()
    }

    #[test]
    fn generalized_indices_outside_the_light_client_protocol_verify() {
        let state = nontrivial_state();
        let root = state.hash_tree_root();

        for (gindex, leaf) in [
            (43, state.validators.hash_tree_root()),
            (103, state.current_justified_checkpoint.root),
            (
                100,
                state.previous_justified_checkpoint.epoch.hash_tree_root(),
            ),
        ] {
            assert!(is_valid_merkle_branch(
                leaf,
                compute_merkle_proof(&state, gindex).expect("proof is constructible"),
                index_at_leaf_depth(gindex),
                root,
            ));
        }
    }

    #[test]
    fn rejects_generalized_indices_without_a_proof() {
        let state = nontrivial_state();

        for gindex in [1, 5, 70] {
            assert!(compute_merkle_proof(&state, gindex).is_err());
        }
    }

    #[test]
    fn bootstrap_branch_verifies_against_the_header_state_root() {
        let (block, state) = block_with_post_state(nontrivial_state(), 8, H256::zero());

        let bootstrap =
            create_light_client_bootstrap(&state, &block).expect("state is the block post state");

        assert_eq!(bootstrap.header.beacon, block.message().to_header());

        assert!(is_valid_merkle_branch(
            bootstrap.current_sync_committee.hash_tree_root(),
            bootstrap.current_sync_committee_branch,
            index_at_leaf_depth(CurrentSyncCommitteeIndex::U64),
            bootstrap.header.beacon.state_root,
        ));
    }

    #[test]
    fn update_branches_verify_against_the_attested_header_state_root() {
        let (finalized_block, _) = block_with_post_state(nontrivial_state(), 8, H256::zero());

        let mut attested = nontrivial_state();
        attested.finalized_checkpoint.root = finalized_block.message().hash_tree_root();

        let (attested_block, attested_state) = block_with_post_state(attested, 16, H256::zero());
        let (block, state) = block_with_post_state(
            nontrivial_state(),
            17,
            attested_block.message().hash_tree_root(),
        );

        let update = create_light_client_update(
            &state,
            &block,
            &attested_state,
            &attested_block,
            Some(&finalized_block),
        )
        .expect("states are the post states of their blocks");

        assert_eq!(
            update.attested_header.beacon,
            attested_block.message().to_header()
        );
        assert_eq!(
            update.finalized_header.beacon,
            finalized_block.message().to_header()
        );
        assert_eq!(update.signature_slot, block.message().slot());

        let finality_update = create_light_client_finality_update(update.clone());
        let optimistic_update = create_light_client_optimistic_update(update.clone());

        assert_eq!(finality_update.finalized_header, update.finalized_header);
        assert_eq!(finality_update.finality_branch, update.finality_branch);
        assert_eq!(optimistic_update.attested_header, update.attested_header);
        assert_eq!(optimistic_update.signature_slot, update.signature_slot);

        let attested_state_root = update.attested_header.beacon.state_root;

        assert!(is_valid_merkle_branch(
            update.next_sync_committee.hash_tree_root(),
            update.next_sync_committee_branch,
            index_at_leaf_depth(NextSyncCommitteeIndex::U64),
            attested_state_root,
        ));

        assert!(is_valid_merkle_branch(
            attested_state.finalized_checkpoint.root,
            update.finality_branch,
            index_at_leaf_depth(FinalizedRootIndex::U64),
            attested_state_root,
        ));
    }

    #[test]
    fn rejects_a_state_that_is_not_the_block_post_state() {
        let (block, _) = block_with_post_state(nontrivial_state(), 8, H256::zero());
        let (_, other_state) = block_with_post_state(nontrivial_state(), 9, H256::zero());

        assert!(create_light_client_bootstrap(&other_state, &block).is_err());
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

    fn run_state_proof_case<P: Preset>(case: Case) {
        let Proof {
            leaf,
            leaf_index,
            branch,
        } = case.yaml("proof");

        let state = case.ssz_default::<AltairBeaconState<P>>("object");

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
