// Some of the tests cause validators to violate slashing conditions.
// The tests should pass despite this, as slashing is outside the purview of the fork choice store.
//
// Some of the tests are taken from Lighthouse but adapted to make sense in our implementation.
// The original ones test implementation details specific to Lighthouse, test cases that could never
// occur according to `consensus-specs`, and don't bother constructing valid blocks or attestations.
//
// Some of the tests had to be adapted for `consensus-specs` version 1.3.0-rc.4 because of the
// addition of unrealized checkpoints and changes to how viability is determined.

#![expect(clippy::similar_names)]
#![expect(clippy::too_many_lines)]

#[cfg(feature = "eth2-cache")]
use std::sync::Arc;

#[cfg(feature = "eth2-cache")]
use eth2_cache_utils::medalla;
#[cfg(feature = "eth2-cache")]
use eth2_libp2p::GossipId;
use helper_functions::misc;
#[cfg(feature = "eth2-cache")]
use std_ext::ArcExt as _;
#[cfg(feature = "eth2-cache")]
use types::{config::Config, preset::Medalla};
use types::{
    nonstandard::PayloadStatus,
    phase0::{
        consts::{GENESIS_EPOCH, GENESIS_SLOT},
        primitives::H256,
    },
    preset::Minimal,
    traits::SignedBeaconBlock as _,
};

use crate::helpers::{epoch_at_slot, is_at_start_of_epoch, start_of_epoch, Context, Status};

#[cfg(feature = "eth2-cache")]
use crate::specialized::TestController;

// This test was added to reproduce the bug described in
// <https://github.com/ethereum/consensus-specs/issues/1887>.
// The bug would only manifest starting with the first slot of the next epoch.
#[test]
#[cfg(feature = "eth2-cache")]
fn processes_old_attestations_from_medalla_in_a_future_slot() {
    let config = Arc::new(Config::medalla());
    let genesis_state = medalla::GENESIS_BEACON_STATE.force().clone_arc();
    let genesis_block = medalla::GENESIS_BEACON_BLOCK.force().clone_arc();
    let last_slot = 224;

    let next_epoch = misc::compute_epoch_at_slot::<Medalla>(last_slot) + 1;
    let first_slot_of_next_epoch = misc::compute_start_slot_at_epoch::<Medalla>(next_epoch);

    let (controller, _mutator_handle) = TestController::quiet(config, genesis_block, genesis_state);

    controller.on_slot(first_slot_of_next_epoch);
    controller.wait_for_tasks();

    for block in medalla::beacon_blocks(1..=last_slot, 4) {
        controller.on_requested_block(block.clone_arc(), None);
        controller.wait_for_tasks();

        let head = controller.head().value;

        assert_eq!(head.slot(), block.message().slot());
        assert_eq!(head.block_root, block.message().hash_tree_root());
    }
}

#[test]
#[cfg(feature = "eth2-cache")]
fn processes_blocks_from_medalla_in_their_slots() {
    let config = Arc::new(Config::medalla());
    let genesis_state = medalla::GENESIS_BEACON_STATE.force().clone_arc();
    let genesis_block = medalla::GENESIS_BEACON_BLOCK.force().clone_arc();
    let last_slot = 224;

    let (controller, _mutator_handle) = TestController::quiet(config, genesis_block, genesis_state);

    for block in medalla::beacon_blocks(1..=last_slot, 4) {
        controller.on_slot(block.message().slot());
        controller.wait_for_tasks();
        controller.on_gossip_block(block.clone_arc(), GossipId::default());
        controller.wait_for_tasks();

        let head = controller.head().value;

        assert_eq!(head.slot(), block.message().slot());
        assert_eq!(head.block_root, block.message().hash_tree_root());
    }
}

// Based on the only fork choice test we had in the repository from 2019.
#[test]
fn handles_happy_path_with_3_blocks_and_height_difference_of_1() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::repeat_byte(1));
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::repeat_byte(2));
    let (block_3, state_3) = context.empty_block(&state_0, 3, H256::repeat_byte(3));

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());
    assert!(block_2.message().hash_tree_root() < block_3.message().hash_tree_root());

    context.on_slot(start_of_epoch(2));

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_2, 1, 0);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_1, 1, 1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_1, 1, 2);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_3, 1, 3);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_3, 1, 4);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });
}

#[test]
fn best_child_is_updated_when_it_falls_behind_the_2nd_best_one() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, start_of_epoch(1), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    // At this point the block tree looks like this:
    //
    //          block_0(0) HEAD
    //
    // I.e., there's a single block in slot 0 with attesting balance 0.
    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_slot(start_of_epoch(2));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    // At this point the block tree looks like this:
    //
    //          block_0(0)
    //            / \
    //           /   \
    //          /     \
    //         /       \
    //      block_1(0)  |
    //                  |
    //               block_2(0) HEAD
    //
    // `block_2` is the head because
    // `block_1.message().hash_tree_root() < block_2.message().hash_tree_root()`.
    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_singular_attestation(&state_1, 1, 0);
    context.on_acceptable_singular_attestation(&state_1, 1, 1);
    context.on_acceptable_singular_attestation(&state_1, 1, 2);

    //          block_0(0)
    //            / \
    //           /   \
    //          /     \
    //         /       \
    // HEAD block_1(3)  |
    //                  |
    //               block_2(0)
    //
    // We use the number of attesting validators as a shorthand for the attesting balance.
    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(3),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_slot(start_of_epoch(3));

    context.on_acceptable_singular_attestation(&state_2, 2, 1);
    context.on_acceptable_singular_attestation(&state_2, 2, 2);

    //          block_0(0)
    //            / \
    //           /   \
    //          /     \
    //         /       \
    //      block_1(1)  |
    //                  |
    //               block_2(2) HEAD
    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });
}

// ```text
//   0
//  / \
// |   4  block at the start of epoch 2,
// |   |  justified between epochs 2 and 3 by blocks 5 and 6,
// |   |  finalized between epochs 3 and 4 by blocks 6 and 7
// |   |
// |   5  block at the end of epoch 2,
// |   |  with attestations justifying block 4 in epoch 2
// |   |
// |   6  block at the end of epoch 3,
// |   |  with attestations justifying block 5 in epoch 3 and finalizing block 4 in epoch 2,
// |   |  causing attestations added by block 5 to be processed
// |   |
// |   7  block at the start of epoch 4,
// |   |  causing attestations added by block 6 to be processed
// |   |
// 1   |  block at the start of epoch 4,
// |   |  justified between epochs 4 and 5 by blocks 2 and 3
// |   |
// 2   |  block at the end of epoch 4,
// |   |  with attestations justifying block 1 in epoch 4
// |   |
// 3   |  block at the start of epoch 5,
//     |  causing attestations added by block 2 to be processed
//     |
//     8  block at the end of epoch 5,
//        with attestations justifying block 7 in epoch 5
// ```
//
// This test predates `consensus-specs` v1.3.0-rc.4.
// Some of the blocks may no longer be necessary due to the addition of unrealized checkpoints.
//
// This scenario can only happen if 1/3 of the validators make slashable attestations.
// The 2nd supermajority link on the 4-7 fork is surrounded by the one on the 1-3 fork.
//
// Processing block 6 causes checkpoints in the fork choice store to become inconsistent.
// A fully compliant implementation should return an orphaned block as the head when that happens.
// Our implementation cannot do so because it prunes orphaned blocks as soon as possible.
// The checkpoints become consistent again when block 8 is processed.
//
// This edge case was introduced to the Fork choice specification in `consensus-specs` v1.3.0-rc.4.
// [Pull request #3290] removed the atomic checkpoint update implemented in [pull request #2727].
// The edge case was touched on in the [comments for pull request #3290].
// djrtwo's comment appears to be incorrect.
// It does not consider blocks arriving in an unusual order like in this test.
//
// We [reported this as a bug], but it turned out to be a known limitation:
// > The issue (https://notes.ethereum.org/1gK1XfrDSpiFSFwSnJ-dAw) is known to us, and the design decision to allow inconsistent Store.justified_checkpoint & Store.finalized_checkpoint updates is intentional.
// >
// > Admittedly, the documentation for this behavior is lacking. It is however, specified in fork-choice.md (https://github.com/ethereum/consensus-specs/blame/c90d724392c619c0fd3dbd471567d2bba9921bef/specs/phase0/fork-choice.md#L345-L359) and acknowledged in these test cases:
// > - test_new_finalized_slot_is_justified_checkpoint_ancestor (https://github.com/ethereum/consensus-specs/blob/c90d724392c619c0fd3dbd471567d2bba9921bef/tests/core/pyspec/eth2spec/test/phase0/fork_choice/test_on_block.py#L443-L444)
// > - test_new_finalized_slot_is_not_justified_checkpoint_ancestor (https://github.com/ethereum/consensus-specs/blob/c90d724392c619c0fd3dbd471567d2bba9921bef/tests/core/pyspec/eth2spec/test/phase0/fork_choice/test_on_block.py#L364-L368) (due to limitations in client testing infrastructure, we cannot execute this spec test in clients)
// >
// > Here’s the rationale for the design decision - we have a choice between two properties:
// > P1. monotonicity (https://docs.google.com/document/d/1DltBHQ_-jEi0N4qu5Pu5LtSaBruTj_Uqq_z47E1LelQ/edit#bookmark=id.9v8oqstpww8e) of Store.justified_checkpoint
// > P2. consistency between Store.justified_checkpoint & Store.finalized_checkpoint
// >
// > Note that:
// > - P1 breaks under asynchrony and without slashing. If we don't fix P1, we can end up with validator voting deadlock ("self-slashability").
// > - P2 can break only when >1/3 slashable.
// >
// > In the fork choice upgrade (https://github.com/ethereum/consensus-specs/pull/3290), we preferred to preserve P1 over P2, because the risk of encountering asynchronous network conditions was deemed larger than >1/3 validators producing slashable messages.
//
// [Pull request #3290]:              https://github.com/ethereum/consensus-specs/pull/3290
// [pull request #2727]:              https://github.com/ethereum/consensus-specs/pull/2727
// [comments for pull request #3290]: https://github.com/ethereum/consensus-specs/pull/3290/files#r1135866084
// [reported this as a bug]:          https://notes.ethereum.org/1gK1XfrDSpiFSFwSnJ-dAw
#[test]
fn survives_and_recovers_from_justified_block_being_pruned() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, start_of_epoch(4), H256::default());
    let (block_2, state_2) = context.block_justifying_current_epoch(&state_1, 4, H256::default());
    let (block_3, _) = context.empty_block(&state_2, start_of_epoch(5), H256::default());
    let (block_4, state_4) = context.empty_block(&state_0, start_of_epoch(2), H256::default());
    let (block_5, state_5) = context.block_justifying_current_epoch(&state_4, 2, H256::default());
    let (block_6, state_6) = context.block_justifying_current_epoch(&state_5, 3, H256::default());
    let (block_7, state_7) = context.empty_block(&state_6, start_of_epoch(4), H256::default());
    let (block_8, _) = context.block_justifying_current_epoch(&state_7, 5, H256::default());

    context.on_slot(start_of_epoch(6));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);
    context.on_acceptable_block(&block_5);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 4,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_6);

    assert_eq!(context.anchor_block(), block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: None,
        store_justified_epoch: 4,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_7);

    assert_eq!(context.anchor_block(), block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: None,
        store_justified_epoch: 4,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_8);

    context.assert_status(Status {
        head: &block_8,
        attesting_validators: Some(0),
        store_justified_epoch: 5,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 4,
    });
}

// 0
//  \
//   1
//   |\
//   2 3
//     |\
//     4 5
//     |\
//     6 \
//     |\ \
//     7 \ \
//        \ \
//         8 \
//         |  |
//         9 10
//            |
//           11
//            |\
//           12 |
//              |
//             13  block that gets finalized
//              |
//             14  block with attestations justifying block 13
//              |
//             15  block with attestations finalizing block 13
//              |
//             16  block that causes attestations added by block 15 to be processed
//
// - 1 2 3 4  5 6  segments
//
// Block 0 is not in any segment because it's the genesis block.
#[test]
fn finalizes_and_prunes_many_segments_correctly() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block(&state_1, 2, H256::repeat_byte(0));
    let (block_3, state_3) = context.empty_block(&state_1, 2, H256::repeat_byte(1));
    let (block_4, state_4) = context.empty_block(&state_3, 3, H256::repeat_byte(0));
    let (block_5, _) = context.empty_block(&state_3, 3, H256::repeat_byte(1));
    let (block_6, state_6) = context.empty_block(&state_4, 4, H256::repeat_byte(0));
    let (block_7, _) = context.empty_block(&state_6, 5, H256::repeat_byte(0));
    let (block_8, state_8) = context.empty_block(&state_6, 5, H256::repeat_byte(1));
    let (block_9, _) = context.empty_block(&state_8, 6, H256::default());
    let (block_10, state_10) = context.empty_block(&state_4, 6, H256::repeat_byte(2));
    let (block_11, state_11) = context.empty_block(&state_10, 7, H256::default());
    let (block_12, _) = context.empty_block(&state_11, 8, H256::repeat_byte(0));
    let (block_13, state_13) =
        context.empty_block(&state_11, start_of_epoch(2), H256::repeat_byte(2));
    let (block_14, state_14) =
        context.block_justifying_current_epoch(&state_13, 2, H256::default());
    let (block_15, state_15) =
        context.block_justifying_current_epoch(&state_14, 3, H256::default());
    let (block_16, _) = context.empty_block(&state_15, start_of_epoch(4), H256::default());

    assert!(block_2.message().hash_tree_root() < block_3.message().hash_tree_root());
    assert!(block_4.message().hash_tree_root() > block_5.message().hash_tree_root());
    assert!(block_6.message().hash_tree_root() < block_10.message().hash_tree_root());
    assert_ne!(
        block_7.message().hash_tree_root(),
        block_8.message().hash_tree_root(),
    );
    assert!(block_12.message().hash_tree_root() < block_13.message().hash_tree_root());

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);
    context.on_acceptable_block(&block_5);
    context.on_acceptable_block(&block_6);
    context.on_acceptable_block(&block_7);
    context.on_acceptable_block(&block_8);
    context.on_acceptable_block(&block_9);
    context.on_acceptable_block(&block_10);
    context.on_acceptable_block(&block_11);
    context.on_acceptable_block(&block_12);
    context.on_acceptable_block(&block_13);

    context.assert_status(Status {
        head: &block_13,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 6,
        fork_count_total: 6,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 6,
        unfinalized_block_count_total: 13,
    });

    context.on_acceptable_block(&block_14);

    context.assert_status(Status {
        head: &block_14,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 6,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 14,
    });

    context.on_acceptable_block(&block_15);

    context.assert_status(Status {
        head: &block_15,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 7,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_16);

    context.assert_status(Status {
        head: &block_16,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 7,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });
}

// This covers a bug we found in `Store::unload_old_states` while implementing in-memory mode.
// The bug would cause blocks to become anchors while having unloaded post-states, making it
// impossible to access their post-states or compute the post-states of their descendants.
//
// ```text
// | epoch 0| epoch 1| epoch 2| epoch 3| epoch 4|
// |□-------|--------|□------▣|-------▣|□-------|
// |0       |        |1      2|       3|4       |
// ```
//
// | symbol | meaning                                            |
// | :----: | -------------------------------------------------- |
// | □      | block without attestations                         |
// | ▣      | block with enough attestations to justify an epoch |
// | -      | slot that may contain a block                      |
//
// Block 1 becomes justified after processing block 3 (or block 2 with unrealized justification).
// Block 1 becomes the anchor after processing block 4 (or block 3 with unrealized justification).
// Before the fix, its post-state could be unloaded after block 2 became the justified block.
//
// Block 2 delivers attestations that justify block 1.
// Block 2 becomes justified after processing block 4 (or block 3 with unrealized justification).
// Before the fix, block 2 becoming justified would leave block 1 unprotected from unloading.
//
// Block 3 triggers epoch processing that justifies block 1.
// Block 3 delivers attestations that justify block 2 and finalize block 1.
//
// Block 4 triggers epoch processing that justifies block 2 and finalizes block 1.
// Block 4 causes the post-state of block 1 to be unloaded from memory.
// Block 4 causes block 0 to be archived, making block 1 the anchor.
//
// Block 4 is not strictly necessary due to unrealized justification.
// However, unrealized justification is a recent addition.
// It was not present in historical designs of the consensus layer that are commonly taught.
// Other specifications do not use it, though Lighthouse seems to use it at the p2p level.
#[test]
fn does_not_unload_states_that_may_become_anchors() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, start_of_epoch(2), H256::default());
    let (block_2, state_2) = context.block_justifying_current_epoch(&state_1, 2, H256::default());
    let (block_3, state_3) = context.block_justifying_current_epoch(&state_2, 3, H256::default());
    let (block_4, _) = context.empty_block(&state_3, start_of_epoch(4), H256::default());

    assert!(
        is_at_start_of_epoch(&block_1),
        "block 1 must be at the start of an epoch to become the anchor",
    );
    assert!(
        GENESIS_EPOCH + 1 < epoch_at_slot(block_2.message().slot()),
        "block 2 must be in epoch 2 or later to have its attestations processed",
    );
    assert!(
        GENESIS_EPOCH + 1 < epoch_at_slot(block_3.message().slot()),
        "block 3 must be in epoch 2 or later to have its attestations processed",
    );
    assert!(
        epoch_at_slot(block_2.message().slot()) < epoch_at_slot(block_3.message().slot()),
        "block 3 must be in an epoch after block 2 to trigger epoch processing",
    );
    assert!(
        epoch_at_slot(block_3.message().slot()) < epoch_at_slot(block_4.message().slot()),
        "block 4 must be in an epoch after block 3 to trigger epoch processing",
    );
    assert!(
        is_at_start_of_epoch(&block_4),
        "block 4 must be at the start of an epoch to trigger unloading",
    );
    assert!(
        block_4.message().slot() - block_1.message().slot()
            >= context.unfinalized_states_in_memory(),
        "block 1 and block 4 must be sufficiently far apart to unload the post-state of block 1",
    );

    context.on_slot(block_4.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);

    assert_eq!(context.anchor_state(), state_1);
    assert_eq!(context.last_finalized_state(), state_1);
    assert_eq!(context.justified_state(), state_2);
}

// 0
//  \
//   \
//   |\
//   1 2
//     |\
//     3 |
//       |
//       4  block that gets finalized
//       |
//       5  block with attestations justifying block 4
//       |
//       6  block with attestations finalizing block 4
//       |
//       7  block that causes attestations added by block 6 to be processed
//
// - 1 2 3  segments
//
// This test was added to reproduce a bug we encountered while testing in Pyrmont.
// It was caused by a block just like block 3 being pruned incorrectly, leading to a panic in
// `Store::propagate_and_dissolve_differences` later, when processing attestations found in a block.
//
// When block 4 is finalized, both segment 1 and segment 2 should be removed.
// Segment 1 should be pruned in its entirety.
// Segment 2 should be partially finalized and partially pruned.
#[test]
fn handles_attestations_for_previously_known_blocks() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::default());
    let (block_3, state_3) = context.empty_block(&state_2, 3, H256::default());
    let (block_4, state_4) = context.empty_block(&state_2, 4, H256::default());
    let (block_5, state_5) = context.block_justifying_current_epoch(&state_4, 2, H256::default());
    let (block_6, state_6) = context.block_justifying_current_epoch(&state_5, 3, H256::default());
    let (block_7, state_7) = context.empty_block(&state_6, start_of_epoch(4), H256::default());

    context.on_slot(start_of_epoch(2));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);

    // The validators used here are picked from committees in the last slot of epoch 3. This is
    // needed to prevent attestations delivered in block 6 from overwriting the `LatestMessage`s
    // corresponding to the validators. Note that attestations in block 5 are not used for fork
    // choice because they're older than the previous epoch by the time block 5 is added.
    context.on_acceptable_singular_attestation(&state_1, 1, 1);
    context.on_acceptable_singular_attestation(&state_2, 1, 2);
    context.on_acceptable_singular_attestation(&state_3, 1, 4);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_block(&block_5);
    context.on_acceptable_block(&block_6);
    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 3,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });

    context.on_slot(start_of_epoch(5));

    context.on_acceptable_singular_attestation(&state_7, 4, 1);
    context.on_acceptable_singular_attestation(&state_7, 4, 2);
    context.on_acceptable_singular_attestation(&state_7, 4, 4);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(3),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 3,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });
}

// We ignore attestations that vote for old blocks to prevent denial of service (malicious or not).
// The number of allowed empty slots is configurable through `max_empty_slots`.
// This is a deviation from the Fork Choice specification.
// Other implementations appear to do something similar.
// See <https://medium.com/offchainlabs/post-mortem-report-ethereum-mainnet-finality-05-11-2023-95e271dfd8b2>.
#[test]
fn ignores_attestations_that_vote_for_old_blocks() {
    let attestation_epoch = 5;
    let head_slot = misc::compute_start_slot_at_epoch::<Minimal>(attestation_epoch + 1);

    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block(&state_0, head_slot, H256::default());

    context.on_slot(start_of_epoch(attestation_epoch + 1));

    context.on_acceptable_block(&block_1);

    context.assert_forward_synced(false);

    context.on_ignorable_singular_attestation(&state_1, attestation_epoch, 0);

    context.on_acceptable_block(&block_2);

    context.assert_forward_synced(true);

    context.on_ignorable_singular_attestation(&state_1, attestation_epoch, 0);
}

// 0
//  \
//   1
//   |\
//   2 |
//     |
//     3  block with attestations justifying block 1
//     |
//     4  block that causes attestations added by block 3 to be processed
//
// - 1 2  segments
//
// This test was added to reproduce a bug we encountered while testing in Pyrmont.
// It was caused by an oversight in `Store::update_head_segment_id`.
//
// This could be done with just 1 block in segment 2 by delivering the attestations in block 1.
#[test]
fn non_viable_parent_segment_is_ignored_even_when_it_has_a_higher_score() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_1, start_of_epoch(1), H256::repeat_byte(0));
    let (block_3, state_3) =
        context.block_justifying_current_epoch(&state_1, 2, H256::repeat_byte(1));
    let (block_4, _) = context.empty_block(&state_3, start_of_epoch(3), H256::default());

    assert!(block_2.message().hash_tree_root() > block_3.message().hash_tree_root());

    context.on_slot(start_of_epoch(3));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);

    context.on_acceptable_singular_attestation(&state_2, 2, 0);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 4,
    });
}

//   0
//  / \
// |   2  block that gets finalized
// |   |
// |   3  block with attestations justifying block 2
// |   |
// 1   |  block that gets orphaned and added again
//     |
//     4  block with attestations finalizing block 2
//     |
//     5  block that causes attestations added by block 4 to be processed
//
// This test was added to reproduce a panic we encountered while testing in Pyrmont.
// `Store::validate_block` would accept orphaned blocks if their parents were finalized blocks.
// Combined with the lack of pruning for `Store.state_roots_to_block_roots` this led to a panic in
// `Store::insert_block` later, when inserting roots into `Store.state_roots_to_block_roots`.
#[test]
fn handles_orphan_block_that_was_previously_known() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, _) = context.empty_block(&state_0, start_of_epoch(2) + 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::default());
    let (block_3, state_3) = context.block_justifying_current_epoch(&state_2, 2, H256::default());
    let (block_4, state_4) = context.block_justifying_current_epoch(&state_3, 3, H256::default());
    let (block_5, _) = context.empty_block(&state_4, start_of_epoch(4), H256::default());

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_5);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });

    context.on_ignorable_block(&block_1);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });
}

// Based on the test `ffg_case_01` from Lighthouse.
// The name is taken from Prysm. It's called `TestFFGUpdates_OneBranch` there.
//
// A chain with just 4 blocks cannot finalize epoch 1. The 2-block finalization rules
// (rule 2 and rule 4) require the previous checkpoint to have been finalized in its own epoch.
// However, `process_justification_and_finalization` is not run in epoch 1.
// We use finalization rule 4 to finalize epoch 2 instead.
// We could also finalize epoch 1 using finalization rule 3, but that would require 5 blocks.
#[test]
fn lighthouse_ffg_updates_one_branch() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.block_justifying_current_epoch(&state_0, 2, H256::default());
    let (block_2, state_2) = context.block_justifying_current_epoch(&state_1, 3, H256::default());
    let (block_3, _) = context.empty_block(&state_2, start_of_epoch(4), H256::default());

    context.on_slot(start_of_epoch(4));

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });
}

//   0
//  / \
// 1   2  blocks at the start of epoch 2,
// |   |  with attestations justifying block 0 in epoch 1
// |   |
// 7   8  blocks at the start of epoch 3,
// |   |  with attestations justifying blocks 1 and 2 in epoch 2
// |   |
// 9  10  blocks at the start of epoch 4,
//        causing attestations added by blocks 7 and 8 to be processed
//
// Based on the `ffg_case_02` test from Lighthouse.
// The name is taken from Prysm. It's called `TestFFGUpdates_TwoBranches` there.
//
// Blocks 3 to 6 in the original test serve no purpose and have been removed.
#[test]
fn lighthouse_ffg_updates_two_branches_starting_with_lower_in_a_future_slot() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(0));
    let (block_2, state_2) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(2));
    let (block_7, state_7) = context.block_justifying_previous_epoch(&state_1, 3, H256::default());
    let (block_8, state_8) = context.block_justifying_previous_epoch(&state_2, 3, H256::default());
    let (block_9, _) = context.empty_block(&state_7, start_of_epoch(4), H256::default());
    let (block_10, _) = context.empty_block(&state_8, start_of_epoch(4), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.on_slot(start_of_epoch(4));

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_8);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_acceptable_block(&block_9);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_10);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 6,
    });
}

//   0
//  / \
// 1   2  blocks at the start of epoch 2,
// |   |  with attestations justifying block 0 in epoch 1
// |   |
// 7   8  blocks at the start of epoch 3,
// |   |  with attestations justifying blocks 1 and 2 in epoch 2
// |   |
// 9  10  blocks at the start of epoch 4,
//        causing attestations added by blocks 7 and 8 to be processed
//
// Based on the `ffg_case_02` test from Lighthouse.
// The name is taken from Prysm. It's called `TestFFGUpdates_TwoBranches` there.
//
// Blocks 3 to 6 in the original test serve no purpose and have been removed.
#[test]
fn lighthouse_ffg_updates_two_branches_starting_with_higher_in_a_future_slot() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(0));
    let (block_2, state_2) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(2));
    let (block_7, state_7) = context.block_justifying_previous_epoch(&state_1, 3, H256::default());
    let (block_8, state_8) = context.block_justifying_previous_epoch(&state_2, 3, H256::default());
    let (block_9, _) = context.empty_block(&state_7, start_of_epoch(4), H256::default());
    let (block_10, _) = context.empty_block(&state_8, start_of_epoch(4), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.on_slot(start_of_epoch(4));

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_8);

    context.assert_status(Status {
        head: &block_8,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_8,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_acceptable_block(&block_10);

    context.assert_status(Status {
        head: &block_10,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_9);

    context.assert_status(Status {
        head: &block_10,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 6,
    });
}

//   0
//  / \
// 1   2  blocks at the start of epoch 2,
// |   |  with attestations justifying block 0 in epoch 1
// |   |
// 7   8  blocks at the start of epoch 3,
// |   |  with attestations justifying blocks 1 and 2 in epoch 2
// |   |
// 9  10  blocks at the start of epoch 4,
//        causing attestations added by blocks 7 and 8 to be processed
//
// Based on the `ffg_case_02` test from Lighthouse.
// The name is taken from Prysm. It's called `TestFFGUpdates_TwoBranches` there.
//
// Blocks 3 to 6 in the original test serve no purpose and have been removed.
#[test]
fn lighthouse_ffg_updates_two_branches_starting_with_lower_in_real_time() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(0));
    let (block_2, state_2) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(2));
    let (block_7, state_7) = context.block_justifying_previous_epoch(&state_1, 3, H256::default());
    let (block_8, state_8) = context.block_justifying_previous_epoch(&state_2, 3, H256::default());
    let (block_9, _) = context.empty_block(&state_7, start_of_epoch(4), H256::default());
    let (block_10, _) = context.empty_block(&state_8, start_of_epoch(4), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_slot(start_of_epoch(2));

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_slot(start_of_epoch(3));

    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_8);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_block(&block_9);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_10);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 6,
    });
}

// Based on the `no_votes` test from Lighthouse.
#[test]
fn lighthouse_no_votes() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::default());
    let (block_3, _) = context.empty_block(&state_1, 3, H256::default());
    let (block_4, state_4) = context.block_justifying_current_epoch(&state_2, 2, H256::default());
    let (block_5, state_5) = context.empty_block(&state_4, start_of_epoch(3), H256::default());
    let (block_6, _) = context.empty_block(&state_5, start_of_epoch(3) + 1, H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.on_slot(start_of_epoch(3) + 1);

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_acceptable_block(&block_5);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_6);

    context.assert_status(Status {
        head: &block_6,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 6,
    });
}

// ```text
// 0
//  \
//   \
//   |\
//   | 1
//   | |
//   2 |
//     |
//     3
//     |
//     4
//     |\
//     5 |
//     | |
//     7 6
//     |
//     8
//     |\
//     | \
//     |  \
//     9  10
//     |
//     11
//     |
//     12
//
// - 1 2 3 4  segments
// ```
//
// Based on the `votes` test from Lighthouse.
//
// The test is quite a bit different from the original one because we cannot arbitrarily alter the
// validators' balances or set the justified and finalized epochs.
//
// We use block 5 to deliver the attestations justifying epoch 2 and block 6 to process them, unlike
// the original, which pretends to process them with block 5. It appears to be impossible to both
// justify epoch 2 with block 5 and finalize the chain up to exactly block 4. We use block 11 along
// with one not present in the original test (block 12) to finalize the chain up to block 4.
#[test]
fn lighthouse_votes() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::default());
    let (block_3, state_3) = context.empty_block(&state_1, 3, H256::default());
    let (block_4, state_4) = context.empty_block(&state_3, 4, H256::default());
    let (block_5, state_5) =
        context.block_justifying_current_epoch(&state_4, 2, H256::repeat_byte(4));
    let (block_6, _) = context.empty_block(&state_4, start_of_epoch(3), H256::default());
    let (block_7, state_7) = context.empty_block(&state_5, start_of_epoch(3), H256::default());
    let (block_8, state_8) = context.empty_block(&state_7, start_of_epoch(3) + 1, H256::default());
    let (block_9, state_9) =
        context.empty_block(&state_8, start_of_epoch(3) + 2, H256::repeat_byte(1));
    let (block_10, state_10) =
        context.empty_block(&state_8, start_of_epoch(3) + 2, H256::repeat_byte(0));
    let (block_11, state_11) = context.block_justifying_current_epoch(&state_9, 3, H256::default());
    let (block_12, _) = context.empty_block(&state_11, start_of_epoch(4), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());
    assert!(block_5.message().hash_tree_root() < block_6.message().hash_tree_root());
    assert!(block_9.message().hash_tree_root() < block_10.message().hash_tree_root());

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_slot(start_of_epoch(1));

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_singular_attestation(&state_1, 0, 0);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_singular_attestation(&state_2, 0, 1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_slot(start_of_epoch(2));

    context.on_acceptable_singular_attestation(&state_3, 1, 0);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_3, 1, 1);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 4,
    });

    context.on_slot(start_of_epoch(3));

    context.on_acceptable_block(&block_5);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_6);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 6,
    });

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_singular_attestation(&state_5, 3, 0);
    context.on_acceptable_singular_attestation(&state_5, 3, 1);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(2),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 6,
    });

    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 5,
        unfinalized_block_count_total: 7,
    });

    context.on_acceptable_block(&block_8);
    context.on_acceptable_block(&block_9);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 9,
    });

    context.on_slot(start_of_epoch(5));

    context.on_acceptable_singular_attestation(&state_9, 4, 0);
    context.on_acceptable_singular_attestation(&state_9, 4, 1);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(2),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 9,
    });

    context.on_acceptable_block(&block_10);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(2),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 4,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 10,
    });

    context.on_acceptable_singular_attestation(&state_10, 4, 2);
    context.on_acceptable_singular_attestation(&state_10, 4, 3);

    context.assert_status(Status {
        head: &block_10,
        attesting_validators: Some(2),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 4,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 10,
    });

    context.on_acceptable_singular_attestation(&state_9, 4, 4);
    context.on_acceptable_singular_attestation(&state_9, 4, 5);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(4),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 4,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 10,
    });

    context.on_acceptable_block(&block_11);

    context.assert_status(Status {
        head: &block_11,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 4,
        unfinalized_block_count_in_fork: 5,
        unfinalized_block_count_total: 7,
    });

    context.on_acceptable_block(&block_12);

    context.assert_status(Status {
        head: &block_12,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 4,
        unfinalized_block_count_in_fork: 6,
        unfinalized_block_count_total: 8,
    });
}

// This was added to reproduce an off-by-one bug in `Segment::iter_up_to`.
#[test]
fn controller_blocks_by_range_can_access_all_blocks_in_a_segment() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, _) = context.empty_block(&state_0, 1, H256::default());

    context.on_slot(block_1.message().slot());

    context.on_acceptable_block(&block_1);

    let expected_blocks = [block_0, block_1];

    let actual_blocks = context
        .blocks_by_range(GENESIS_SLOT..u64::MAX)
        .expect("arguments passed to blocks_by_range are valid")
        .into_iter()
        .map(|block_with_root| block_with_root.block);

    itertools::assert_equal(actual_blocks, expected_blocks);
}

#[test]
fn head_falls_back_to_previous_block_if_last_block_of_single_fork_is_invalidated() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_notified_invalid_payload(&block_2, None);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });
}

#[test]
fn head_falls_back_to_justified_block_if_every_segment_is_invalidated() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, _) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));

    context.on_slot(block_1.message().slot());

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });
}

// The [Optimistic Sync specification] says:
// > When a block transitions from `NOT_VALIDATED` -> `VALID`,
// > all *ancestors* of the block MUST also transition from `NOT_VALIDATED` -> `VALID`.
//
// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#how-to-optimistically-import-blocks
#[test]
fn confirming_a_block_confirms_its_ancestors() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, state_2) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, _) =
        context.block_with_payload(&state_2, 3, H256::default(), H256::repeat_byte(3));

    let status = Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    };

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_status(status);
    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));

    context.on_notified_valid_payload(&block_2);

    context.assert_status(status);
    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));
}

// The [Optimistic Sync specification] says:
// > When a block transitions from `NOT_VALIDATED` -> `INVALIDATED`,
// > all *descendants* of the block MUST also transition from `NOT_VALIDATED` -> `INVALIDATED`.
//
// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#how-to-optimistically-import-blocks
#[test]
fn invalidating_a_block_invalidates_its_descendants() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, state_2) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, _) =
        context.block_with_payload(&state_2, 3, H256::default(), H256::repeat_byte(3));

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));

    context.on_notified_invalid_payload(&block_2, None);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
}

// ```text
// 0
//  \
//   1      latest_valid_hash
//   |\
//   2 \    first invalid block
//   |\ \
//   3 | |  execution_block_hash
//     | |
//     4 |  block in another fork that should also be invalidated
//       |
//       5  block whose payload status should remain unknown
//
// - 1 2 3  segments
// ```
//
// See the following for how to determine the first invalid block:
// - [Optimistic Sync specification]
// - [Engine API specification]
//
// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#how-to-apply-latestvalidhash-when-payload-status-is-invalid
// [Engine API specification]:      https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payload-validation
#[test]
fn all_descendants_of_first_invalid_block_are_invalidated() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, state_2) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, _) =
        context.block_with_payload(&state_2, 3, H256::default(), H256::repeat_byte(3));
    let (block_4, _) =
        context.block_with_payload(&state_2, 4, H256::default(), H256::repeat_byte(4));
    let (block_5, _) =
        context.block_with_payload(&state_1, 5, H256::default(), H256::repeat_byte(5));

    context.on_slot(block_5.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);
    context.on_acceptable_block(&block_5);

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_5, Some(PayloadStatus::Optimistic));

    context.on_notified_invalid_payload(&block_3, Some(&block_1));

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_5, Some(PayloadStatus::Optimistic));
}

// ```text
// 0
//  \
//   1    latest_valid_hash (0x00…00)
//   |\
//   2 |  merge transition block whose payload status is unknown
//     |
//     3  merge transition block whose payload is invalid
//     |
//     4  execution_block_hash
//
// - 1 2  segments
// ```
//
// See the following for how to determine the first invalid block:
// - [Optimistic Sync specification]
// - [Engine API specification]
//
// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#how-to-apply-latestvalidhash-when-payload-status-is-invalid
// [Engine API specification]:      https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payload-validation
#[test]
fn payload_statuses_are_updated_if_latest_valid_hash_is_all_zeros() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, state_3) =
        context.block_with_payload(&state_1, 3, H256::default(), H256::repeat_byte(3));
    let (block_4, _) =
        context.block_with_payload(&state_3, 4, H256::default(), H256::repeat_byte(4));

    context.on_slot(block_4.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Optimistic));

    context.on_notified_invalid_payload(&block_4, Some(&block_1));

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Invalid));
}

#[test]
fn new_descendants_of_an_invalidated_block_are_immediately_invalidated() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, None);

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_2, None);

    context.on_ignorable_block(&block_2);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
}

// This was originally based on [`NoViableHeadDueToOptimisticSync`] in Hive.
// See [Hive pull request #637] for more information.
//
// Not restoring checkpoints is arguably a bug, but doing it correctly may be impossible.
// The [Optimistic Sync specification] treats this as an acceptable limitation. A more appropriate
// solution would be to never set the checkpoints to optimistic values and not expose the optimistic
// head, but that would break compatibility with Hive and the [Eth Beacon Node API specification].
//
// Note that the block that gets invalidated is not the justified block.
// The block justified between epochs 2 and 3 is the genesis block.
// The invalidated block is the one that delivers the attestations to justify it.
// Starting with `consensus-specs` version 1.3.0-rc.4, it also produces a new unrealized checkpoint.
//
// This version of the test should pass both before and after `consensus-specs` version 1.3.0-rc.4.
// Before version 1.3.0-rc.4, block 1 is not needed but block 3 is.
// Starting with version 1.3.0-rc.4, block 3 is no longer needed, but the store must be in epoch 3.
//
// Block 1 is in slot 17 to prevent it from being justified.
// The store is left without viable forks either way,
// but it's harder to tell if block 1 is justified.
//
// [`NoViableHeadDueToOptimisticSync`]: https://github.com/ethereum/hive/blob/53be3f712d23c7f56a4865848b73230341ed4fce/simulators/eth2/engine/scenarios.go#L1777-L2038
// [Hive pull request #637]:            https://github.com/ethereum/hive/pull/637
// [Optimistic Sync specification]:     https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#helpers
// [Eth Beacon Node API specification]: https://github.com/ethereum/beacon-APIs/tree/94105bbb1fd35b54eb531d47f9498b8ccf3d17aa
#[test]
fn invalidating_a_block_does_not_restore_checkpoints_and_can_leave_all_forks_unviable() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, start_of_epoch(2) + 1, H256::default());
    let (block_2, state_2) = context.block_with_payload_justifying_current_epoch(
        &state_1,
        2,
        H256::default(),
        H256::repeat_byte(1),
    );
    let (block_3, _) = context.block_with_payload(
        &state_2,
        start_of_epoch(3),
        H256::default(),
        H256::repeat_byte(2),
    );

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });

    context.on_notified_invalid_payload(&block_2, None);

    // There is some disagreement on what the head should be when all forks are non-viable.
    // A strict interpretation of `consensus-specs` is that it should be the justified block.
    // <https://github.com/ethereum/hive/pull/637#issuecomment-1219219657> claims otherwise.
    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 1,
    });
}

#[test]
fn blocks_after_the_merge_are_optimistic_until_confirmation() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    context.assert_optimistic(&block_0, false);
    context.assert_optimistic(&block_1, true);
    context.assert_optimistic(&block_2, true);

    context.on_notified_valid_payload(&block_1);

    context.assert_optimistic(&block_0, false);
    context.assert_optimistic(&block_1, false);
    context.assert_optimistic(&block_2, true);

    context.on_notified_valid_payload(&block_2);

    context.assert_optimistic(&block_0, false);
    context.assert_optimistic(&block_1, false);
    context.assert_optimistic(&block_2, false);
}

#[test]
fn reorganizing_due_to_invalidation_sends_notifications_if_common_ancestor_is_finalized() {
    let graffiti = H256::repeat_byte(0);

    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, _) = context.block_with_payload(&state_0, 1, graffiti, H256::repeat_byte(1));
    let (block_2, _) = context.block_with_payload(&state_0, 2, graffiti, H256::repeat_byte(2));

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_notified_invalid_payload(&block_2, None);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });
}

#[test]
fn reorganizing_due_to_invalidation_sends_notifications_if_common_ancestor_is_unfinalized() {
    let graffiti = H256::repeat_byte(6);

    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.block_with_payload(&state_1, 2, graffiti, H256::repeat_byte(2));
    let (block_3, _) = context.block_with_payload(&state_1, 3, graffiti, H256::repeat_byte(3));

    assert!(block_2.message().hash_tree_root() < block_3.message().hash_tree_root());

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_notified_invalid_payload(&block_3, None);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_notified_invalid_payload(&block_2, None);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });
}
