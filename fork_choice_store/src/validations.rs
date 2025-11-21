use std::sync::Arc;

use anyhow::{ensure, Result};
use execution_engine::ExecutionEngine;
use helper_functions::misc;
use std_ext::ArcExt as _;
use types::{
    bellatrix::containers::PowBlock,
    combined::SignedBeaconBlock,
    config::Config as ChainConfig,
    preset::Preset,
    traits::{BlockBodyWithExecutionPayload, SignedBeaconBlock as _},
};

use crate::{error::Error, misc::PartialBlockAction};

/// [`validate_merge_block`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/fork-choice.md#validate_merge_block)
///
/// > Check the parent PoW block of execution payload is a valid terminal PoW block.
/// >
/// > Note: Unavailable PoW block(s) may later become available,
/// > and a client software MAY delay a call to ``validate_merge_block``
/// > until the PoW block(s) become available.
pub fn validate_merge_block<P: Preset, E: ExecutionEngine<P>>(
    chain_config: &ChainConfig,
    block: &Arc<SignedBeaconBlock<P>>,
    body: &(impl BlockBodyWithExecutionPayload<P> + ?Sized),
    execution_engine: E,
) -> Result<PartialBlockAction> {
    if !chain_config.terminal_block_hash.is_zero() {
        let epoch = misc::compute_epoch_at_slot::<P>(block.message().slot());

        // > If `TERMINAL_BLOCK_HASH` is used as an override,
        // > the activation epoch must be reached.
        ensure!(
            epoch >= chain_config.terminal_block_hash_activation_epoch,
            Error::MergeBlockBeforeActivationEpoch {
                block: block.clone_arc(),
            },
        );

        ensure!(
            body.execution_payload().parent_hash() == chain_config.terminal_block_hash,
            Error::TerminalBlockHashMismatch {
                block: block.clone_arc(),
            },
        );

        return Ok(PartialBlockAction::Accept);
    }

    if E::IS_NULL {
        return Ok(PartialBlockAction::Accept);
    }

    let pow_block_missing_block_action =
        if execution_engine.allow_optimistic_merge_block_validation() {
            // In case PoW block is not found (e.g. execution engine is not synced),
            // let fork choice optimistically accept beacon block
            PartialBlockAction::Accept
        } else {
            PartialBlockAction::Ignore
        };

    // > Check if `pow_block` is available
    let Some(pow_block) = execution_engine.pow_block(body.execution_payload().parent_hash()) else {
        return Ok(pow_block_missing_block_action);
    };

    // > Check if `pow_parent` is available
    let Some(pow_parent) = execution_engine.pow_block(pow_block.pow_block.parent_hash) else {
        return Ok(pow_block_missing_block_action);
    };

    // > Check if `pow_block` is a valid terminal PoW block
    validate_terminal_pow_block(
        chain_config,
        block,
        pow_block.pow_block,
        pow_parent.pow_block,
    )?;

    Ok(PartialBlockAction::Accept)
}

/// [`is_valid_terminal_pow_block`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/fork-choice.md#is_valid_terminal_pow_block)
fn validate_terminal_pow_block<P: Preset>(
    chain_config: &ChainConfig,
    block: &Arc<SignedBeaconBlock<P>>,
    pow_block: PowBlock,
    parent: PowBlock,
) -> Result<()> {
    ensure!(
        pow_block.total_difficulty >= chain_config.terminal_total_difficulty,
        Error::TerminalTotalDifficultyNotReached {
            block: block.clone_arc(),
            pow_block: Box::new(pow_block),
        },
    );

    ensure!(
        parent.total_difficulty < chain_config.terminal_total_difficulty,
        Error::TerminalTotalDifficultyReachedByParent {
            block: block.clone_arc(),
            pow_block: Box::new(pow_block),
            parent: Box::new(parent),
        },
    );

    Ok(())
}
