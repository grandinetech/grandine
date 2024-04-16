use std::sync::Arc;

use eth1_api::ApiController;
use fork_choice_control::Wait;
use genesis::AnchorCheckpointProvider;
use http_api_utils::BlockId;
use types::{
    combined::SignedBeaconBlock, nonstandard::WithStatus, phase0::primitives::H256, preset::Preset,
    traits::SignedBeaconBlock as _,
};

use crate::error::Error;

pub fn block<P: Preset, W: Wait>(
    block_id: BlockId,
    controller: &ApiController<P, W>,
    anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
) -> Result<WithStatus<Arc<SignedBeaconBlock<P>>>, Error> {
    match block_id {
        BlockId::Head => Some(controller.head_block()),
        BlockId::Genesis => anchor_checkpoint_provider
            .checkpoint()
            .genesis()
            .map(|checkpoint| checkpoint.block)
            .map(WithStatus::valid_and_finalized),
        BlockId::Finalized => Some(controller.last_finalized_block()),
        BlockId::Slot(slot) => controller
            .block_by_slot(slot)?
            .map(|with_status| with_status.map(|block_with_root| block_with_root.block)),
        BlockId::Root(root) => controller.block_by_root(root)?,
    }
    .ok_or(Error::BlockNotFound)
}

pub fn block_root<P: Preset, W: Wait>(
    block_id: BlockId,
    controller: &ApiController<P, W>,
    anchor_checkpoint_provider: &AnchorCheckpointProvider<P>,
) -> Result<WithStatus<H256>, Error> {
    match block_id {
        BlockId::Head => Some(controller.head_block_root()),
        BlockId::Genesis => anchor_checkpoint_provider
            .checkpoint()
            .genesis()
            .map(|checkpoint| checkpoint.block.message().hash_tree_root())
            .map(WithStatus::valid_and_finalized),
        BlockId::Finalized => Some(controller.last_finalized_block_root()),
        BlockId::Slot(slot) => controller
            .block_by_slot(slot)?
            .map(|with_status| with_status.map(|with_status| with_status.root)),
        BlockId::Root(root) => controller.check_block_root(root)?,
    }
    .ok_or(Error::BlockNotFound)
}
