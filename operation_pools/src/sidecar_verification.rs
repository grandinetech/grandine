use eip_7594::{
    compute_subnet_for_data_column_sidecar, verify_data_column_sidecar_inclusion_proof,
    verify_data_column_sidecar_kzg_proofs, DataColumnSidecar, NUMBER_OF_COLUMNS,
};
use helper_functions::misc;
use types::traits::BeaconState;
use types::{phase0::primitives::Slot, preset::Preset};

pub enum VerificationResult {
    Reject,
    Ignore,
    Accept,
}

pub fn verify_sidecar<P: Preset>(
    state: &impl BeaconState<P>,
    sidecar: DataColumnSidecar<P>,
    subnet_id: u64,
    current_slot: Slot,
) -> VerificationResult {
    // [REJECT] The sidecar's index is consistent with NUMBER_OF_COLUMNS -- i.e. sidecar.index < NUMBER_OF_COLUMNS.
    if sidecar.index >= NUMBER_OF_COLUMNS {
        return VerificationResult::Reject;
    }

    // [REJECT] The sidecar is for the correct subnet -- i.e. compute_subnet_for_data_column_sidecar(sidecar.index) == subnet_id.
    if compute_subnet_for_data_column_sidecar(sidecar.index) != (subnet_id as usize) {
        return VerificationResult::Reject;
    }
    // [IGNORE] The sidecar is not from a future slot (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. validate that block_header.slot <= current_slot (a client MAY queue future sidecars for processing at the appropriate slot).
    if sidecar.signed_block_header.message.slot > current_slot {
        return VerificationResult::Ignore;
    }
    // [IGNORE] The sidecar is from a slot greater than the latest finalized slot -- i.e. validate that block_header.slot > compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
    if sidecar.signed_block_header.message.slot
        <= misc::compute_start_slot_at_epoch::<P>(state.finalized_checkpoint().epoch)
    {
        return VerificationResult::Ignore;
    }

    // [REJECT] The proposer signature of sidecar.signed_block_header, is valid with respect to the block_header.proposer_index pubkey.
    // neradau, gauti public_key
    // if !sidecar.signed_block_header.signature.verify(sidecar.signed_block_header.message, public_key)
    // {
    //     return VerificationResult::Reject;
    // }

    // [REJECT] The sidecar's kzg_commitments field inclusion proof is valid as verified by verify_data_column_sidecar_inclusion_proof(sidecar).
    if !verify_data_column_sidecar_inclusion_proof(sidecar.clone()) {
        return VerificationResult::Reject;
    }

    // [REJECT] The sidecar's column data is valid as verified by verify_data_column_sidecar_kzg_proofs(sidecar).
    match verify_data_column_sidecar_kzg_proofs(sidecar.clone()) {
        Ok(is_valid) => {
            if !is_valid {
                return VerificationResult::Reject;
            }
        }
        _ => return VerificationResult::Reject,
    }

    // [IGNORE] The sidecar's block's parent (defined by block_header.parent_root) has been seen (via both gossip and non-gossip sources) (a client MAY queue sidecars for processing once the parent block is retrieved).
    // [REJECT] The sidecar's block's parent (defined by block_header.parent_root) passes validation.
    // [REJECT] The sidecar is from a higher slot than the sidecar's block's parent (defined by block_header.parent_root).
    // [REJECT] The current finalized_checkpoint is an ancestor of the sidecar's block -- i.e. get_checkpoint_block(store, block_header.parent_root, store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root.
    // [IGNORE] The sidecar is the first sidecar for the tuple (block_header.slot, block_header.proposer_index, sidecar.index) with valid header signature, sidecar inclusion proof, and kzg proof.
    // [REJECT] The sidecar is proposed by the expected proposer_index for the block's slot in the context of the current shuffling (defined by block_header.parent_root/block_header.slot). If the proposer_index cannot immediately be verified against the expected shuffling, the sidecar MAY be queued for later processing while proposers for the block's branch are calculated -- in such a case do not REJECT, instead IGNORE this message.
    todo!()
}
