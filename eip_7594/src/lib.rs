use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};

use anyhow::{ensure, Result};
use helper_functions::{misc, predicates::is_valid_merkle_branch};
use itertools::Itertools as _;
use kzg_utils::{
    eip_7594::{compute_cells, recover_cells_and_kzg_proofs, verify_cell_kzg_proof_batch},
    KzgBackend,
};
use num_traits::One as _;
use prometheus_metrics::Metrics;
use rayon::iter::{
    IndexedParallelIterator as _, IntoParallelIterator as _, IntoParallelRefIterator as _,
    ParallelIterator as _,
};
use sha2::{Digest as _, Sha256};
use ssz::{ContiguousList, ContiguousVector, SszHash as _, Uint256};
use tracing::instrument;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    combined::SignedBeaconBlock,
    config::Config,
    deneb::primitives::{Blob, KzgCommitment, KzgProof},
    fulu::{
        containers::{DataColumnSidecar, MatrixEntry},
        primitives::{BlobCommitmentsInclusionProof, CellsAndKzgProofs, ColumnIndex, CustodyIndex},
    },
    phase0::{
        containers::SignedBeaconBlockHeader,
        primitives::{Gwei, NodeId, SubnetId, ValidatorIndex},
    },
    preset::Preset,
    traits::{BeaconState, SignedBeaconBlock as _},
};

use error::Error;
mod error;

#[cfg(test)]
mod tests;

pub fn get_custody_groups(
    config: &Config,
    raw_node_id: [u8; 32],
    custody_group_count: u64,
) -> Result<HashSet<CustodyIndex>> {
    let number_of_custody_groups = config.number_of_custody_groups;
    ensure!(
        custody_group_count <= number_of_custody_groups,
        Error::InvalidCustodyGroupCount {
            custody_group_count,
            number_of_custody_groups,
        },
    );

    // Skip computation for super node
    if custody_group_count == number_of_custody_groups {
        return Ok((0..number_of_custody_groups).collect::<HashSet<_>>());
    }

    let mut current_id = NodeId::from_be_bytes(raw_node_id);

    let mut custody_groups = BTreeSet::new();
    while (custody_groups.len() as u64) < custody_group_count {
        let mut hasher = Sha256::new();
        let mut bytes = [0u8; 32];

        current_id.into_raw().to_little_endian(&mut bytes);

        hasher.update(bytes);
        bytes = hasher.finalize().into();

        let output_prefix = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];

        let output_prefix_u64 = u64::from_le_bytes(output_prefix);
        let custody_group = output_prefix_u64
            .checked_rem(number_of_custody_groups)
            .expect("number of custody groups must not be zero");
        custody_groups.insert(custody_group);

        if current_id == Uint256::MAX {
            // > Overflow prevention
            current_id = Uint256::ZERO;
        } else {
            current_id = current_id + Uint256::one();
        }
    }

    Ok(custody_groups.into_iter().collect())
}

pub fn compute_columns_for_custody_group<P: Preset>(
    config: &Config,
    custody_group: CustodyIndex,
) -> Result<impl Iterator<Item = ColumnIndex>> {
    let number_of_custody_groups = config.number_of_custody_groups;
    ensure!(
        custody_group < number_of_custody_groups,
        Error::InvalidCustodyGroup {
            custody_group,
            number_of_custody_groups,
        },
    );

    let mut columns = Vec::new();
    for i in 0..config.columns_per_group::<P>() {
        columns.push(ColumnIndex::from(
            number_of_custody_groups * i + custody_group,
        ));
    }

    Ok(columns.into_iter())
}

pub fn compute_subnets_from_custody_group<P: Preset>(
    config: &Config,
    custody_group: CustodyIndex,
) -> Result<impl Iterator<Item = SubnetId> + '_> {
    let subnets = compute_columns_for_custody_group::<P>(config, custody_group)?
        .map(|column_index| misc::compute_subnet_for_data_column_sidecar(config, column_index))
        .unique();

    Ok(subnets)
}

pub fn compute_subnets_for_node<P: Preset>(
    config: &Config,
    raw_node_id: [u8; 32],
    custody_group_count: u64,
) -> Result<HashSet<SubnetId>> {
    let mut subnets = HashSet::new();
    for custody_group in get_custody_groups(config, raw_node_id, custody_group_count)? {
        let custody_group_subnets = compute_subnets_from_custody_group::<P>(config, custody_group)?;

        subnets.extend(custody_group_subnets);
    }

    Ok(subnets)
}

/// Verify if the data column sidecar is valid.
#[instrument(level = "debug", skip_all)]
pub fn verify_data_column_sidecar<P: Preset>(
    config: &Config,
    data_column_sidecar: &DataColumnSidecar<P>,
) -> bool {
    let DataColumnSidecar {
        index,
        column,
        kzg_commitments,
        kzg_proofs,
        signed_block_header,
        ..
    } = data_column_sidecar;

    // The sidecar index must be within the valid range
    if *index >= P::NumberOfColumns::U64 {
        return false;
    }

    // A sidecar for zero blobs is invalid
    if kzg_commitments.is_empty() {
        return false;
    }

    // Check that the sidecar respects the blob limit
    let epoch = misc::compute_epoch_at_slot::<P>(signed_block_header.message.slot);
    if kzg_commitments.len() > config.get_blob_schedule_entry(epoch).max_blobs_per_block {
        return false;
    }

    // The column length must be equal to the number of commitments/proofs
    if column.len() != kzg_commitments.len() || column.len() != kzg_proofs.len() {
        return false;
    }

    true
}

/// Verify if the KZG proofs are correct.
#[instrument(level = "debug", skip_all)]
pub fn verify_kzg_proofs<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
    backend: KzgBackend,
    metrics: Option<&Arc<Metrics>>,
) -> Result<bool> {
    let _timer = metrics.as_ref().map(|metrics| {
        metrics
            .data_column_sidecar_kzg_verification_batch
            .start_timer()
    });

    let DataColumnSidecar {
        index,
        column,
        kzg_commitments,
        kzg_proofs,
        ..
    } = data_column_sidecar;

    let cell_indices: Vec<u64> = vec![*index; column.len()];

    verify_cell_kzg_proof_batch::<P>(kzg_commitments, cell_indices, column, kzg_proofs, backend)
}

pub fn verify_sidecar_inclusion_proof<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
    metrics: Option<&Arc<Metrics>>,
) -> bool {
    let _timer = metrics.as_ref().map(|metrics| {
        metrics
            .data_column_sidecar_inclusion_proof_verification
            .start_timer()
    });

    let DataColumnSidecar {
        kzg_commitments,
        signed_block_header,
        kzg_commitments_inclusion_proof,
        ..
    } = data_column_sidecar;

    // Fields in BeaconBlockBody before blob KZG commitments
    let index_at_commitment_depth = 11;

    // is_valid_blob_sidecar_inclusion_proof
    is_valid_merkle_branch(
        kzg_commitments.hash_tree_root(),
        *kzg_commitments_inclusion_proof,
        index_at_commitment_depth,
        signed_block_header.message.body_root,
    )
}

pub fn recover_matrix<P: Preset>(
    partial_matrix: &[MatrixEntry<P>],
    backend: KzgBackend,
) -> Result<Vec<MatrixEntry<P>>> {
    let mut partial_matrix_map = BTreeMap::new();
    for matrix in partial_matrix {
        partial_matrix_map
            .entry(matrix.row_index)
            .or_insert(Vec::new())
            .push(matrix);
    }

    partial_matrix_map
        .into_par_iter()
        .map(|(_, entries)| {
            let (cell_indices, cells): (Vec<_>, Vec<_>) =
                entries.iter().map(|e| (e.column_index, &e.cell)).unzip();

            recover_cells_and_kzg_proofs::<P>(cell_indices, cells, backend)
        })
        .collect::<Result<Vec<_>>>()
        .map(construct_full_matrix)
}

fn get_data_column_sidecars<P: Preset>(
    signed_block_header: SignedBeaconBlockHeader,
    kzg_commitments: &ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>,
    kzg_commitments_inclusion_proof: BlobCommitmentsInclusionProof<P>,
    cells_and_kzg_proofs: &[CellsAndKzgProofs<P>],
) -> Result<Vec<Arc<DataColumnSidecar<P>>>> {
    let blob_count = kzg_commitments.len();
    ensure!(
        cells_and_kzg_proofs.len() == blob_count,
        Error::BlobCommitmentsLengthMismatch {
            blob_count,
            commitments_length: kzg_commitments.len(),
        }
    );

    let mut sidecars = vec![];
    for column_index in 0..P::NumberOfColumns::USIZE {
        let column = ContiguousList::try_from_iter(
            (0..blob_count)
                .map(|row_index| cells_and_kzg_proofs[row_index].0[column_index].clone()),
        )?;
        let kzg_proofs = ContiguousList::try_from_iter(
            (0..blob_count).map(|row_index| cells_and_kzg_proofs[row_index].1[column_index]),
        )?;

        sidecars.push(
            DataColumnSidecar {
                index: ColumnIndex::try_from(column_index)?,
                column,
                kzg_commitments: kzg_commitments.clone(),
                kzg_proofs,
                signed_block_header,
                kzg_commitments_inclusion_proof,
            }
            .into(),
        );
    }

    Ok(sidecars)
}

pub fn construct_data_column_sidecars<P: Preset>(
    signed_block: &SignedBeaconBlock<P>,
    cells_and_kzg_proofs: &[CellsAndKzgProofs<P>],
) -> Result<Vec<Arc<DataColumnSidecar<P>>>> {
    let signed_block_header = signed_block.to_header();
    let body = match signed_block {
        SignedBeaconBlock::Fulu(block) => &block.message.body,
        SignedBeaconBlock::Gloas(_) => todo!(),
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Bellatrix(_)
        | SignedBeaconBlock::Capella(_)
        | SignedBeaconBlock::Deneb(_)
        | SignedBeaconBlock::Electra(_) => {
            return Err(Error::BlobsForPreFuluBlock {
                root: signed_block.message().hash_tree_root(),
                slot: signed_block.message().slot(),
            }
            .into());
        }
    };

    let kzg_commitments = &body.blob_kzg_commitments;
    if kzg_commitments.is_empty() {
        return Ok(vec![]);
    }

    let kzg_commitments_inclusion_proof = misc::kzg_commitments_inclusion_proof(body);

    get_data_column_sidecars(
        signed_block_header,
        kzg_commitments,
        kzg_commitments_inclusion_proof,
        cells_and_kzg_proofs,
    )
}

pub fn construct_data_column_sidecars_from_sidecar<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
    cells_and_kzg_proofs: &[CellsAndKzgProofs<P>],
) -> Result<Vec<Arc<DataColumnSidecar<P>>>> {
    let DataColumnSidecar {
        kzg_commitments,
        signed_block_header,
        kzg_commitments_inclusion_proof,
        ..
    } = data_column_sidecar;

    get_data_column_sidecars(
        *signed_block_header,
        kzg_commitments,
        *kzg_commitments_inclusion_proof,
        cells_and_kzg_proofs,
    )
}

pub fn try_convert_to_cells_and_kzg_proofs<P: Preset>(
    blobs: &[Blob<P>],
    cell_proofs: &[KzgProof],
    backend: KzgBackend,
) -> Result<Vec<CellsAndKzgProofs<P>>> {
    let expected_proofs_length = blobs.len() * P::CellsPerExtBlob::USIZE;
    ensure!(
        cell_proofs.len() == expected_proofs_length,
        Error::InvalidCellsProofsLength {
            expected: expected_proofs_length,
            proofs_length: cell_proofs.len(),
        }
    );

    blobs
        .par_iter()
        .enumerate()
        .map(|(i, blob)| {
            compute_cells::<P>(blob, backend).and_then(|cells| {
                let start = P::CellsPerExtBlob::USIZE.saturating_mul(i);
                let end = P::CellsPerExtBlob::USIZE.saturating_add(start);
                ContiguousVector::try_from_iter(cell_proofs[start..end].iter().copied())
                    .map(|proofs| (cells, proofs))
                    .map_err(Into::into)
            })
        })
        .collect::<Result<Vec<_>>>()
}

pub fn construct_cells_and_kzg_proofs<P: Preset>(
    full_matrix: Vec<MatrixEntry<P>>,
) -> Result<Vec<CellsAndKzgProofs<P>>> {
    // Group and sort the matrix entries by blob index
    let mut full_matrix_map = BTreeMap::new();
    for matrix in full_matrix {
        full_matrix_map
            .entry(matrix.row_index)
            .or_insert(Vec::new())
            .push(matrix);
    }

    let mut result = Vec::new();
    for entries in full_matrix_map.into_values() {
        let (cells, proofs): (Vec<_>, Vec<_>) =
            entries.into_iter().map(|e| (e.cell, e.kzg_proof)).unzip();

        let cells = ContiguousVector::try_from_iter(cells.into_iter())?;
        let proofs = ContiguousVector::try_from_iter(proofs.into_iter())?;
        result.push((cells, proofs));
    }

    Ok(result)
}

pub fn get_validator_custody_requirement<P: Preset>(
    config: &Config,
    last_finalized_state: &impl BeaconState<P>,
    validator_indices: &HashSet<ValidatorIndex>,
) -> u64 {
    let total_node_balance = validator_indices
        .iter()
        .map(|index| {
            last_finalized_state
                .validators()
                .get(*index)
                .map(|validator| validator.effective_balance)
        })
        .process_results(|iter| iter.sum::<Gwei>())
        .unwrap_or(0);

    let count = total_node_balance.saturating_div(config.balance_per_additional_custody_group);

    count
        .max(config.validator_custody_requirement)
        .min(config.number_of_custody_groups)
}

fn construct_full_matrix<P: Preset>(
    cells_and_kzg_proofs: Vec<CellsAndKzgProofs<P>>,
) -> Vec<MatrixEntry<P>> {
    cells_and_kzg_proofs
        .into_iter()
        .enumerate()
        .flat_map(|(blob_index, (cells, proofs))| {
            cells
                .into_iter()
                .zip(proofs)
                .enumerate()
                .map(move |(cell_index, (cell, kzg_proof))| MatrixEntry {
                    cell,
                    kzg_proof,
                    row_index: blob_index as u64,
                    column_index: cell_index as u64,
                })
        })
        .collect()
}
