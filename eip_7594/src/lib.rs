use anyhow::{ensure, Result};
use c_kzg::{
    Blob as CKzgBlob, Bytes48, Cell as CKzgCell, KzgProof as CKzgProof, CELLS_PER_EXT_BLOB,
};
use hashing::ZERO_HASHES;
use helper_functions::predicates::is_valid_merkle_branch;
use itertools::Itertools;
use kzg as _;
use num_traits::One as _;
use prometheus_metrics::Metrics;
use sha2::{Digest as _, Sha256};
use ssz::{ByteVector, ContiguousList, ContiguousVector, SszHash, Uint256};
use std::sync::Arc;
use thiserror::Error;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned;
use types::{
    combined::SignedBeaconBlock,
    config::Config,
    deneb::primitives::{Blob, KzgProof},
    eip7594::{
        BlobCommitmentsInclusionProof, Cell, ColumnIndex, DataColumnSidecar, DataColumnSubnetId,
        MatrixEntry, NumberOfColumns,
    },
    phase0::primitives::NodeId,
    preset::Preset,
    traits::{PostDenebBeaconBlockBody, PostElectraBeaconBlockBody, SignedBeaconBlock as _},
};

use crate::trusted_setup::settings;

mod trusted_setup;

#[derive(Debug, Error)]
pub enum VerifyKzgProofsError {
    #[error(
        "Sidecar index is out of bounds: {index} expected {}",
        NumberOfColumns::U64
    )]
    SidecarIndexOutOfBounds { index: u64 },
    #[error(
        "Sidecar column length {column_length} does not match commitment length {commitments_length}"
    )]
    SidecarCommitmentsLengthError {
        column_length: usize,
        commitments_length: usize,
    },
    #[error("Sidecar column length {column_length} does not match proofs length {proofs_length}")]
    SidecarProofsLengthError {
        column_length: usize,
        proofs_length: usize,
    },
    #[error("Sidecar with no commitments considered to be invalid.")]
    SidecarWithoutCommitments,
}

#[derive(Debug, Error)]
pub enum ExtendedSampleError {
    #[error(
        "Allowed failtures is out of range: {allowed_failures} in 0 -> {}",
        NumberOfColumns::U64 / 2
    )]
    AllowedFailtureOutOfRange { allowed_failures: u64 },
}

#[derive(Debug, Error)]
pub enum GetDataColumnSidecarsError {
    #[error(
        "Cells and proofs length {cells_length} does not match commitment length {commitments_length}"
    )]
    CellsCommitmentsLengthError {
        cells_length: usize,
        commitments_length: usize,
    },
}

/// Verify if the data column sidecar is valid.
pub fn verify_data_column_sidecar<P: Preset>(data_column_sidecar: &DataColumnSidecar<P>) -> bool {
    let DataColumnSidecar {
        index,
        column,
        kzg_commitments,
        kzg_proofs,
        ..
    } = data_column_sidecar;

    // The sidecar index must be within the valid range
    if *index >= NumberOfColumns::U64 {
        return false;
    }

    // A sidecar for zero blobs is invalid
    if kzg_commitments.len() == 0 {
        return false;
    }

    // The column length must be equal to the number of commitments/proofs
    if column.len() != kzg_commitments.len() || column.len() != kzg_proofs.len() {
        return false;
    }

    true
}

/// Verify if the KZG proofs are correct.
pub fn verify_kzg_proofs<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
    metrics: &Option<Arc<Metrics>>,
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

    let cells = column
        .clone()
        .into_iter()
        .map(|a| CKzgCell::from_bytes(a.as_bytes()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let commitments = kzg_commitments
        .iter()
        .map(|a| Bytes48::from_bytes(a.as_bytes()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let kzg_proofs = kzg_proofs
        .iter()
        .map(|a| Bytes48::from_bytes(&a.as_bytes()).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let kzg_settings = settings();

    CKzgProof::verify_cell_kzg_proof_batch(
        commitments.as_slice(),
        cell_indices.as_slice(),
        cells.as_slice(),
        kzg_proofs.as_slice(),
        &kzg_settings,
    )
    .map_err(Into::into)
}

pub fn verify_sidecar_inclusion_proof<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
    metrics: &Option<Arc<Metrics>>,
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
    return is_valid_merkle_branch(
        kzg_commitments.hash_tree_root(),
        *kzg_commitments_inclusion_proof,
        index_at_commitment_depth,
        signed_block_header.message.body_root,
    );
}

pub fn get_custody_subnets(
    node_id: NodeId,
    custody_subnet_count: u64,
    config: &Arc<Config>,
) -> impl Iterator<Item = DataColumnSubnetId> {
    assert!(custody_subnet_count <= config.data_column_sidecar_subnet_count);

    let mut subnet_ids = vec![];
    let mut current_id = node_id;

    while (subnet_ids.len() as u64) < custody_subnet_count {
        let mut hasher = Sha256::new();
        let mut bytes: [u8; 32] = [0; 32];

        current_id.into_raw().to_little_endian(&mut bytes);

        hasher.update(&bytes);
        bytes = hasher.finalize().into();

        let output_prefix = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];

        let output_prefix_u64 = u64::from_le_bytes(output_prefix);
        let subnet_id = output_prefix_u64 % config.data_column_sidecar_subnet_count;

        if !subnet_ids.contains(&subnet_id) {
            subnet_ids.push(subnet_id);
        }

        if current_id == Uint256::MAX {
            current_id = Uint256::ZERO;
        }

        current_id = current_id + Uint256::one();
    }

    subnet_ids.into_iter().sorted()
}

pub fn get_custody_columns(
    node_id: NodeId,
    custody_subnet_count: u64,
    config: &Arc<Config>,
) -> impl Iterator<Item = ColumnIndex> {
    get_custody_subnets(node_id, custody_subnet_count, &config)
        .flat_map(|subnet_id| get_columns_index_for_subnet(subnet_id, &config))
        .sorted()
}

fn get_columns_index_for_subnet(
    subnet_id: DataColumnSubnetId,
    config: &Arc<Config>,
) -> impl Iterator<Item = ColumnIndex> {
    let data_column_sidecar_subnet_count = config.data_column_sidecar_subnet_count();
    let columns_per_subnet = NumberOfColumns::U64 / data_column_sidecar_subnet_count;

    (0..columns_per_subnet)
        .map(move |column_index| (data_column_sidecar_subnet_count * column_index + subnet_id))
        .sorted()
}

pub fn compute_matrix_for_data_column_sidecar<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
) -> Vec<MatrixEntry> {
    let DataColumnSidecar {
        index,
        column,
        kzg_proofs,
        ..
    } = data_column_sidecar;

    let blob_count = column.len() as u64;

    (0..blob_count)
        .zip(column)
        .zip(kzg_proofs)
        .map(|((row_index, cell), kzg_proof)| MatrixEntry {
            row_index,
            column_index: *index,
            cell: cell.clone(),
            kzg_proof: kzg_proof.clone(),
        })
        .collect()
}

/**
 * Return the full, flattened sequence of matrix entries.
 *
 * This helper demonstrates the relationship between blobs and the matrix of cells/proofs.
 */
pub fn compute_matrix(
    blobs: Vec<CKzgBlob>,
    metrics: &Option<Arc<Metrics>>,
) -> Result<Vec<MatrixEntry>> {
    let _timer = metrics
        .as_ref()
        .map(|metrics| metrics.data_column_sidecar_computation.start_timer());

    let kzg_settings = settings();

    let mut matrix = vec![];
    for (blob_index, blob) in blobs.iter().enumerate() {
        let (cells, proofs) = CKzgCell::compute_cells_and_kzg_proofs(blob, &kzg_settings)?;
        for (cell_index, (cell, proof)) in cells.into_iter().zip(proofs.into_iter()).enumerate() {
            matrix.push(MatrixEntry {
                cell: try_convert_ckzg_cell_to_cell(&cell)?,
                kzg_proof: KzgProof::try_from(proof.to_bytes().into_inner())?,
                row_index: blob_index as u64,
                column_index: cell_index as u64,
            });
        }
    }

    Ok(matrix)
}

/**
 * Recover the full, flattened sequence of matrix entries.
 *
 * This helper demonstrates how to apply ``recover_cells_and_kzg_proofs``.
 */
pub fn recover_matrix(
    partial_matrix: Vec<MatrixEntry>,
    blob_count: usize,
    metrics: &Option<Arc<Metrics>>,
) -> Result<Vec<MatrixEntry>> {
    let _timer = metrics
        .as_ref()
        .map(|metrics| metrics.columns_reconstruction_time.start_timer());

    let mut matrix = vec![];
    for blob_index in 0..blob_count {
        let (cell_indexs, cells_bytes): (Vec<_>, Vec<_>) = partial_matrix
            .iter()
            .filter_map(|e| {
                if e.row_index == blob_index as u64 {
                    Some((e.column_index, e.cell.as_bytes()))
                } else {
                    None
                }
            })
            .unzip();

        let cells = cells_bytes
            .into_iter()
            .map(|c| CKzgCell::from_bytes(c).map_err(Into::into))
            .collect::<Result<Vec<CKzgCell>>>()?;

        let kzg_settings = settings();
        let (recovered_cells, recovered_proofs) =
            CKzgCell::recover_cells_and_kzg_proofs(&cell_indexs, &cells, &kzg_settings)?;

        for (cell_index, (cell, proof)) in recovered_cells
            .into_iter()
            .zip(recovered_proofs.into_iter())
            .enumerate()
        {
            matrix.push(MatrixEntry {
                cell: try_convert_ckzg_cell_to_cell(&cell)?,
                kzg_proof: KzgProof::try_from(proof.to_bytes().into_inner())?,
                row_index: blob_index as u64,
                column_index: cell_index as u64,
            });
        }
    }

    Ok(matrix)
}

fn try_convert_ckzg_cell_to_cell(cell: &CKzgCell) -> Result<Cell> {
    Ok(Box::new(ByteVector::from(ContiguousVector::try_from_iter(
        cell.to_bytes(),
    )?)))
}

pub fn convert_blobs_to_cells_and_kzg_proofs<P: Preset>(
    blobs: impl Iterator<Item = Blob<P>>,
) -> Result<Vec<([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB])>> {
    let kzg_settings = settings();
    let cells_and_kzg_proofs = blobs
        .map(|blob| {
            let c_kzg_blob = CKzgBlob::from_bytes(blob.as_bytes())?;
            CKzgCell::compute_cells_and_kzg_proofs(&c_kzg_blob, &kzg_settings).map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?;

    let mut result: Vec<([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB])> = vec![];
    for (column_cells, column_proofs) in cells_and_kzg_proofs {
        let cells = column_cells
            .iter()
            .map(|cell| try_convert_ckzg_cell_to_cell(cell))
            .collect::<Result<Vec<Cell>>>()?;

        let proofs = column_proofs
            .iter()
            .map(|proof| KzgProof::try_from(proof.to_bytes().into_inner()).map_err(Into::into))
            .collect::<Result<Vec<KzgProof>>>()?;

        let column: [Cell; CELLS_PER_EXT_BLOB] = cells
            .try_into()
            .expect("cells should not be more than number of columns");
        let kzg_proofs: [KzgProof; CELLS_PER_EXT_BLOB] = proofs
            .try_into()
            .expect("kzg_proofs should not be more than number of columns");
        result.push((column, kzg_proofs));
    }

    Ok(result)
}

pub fn get_data_column_sidecars<P: Preset>(
    signed_block: &SignedBeaconBlock<P>,
    cells_and_kzg_proofs: Vec<([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB])>,
) -> Result<Vec<DataColumnSidecar<P>>> {
    let signed_block_header = signed_block.to_header();

    let mut sidecars: Vec<DataColumnSidecar<P>> = Vec::new();
    if let Some(post_deneb_beacon_block_body) = signed_block.message().body().post_deneb() {
        let kzg_commitments = post_deneb_beacon_block_body.blob_kzg_commitments();

        if kzg_commitments.is_empty() {
            return Ok(vec![]);
        }

        let blob_count = cells_and_kzg_proofs.len();
        ensure!(
            kzg_commitments.len() == blob_count,
            GetDataColumnSidecarsError::CellsCommitmentsLengthError {
                cells_length: blob_count,
                commitments_length: kzg_commitments.len(),
            }
        );

        let kzg_commitments_inclusion_proof = signed_block
            .message()
            .body()
            .post_electra()
            .map(|post_electra_beacon_block_body| {
                electra_kzg_commitment_inclusion_proof(post_electra_beacon_block_body)
            })
            .unwrap_or_else(|| kzg_commitment_inclusion_proof(post_deneb_beacon_block_body));

        for column_index in 0..NumberOfColumns::U64 {
            let column_cells: Vec<Cell> = (0..blob_count)
                .map(|row_index| cells_and_kzg_proofs[row_index].0[column_index as usize].clone())
                .collect();

            let column_proofs: Vec<KzgProof> = (0..blob_count)
                .map(|row_index| cells_and_kzg_proofs[row_index].1[column_index as usize].clone())
                .collect();

            let column = ContiguousList::try_from_iter(column_cells.into_iter())?;
            let kzg_proofs = ContiguousList::try_from_iter(column_proofs.into_iter())?;

            sidecars.push(DataColumnSidecar {
                index: column_index,
                column,
                kzg_commitments: kzg_commitments.clone(),
                kzg_proofs,
                signed_block_header,
                kzg_commitments_inclusion_proof,
            });
        }
    }

    Ok(sidecars)
}

fn kzg_commitment_inclusion_proof<P: Preset>(
    body: &(impl PostDenebBeaconBlockBody<P> + ?Sized),
) -> BlobCommitmentsInclusionProof {
    let mut proof = BlobCommitmentsInclusionProof::default();

    proof[0] = body.bls_to_execution_changes().hash_tree_root();

    proof[1] = hashing::hash_256_256(
        body.sync_aggregate().hash_tree_root(),
        body.execution_payload().hash_tree_root(),
    );

    proof[2] = ZERO_HASHES[2];

    proof[3] = hashing::hash_256_256(
        hashing::hash_256_256(
            hashing::hash_256_256(
                body.randao_reveal().hash_tree_root(),
                body.eth1_data().hash_tree_root(),
            ),
            hashing::hash_256_256(body.graffiti(), body.proposer_slashings().hash_tree_root()),
        ),
        hashing::hash_256_256(
            hashing::hash_256_256(body.attester_slashings_root(), body.attestations_root()),
            hashing::hash_256_256(
                body.deposits().hash_tree_root(),
                body.voluntary_exits().hash_tree_root(),
            ),
        ),
    );

    proof
}

fn electra_kzg_commitment_inclusion_proof<P: Preset>(
    body: &(impl PostElectraBeaconBlockBody<P> + ?Sized),
) -> BlobCommitmentsInclusionProof {
    let mut proof = BlobCommitmentsInclusionProof::default();

    proof[0] = body.bls_to_execution_changes().hash_tree_root();

    proof[1] = hashing::hash_256_256(
        body.sync_aggregate().hash_tree_root(),
        body.execution_payload().hash_tree_root(),
    );

    proof[2] = hashing::hash_256_256(
        hashing::hash_256_256(body.execution_requests().hash_tree_root(), ZERO_HASHES[0]),
        ZERO_HASHES[1],
    );

    proof[3] = hashing::hash_256_256(
        hashing::hash_256_256(
            hashing::hash_256_256(
                body.randao_reveal().hash_tree_root(),
                body.eth1_data().hash_tree_root(),
            ),
            hashing::hash_256_256(body.graffiti(), body.proposer_slashings().hash_tree_root()),
        ),
        hashing::hash_256_256(
            hashing::hash_256_256(body.attester_slashings_root(), body.attestations_root()),
            hashing::hash_256_256(
                body.deposits().hash_tree_root(),
                body.voluntary_exits().hash_tree_root(),
            ),
        ),
    );

    proof
}

/**
 * Return the sample count if allowing failures.
 *
 * This helper demonstrates how to calculate the number of columns to query per slot when
 * allowing given number of failures, assuming uniform random selection without replacement.
*/
pub fn get_extended_sample_count(allowed_failures: u64, config: &Config) -> Result<u64> {
    // check that `allowed_failures` within the accepted range [0 -> NUMBER_OF_COLUMNS // 2]
    // missing chunks for more than a half is the worst case
    let worst_case_missing = NumberOfColumns::U64 / 2 + 1;
    ensure!(
        allowed_failures < worst_case_missing,
        ExtendedSampleError::AllowedFailtureOutOfRange { allowed_failures }
    );

    // modified from [math_lib](https://docs.rs/math_l/latest/src/math_l/math.rs.html#32-38) with compatible types
    let math_comb = |n: u64, k: u64| -> f64 {
        if k > n {
            0_f64
        } else {
            (1..=k).fold(1_f64, |acc, i| acc * (n - i + 1) as f64 / i as f64)
        }
    };

    let hypergeom_cdf = |k: u64, m: u64, n: u64, big_n: u64| -> f64 {
        (0..=k).fold(0_f64, |acc, i| {
            acc + math_comb(n, i) * math_comb(m - n, big_n - i) / math_comb(m, big_n)
        })
    };

    // the probability of successful sampling of an unavailable block
    let false_positive_threshold = hypergeom_cdf(
        0,
        NumberOfColumns::U64,
        worst_case_missing,
        config.samples_per_slot(),
    );

    // number of unique column IDs
    let mut sample_count = config.samples_per_slot();
    while sample_count <= NumberOfColumns::U64 {
        if hypergeom_cdf(
            allowed_failures,
            NumberOfColumns::U64,
            worst_case_missing,
            sample_count,
        ) <= false_positive_threshold
        {
            break;
        }
        sample_count += 1;
    }

    Ok(sample_count)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use duplicate::duplicate_item;
    use helper_functions::predicates::{index_at_commitment_depth, is_valid_merkle_branch};
    use serde::Deserialize;
    use spec_test_utils::Case;
    use ssz::{SszHash as _, H256};
    use test_generator::test_resources;
    use typenum::Unsigned as _;
    use types::{
        config::Config,
        deneb::containers::BeaconBlockBody as DenebBeaconBlockBody,
        phase0::primitives::NodeId,
        preset::{Mainnet, Minimal, Preset},
    };

    use crate::{get_custody_columns, kzg_commitment_inclusion_proof, ColumnIndex};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Meta {
        description: Option<String>,
        node_id: NodeId,
        custody_subnet_count: u64,
        result: Vec<ColumnIndex>,
    }

    #[duplicate_item(
        glob                                                                              function_name                 preset;
        ["consensus-spec-tests/tests/mainnet/eip7594/networking/get_custody_columns/*/*"] [get_custody_columns_mainnet] [Mainnet];
        ["consensus-spec-tests/tests/minimal/eip7594/networking/get_custody_columns/*/*"] [get_custody_columns_minimal] [Minimal];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_case::<preset>(case);
    }

    fn run_case<P: Preset>(case: Case) {
        let Meta {
            description: _description,
            node_id,
            custody_subnet_count,
            result,
        } = case.yaml::<Meta>("meta");

        let config = Arc::new(Config::default());
        assert_eq!(
            get_custody_columns(node_id, custody_subnet_count, &config).collect::<Vec<_>>(),
            result
        );
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Proof {
        leaf: H256,
        leaf_index: u64,
        branch: Vec<H256>,
    }

    #[duplicate_item(
        glob                                                                                                                   function_name                            preset;
        ["consensus-spec-tests/tests/mainnet/eip7594/merkle_proof/single_merkle_proof/BeaconBlockBody/blob_kzg_commitments_*"] [kzg_commitment_inclusion_proof_mainnet] [Mainnet];
        ["consensus-spec-tests/tests/minimal/eip7594/merkle_proof/single_merkle_proof/BeaconBlockBody/blob_kzg_commitments_*"] [kzg_commitment_inclusion_proof_minimal] [Minimal];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_beacon_block_body_proof_case::<preset>(case);
    }

    fn run_beacon_block_body_proof_case<P: Preset>(case: Case) {
        let Proof {
            leaf,
            leaf_index,
            branch,
        } = case.yaml("proof");

        // Unlike the name suggests, `leaf_index` is actually a generalized index.
        // `is_valid_merkle_branch` expects an index that includes only leaves.
        let commitment_index = leaf_index % P::MaxBlobCommitmentsPerBlock::U64;
        let index_at_commitment_depth = index_at_commitment_depth::<P>(commitment_index);
        // vs
        // let index_at_leaf_depth = leaf_index - leaf_index.prev_power_of_two();

        let block_body: DenebBeaconBlockBody<P> =
            case.ssz_default::<DenebBeaconBlockBody<P>>("object");

        let root = block_body.hash_tree_root();

        // > Check that `is_valid_merkle_branch` confirms `leaf` at `leaf_index` to verify
        // > against `has_tree_root(state)` and `proof`.
        assert!(is_valid_merkle_branch(
            leaf,
            branch.iter().copied(),
            index_at_commitment_depth,
            root,
        ));

        // > If the implementation supports generating merkle proofs, check that the
        // > self-generated proof matches the `proof` provided with the test.
        //
        let proof = kzg_commitment_inclusion_proof(&block_body);

        assert_eq!(proof.as_slice(), branch);
    }
}
