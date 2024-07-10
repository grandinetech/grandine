use std::collections::HashMap;

use anyhow::{ensure, Result};
use c_kzg::{Blob as CKzgBlob, Bytes48, Cell as CKzgCell, KzgProof as CKzgProof};
use hashing::ZERO_HASHES;
use helper_functions::predicates::is_valid_merkle_branch;
use num_traits::One as _;
use sha2::{Digest as _, Sha256};
use ssz::{ByteVector, ContiguousList, ContiguousVector, SszHash, Uint256};
use thiserror::Error;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned;
use types::{
    combined::SignedBeaconBlock,
    deneb::primitives::{Blob, BlobIndex, KzgProof},
    eip7594::{
        BlobCommitmentsInclusionProof, ColumnIndex, DataColumnSidecar, NumberOfColumns,
        DATA_COLUMN_SIDECAR_SUBNET_COUNT, SAMPLES_PER_SLOT,
    },
    phase0::{containers::SignedBeaconBlockHeader, primitives::NodeId},
    preset::Preset,
    traits::{BeaconBlock as _, PostDenebBeaconBlockBody},
};

use crate::trusted_setup::settings;

mod trusted_setup;

const MAX_BLOBS_PER_BLOCK: u64 = 6;

type ExtendedMatrix = [CKzgCell; (MAX_BLOBS_PER_BLOCK * NumberOfColumns::U64) as usize];
type CellID = u64;

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
}

pub fn verify_kzg_proofs<P: Preset>(data_column_sidecar: &DataColumnSidecar<P>) -> Result<bool> {
    let DataColumnSidecar {
        index,
        column,
        kzg_commitments,
        kzg_proofs,
        ..
    } = data_column_sidecar;

    ensure!(
        *index < NumberOfColumns::U64,
        VerifyKzgProofsError::SidecarIndexOutOfBounds { index: *index }
    );

    ensure!(
        column.len() == kzg_commitments.len(),
        VerifyKzgProofsError::SidecarCommitmentsLengthError {
            column_length: column.len(),
            commitments_length: kzg_commitments.len(),
        }
    );

    ensure!(
        column.len() == kzg_proofs.len(),
        VerifyKzgProofsError::SidecarProofsLengthError {
            column_length: column.len(),
            proofs_length: kzg_proofs.len(),
        }
    );

    let (row_indices, col_indices): (Vec<_>, Vec<_>) = column
        .iter()
        .zip(0_u64..)
        .map(|(_, row_index)| (row_index, index))
        .unzip();

    let kzg_settings = settings();

    let column = column
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

    CKzgProof::verify_cell_proof_batch(
        commitments.as_slice(),
        &row_indices,
        &col_indices,
        column.as_slice(),
        &kzg_proofs,
        &kzg_settings,
    )
    .map_err(Into::into)
}

pub fn verify_sidecar_inclusion_proof<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
) -> bool {
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

pub fn get_custody_columns(node_id: NodeId, custody_subnet_count: u64) -> Vec<ColumnIndex> {
    assert!(custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT);

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
        let subnet_id = output_prefix_u64 % DATA_COLUMN_SIDECAR_SUBNET_COUNT;

        if !subnet_ids.contains(&subnet_id) {
            subnet_ids.push(subnet_id);
        }

        if current_id == Uint256::MAX {
            current_id = Uint256::ZERO;
        }

        current_id = current_id + Uint256::one();
    }

    let columns_per_subnet = NumberOfColumns::U64 / DATA_COLUMN_SIDECAR_SUBNET_COUNT;
    let mut result = Vec::new();
    for i in 0..columns_per_subnet {
        for &subnet_id in &subnet_ids {
            result.push(
                (DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnet_id)
                    .try_into()
                    .unwrap(),
            );
        }
    }

    result.sort();
    result
}

pub fn compute_extended_matrix(blobs: Vec<CKzgBlob>) -> Result<ExtendedMatrix> {
    let mut extended_matrix: Vec<CKzgCell> = Vec::new();

    let kzg_settings = settings();

    for blob in blobs {
        let cells = *CKzgCell::compute_cells(&blob, &kzg_settings)?;
        extended_matrix.extend(cells);
    }

    let mut array = [CKzgCell::default(); (MAX_BLOBS_PER_BLOCK * NumberOfColumns::U64) as usize];
    array.copy_from_slice(&extended_matrix[..]);

    Ok(array)
}

pub fn recover_matrix(
    cells_dict: &HashMap<(BlobIndex, CellID), CKzgCell>,
    blob_count: usize,
) -> Result<ExtendedMatrix> {
    let kzg_settings = settings();

    let mut extended_matrix = Vec::new();
    for blob_index in 0..blob_count {
        let mut cell_ids = Vec::new();
        for &(b_index, cell_id) in cells_dict.keys() {
            if b_index == blob_index as u64 {
                cell_ids.push(cell_id);
            }
        }
        let cells: Vec<CKzgCell> = cell_ids
            .iter()
            .map(|&cell_id| cells_dict[&(blob_index as u64, cell_id)])
            .collect();
        let full_polynomial = CKzgCell::recover_polynomial(&cell_ids, &cells, &kzg_settings)?;
        extended_matrix.push(full_polynomial);
    }
    let mut array = [CKzgCell::default(); (MAX_BLOBS_PER_BLOCK * NumberOfColumns::U64) as usize];
    array.copy_from_slice(&extended_matrix[..]);

    Ok(array)
}

pub fn get_data_column_sidecars<P: Preset>(
    signed_block: SignedBeaconBlock<P>,
    blobs: impl Iterator<Item = Blob<P>>,
) -> Result<Vec<DataColumnSidecar<P>>> {
    let mut sidecars: Vec<DataColumnSidecar<P>> = Vec::new();
    let (beacon_block, signature) = signed_block.split();

    if let Some(post_deneb_beacon_block_body) = beacon_block.body().post_deneb() {
        let kzg_commitments_inclusion_proof =
            kzg_commitment_inclusion_proof(post_deneb_beacon_block_body);

        let kzg_settings = settings();

        let signed_block_header = SignedBeaconBlockHeader {
            message: beacon_block.to_header(),
            signature,
        };

        let c_kzg_blobs = blobs
            .map(|blob| CKzgBlob::from_bytes(blob.as_bytes()).map_err(Into::into))
            .collect::<Result<Vec<CKzgBlob>>>()?;

        let cells_and_proofs = c_kzg_blobs
            .into_iter()
            .map(|blob| {
                CKzgCell::compute_cells_and_proofs(&blob, &kzg_settings).map_err(Into::into)
            })
            .collect::<Result<Vec<_>>>()?;

        let blob_count = cells_and_proofs.len();

        for column_index in 0..NumberOfColumns::U64 {
            let mut column_cells: Vec<CKzgCell> = Vec::new();

            for row_index in 0..blob_count {
                column_cells.push(cells_and_proofs[row_index].0[column_index as usize].clone());
            }

            let kzg_proof_of_column: Vec<_> = (0..blob_count)
                .map(|row_index| cells_and_proofs[row_index].1[column_index as usize].clone())
                .collect();

            let cells = column_cells.iter().map(|cell| cell.to_bytes());

            let mut cont_cells = Vec::new();

            for cell in cells {
                let bytes = cell.into_iter();
                let v = ByteVector::from(ContiguousVector::try_from_iter(bytes)?);
                let v = Box::new(v);

                cont_cells.push(v);
            }

            let proofs = kzg_proof_of_column
                .iter()
                .map(|data| KzgProof::try_from(data).map_err(Into::into))
                .collect::<Result<Vec<KzgProof>>>()?;

            let kzg_proofs = ContiguousList::try_from_iter(proofs.into_iter())?;

            sidecars.push(DataColumnSidecar {
                index: column_index,
                column: ContiguousList::try_from(cont_cells)?,
                kzg_commitments: post_deneb_beacon_block_body.blob_kzg_commitments().clone(),
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
            hashing::hash_256_256(
                body.attester_slashings().hash_tree_root(),
                body.attestations().hash_tree_root(),
            ),
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
pub fn get_extended_sample_count(allowed_failures: u64) -> u64 {
    // check that `allowed_failures` within the accepted range [0 -> NUMBER_OF_COLUMNS // 2]
    assert!((0..(NumberOfColumns::U64 / 2)).contains(&allowed_failures));

    // missing chunks for more than a half is the worst case
    let worst_case_missing = NumberOfColumns::U64 / 2 + 1;

    // the probability of successful sampling of an unavailable block
    let false_positive_threshold = 
        hypergeom_cdf(0, NumberOfColumns::U64, worst_case_missing, SAMPLES_PER_SLOT);

    // number of unique column IDs
    let mut sample_count = SAMPLES_PER_SLOT;
    while sample_count <= NumberOfColumns::U64 + 1 {
        // TODO(feature/das): change variable name `x` to a suitable one
        let x = 
            hypergeom_cdf(allowed_failures, NumberOfColumns::U64, worst_case_missing, sample_count);
        if x <= false_positive_threshold {
            break;
        }
        sample_count += 1;
    }
    return sample_count;
}

fn hypergeom_cdf(k: u64, m: u64, n: u64, big_n: u64) -> f64 {
    let mut sum = 0_f64;
    for i in 0..(k + 1) {
        sum += math_comb(n, i) * math_comb(m - n, big_n - i) / math_comb(m, big_n);
    }
    sum
}

fn math_comb(n: u64, k: u64) -> f64 {
    if !(0..n).contains(&k) {
        return 0_f64;
    }
    let mut r = 1_f64;
    for i in 0..(std::cmp::min(k, n - k)) {
        r *= (n - i) as f64 / (i + 1) as f64
    }
    r
}

#[cfg(test)]
mod tests {
    use duplicate::duplicate_item;
    use helper_functions::predicates::{index_at_commitment_depth, is_valid_merkle_branch};
    use serde::Deserialize;
    use spec_test_utils::Case;
    use ssz::{SszHash as _, H256};
    use test_generator::test_resources;
    use typenum::Unsigned as _;
    use types::{
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

        assert_eq!(get_custody_columns(node_id, custody_subnet_count), result);
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Proof {
        leaf: H256,
        leaf_index: u64,
        branch: Vec<H256>,
    }

    #[duplicate_item(
        glob                                                                                              function_name                            preset;
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
