use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use anyhow::Result;
use c_kzg::{Blob, Bytes32, Bytes48, Cell as CKzgCell, KzgProof as CKzgProof, KzgSettings};
use hashing::{hash_64, ZERO_HASHES};
use helper_functions::{
    misc,
    predicates::{index_at_commitment_depth, is_valid_merkle_branch},
};
use sha3::{Digest, Sha3_256};
use ssz::{
    ByteVector, ContiguousList, ContiguousVector, MerkleElements, MerkleTree, SszHash, SszWrite,
    H256,
};
use try_from_iterator::TryFromIterator as _;
use typenum::{Unsigned as _, U2048};
use types::{
    config::Config,
    deneb::primitives::{BlobIndex, KzgCommitment, KzgProof},
    eip7594::{BlobCommitmentsInclusionProof, ColumnIndex, DataColumnSidecar, NumberOfColumns},
    electra::containers::SignedBeaconBlock,
    phase0::{
        containers::{BeaconBlockHeader, SignedBeaconBlockHeader},
        primitives::{NodeId, SubnetId},
    },
    traits::PostElectraBeaconBlockBody,
};
use types::{
    eip7594::{Cell, DATA_COLUMN_SIDECAR_SUBNET_COUNT},
    preset::Preset,
};

use num_traits::One as _;
use sha2::Sha256;
use ssz::Uint256;
use types::eip7594::{CustodyIndex, NUMBER_OF_CUSTODY_GROUPS};
use types::phase0::primitives::NodeId as NodeID;

const SAMPLES_PER_SLOT: u64 = 8;
const TARGET_NUMBER_OF_PEERS: u64 = 70;
const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 2 * FIELD_ELEMENTS_PER_BLOB;
const FIELD_ELEMENTS_PER_CELL: usize = 64;
const BYTES_PER_FIELD_ELEMENT: usize = 32;
const BYTES_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT;
type BytesPerCell = U2048;
const CELLS_PER_BLOB: usize = FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL;
const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: usize = 4;
const MAX_BLOBS_PER_BLOCK: u64 = 6;
const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 6;

type PolynomialCoeff = [Bytes32; FIELD_ELEMENTS_PER_EXT_BLOB];
type CellID = u64;
type RowIndex = u64;
// type BlobIndex = usize;
type ExtendedMatrix = [CKzgCell; (MAX_BLOBS_PER_BLOCK * NumberOfColumns::U64) as usize];

pub fn verify_kzg_proofs<P: Preset>(data_column_sidecar: &DataColumnSidecar<P>) -> Result<bool> {
    let DataColumnSidecar {
        index,
        column,
        kzg_commitments,
        kzg_proofs,
        ..
    } = data_column_sidecar;

    assert!(*index < NumberOfColumns::U64);
    assert!(column.len() == kzg_commitments.len() && column.len() == kzg_proofs.len());

    let mut row_ids = Vec::new();
    for i in 0..column.len() {
        row_ids.push(i as u64);
    }

    let trusted_setup_file = Path::new("kzg_utils/trusted_setup.txt");
    let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

    let column = column
        .clone()
        .into_iter()
        .map(|a| CKzgCell::from_bytes(a.as_bytes()).unwrap())
        .collect::<Vec<_>>();

    let commitment = kzg_commitments
        .iter()
        .map(|a| Bytes48::from_bytes(a.as_bytes()).unwrap())
        .collect::<Vec<_>>();

    let kzg_proofs = kzg_proofs
        .iter()
        .map(|a| Bytes48::from_bytes(&a.as_bytes()).unwrap())
        .collect::<Vec<_>>();

    Ok(CKzgProof::verify_cell_proof_batch(
        &commitment[..],
        &row_ids,
        &[*index],
        &column[..],
        &kzg_proofs,
        &kzg_settings,
    )?)
}

pub fn verify_sidecar_inclusion_proof<P: Preset>(
    data_column_sidecar: &DataColumnSidecar<P>,
) -> bool {
    let DataColumnSidecar {
        index,
        kzg_commitments,
        signed_block_header,
        kzg_commitments_inclusion_proof,
        ..
    } = data_column_sidecar;

    let index_at_commitment_depth = index_at_commitment_depth::<P>(*index);

    // is_valid_blob_sidecar_inclusion_proof
    return is_valid_merkle_branch(
        kzg_commitments.hash_tree_root(),
        *kzg_commitments_inclusion_proof,
        index_at_commitment_depth,
        signed_block_header.message.body_root,
    );
}

// source: https://github.com/ethereum/consensus-specs/pull/3574/files/cebf78a83e6fc8fa237daf4264b9ca0fe61473f4#diff-96cf4db15bede3d60f04584fb25339507c35755959159cdbe19d760ca92de109R106
pub fn compute_subnet_for_data_column_sidecar(column_index: ColumnIndex) -> SubnetId {
    (column_index % DATA_COLUMN_SIDECAR_SUBNET_COUNT)
        .try_into()
        .unwrap()
}

pub fn get_custody_columns(node_id: NodeId, custody_subnet_count: u64) -> Vec<ColumnIndex> {
    assert!(custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT);

    let mut subnet_ids = HashSet::new();
    let mut i: u64 = 0;
    while (subnet_ids.len() as u64) < custody_subnet_count {
        let mut hasher = Sha3_256::new();
        let mut bytes: [u8; 32] = [0; 32];
        (node_id + NodeId::from_u64(i)).write_fixed(&mut bytes);
        println!("bytes = {:?}", bytes);

        let last_8_bytes: [u8; 8] = bytes[0..8].try_into().unwrap();
        println!("last_8_bytes = {:?}", &last_8_bytes);
        hasher.update(last_8_bytes);
        let u64_from_last_8 = u64::from_le_bytes(last_8_bytes);
        let el = hash_64(u64_from_last_8);
        // let mut output: [u8; 32] = hasher.finalize().into();
        let output = el.as_bytes();
        println!("hasho output = {:?}", output);

        let output_prefix = [
            output[0], output[1], output[2], output[3], output[4], output[5], output[6], output[7],
        ];
        let output_prefix_u64 = u64::from_le_bytes(output_prefix);
        let subnet_id = output_prefix_u64 % DATA_COLUMN_SIDECAR_SUBNET_COUNT;
        println!("subnet_id = {}", subnet_id);
        if !subnet_ids.contains(&subnet_id) {
            subnet_ids.insert(subnet_id);
        }
        i += 1;
    }
    assert_eq!(subnet_ids.len() as u64, custody_subnet_count);

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

pub fn compute_extended_matrix(blobs: Vec<Blob>) -> Result<ExtendedMatrix> {
    let mut extended_matrix: Vec<CKzgCell> = Vec::new();

    let trusted_setup_file = Path::new("kzg_utils/trusted_setup.txt");

    let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

    for blob in blobs {
        let cells = *CKzgCell::compute_cells(&blob, &kzg_settings)?;
        extended_matrix.extend(cells);
    }

    let mut array = [CKzgCell::default(); (MAX_BLOBS_PER_BLOCK * NumberOfColumns::U64) as usize];
    array.copy_from_slice(&extended_matrix[..]);

    Ok(array)
}

fn recover_matrix(
    cells_dict: &HashMap<(BlobIndex, CellID), CKzgCell>,
    blob_count: usize,
) -> Result<ExtendedMatrix> {
    let trusted_setup_file = Path::new("kzg_utils/trusted_setup.txt");
    let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

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

fn get_data_column_sidecars<P: Preset>(
    signed_block: SignedBeaconBlock<P>,
    blobs: Vec<Blob>,
) -> Result<Vec<DataColumnSidecar<P>>> {
    let trusted_setup_file = Path::new("kzg_utils/trusted_setup.txt");
    let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

    let block_header = BeaconBlockHeader {
        slot: signed_block.message.slot,
        proposer_index: signed_block.message.proposer_index,
        parent_root: signed_block.message.parent_root,
        state_root: signed_block.message.state_root,
        body_root: signed_block.message.body.hash_tree_root(),
    };
    let signed_block_header = SignedBeaconBlockHeader {
        message: block_header,
        signature: signed_block.signature,
    };

    let mut cells_and_proofs = Vec::new();
    for blob in &blobs {
        cells_and_proofs.push(CKzgCell::compute_cells_and_proofs(&blob, &kzg_settings)?);
    }
    let blob_count = blobs.len();
    // let mut cells: Vec<Vec<CKzgCell>> = Vec::new();
    // let mut proofs: Vec<Vec<KzgProof>> = Vec::new();
    // for i in 0..blob_count {
    //     cells.push(cells_and_proofs[i].0.clone());
    //     proofs.push(cells_and_proofs[i].1.clone());
    // }
    let mut sidecars: Vec<DataColumnSidecar<P>> = Vec::new();
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
        // let mut column_cell_array = [[0; 2048]; MAX_BLOB_COMMITMENTS_PER_BLOCK];
        // column_cell_array.copy_from_slice(&column_cells[..]);

        let mut kzg_proofs_array: [[u8; 48]; MAX_BLOB_COMMITMENTS_PER_BLOCK] =
            [[0; 48]; MAX_BLOB_COMMITMENTS_PER_BLOCK];
        kzg_proofs_array.copy_from_slice(&kzg_proof_of_column[..]);

        let mut continuous_proof_vec = Vec::new();
        for proof in kzg_proofs_array {
            continuous_proof_vec.push(KzgProof::try_from(proof)?);
        }

        sidecars.push(DataColumnSidecar {
            index: column_index,
            column: ContiguousList::try_from(cont_cells)?,
            kzg_commitments: signed_block.message.body.blob_kzg_commitments.clone(),
            kzg_proofs: ContiguousList::try_from(continuous_proof_vec)?,
            signed_block_header,
            kzg_commitments_inclusion_proof: kzg_commitment_inclusion_proof(
                &signed_block.message.body,
                column_index,
            ),
        });
    }

    Ok(sidecars)
}

fn kzg_commitment_inclusion_proof<P: Preset>(
    body: &(impl PostElectraBeaconBlockBody<P> + ?Sized),
    commitment_index: BlobIndex,
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

#[must_use]
pub fn get_custody_groups(node_id: NodeID, custody_group_count: u64) -> Vec<CustodyIndex> {
    assert!(custody_group_count <= NUMBER_OF_CUSTODY_GROUPS);

    let mut custody_groups = vec![];
    let mut current_id = node_id;

    while (custody_groups.len() as u64) < custody_group_count {
        let mut hasher = Sha256::new();
        let mut bytes: [u8; 32] = [0; 32];

        current_id.into_raw().to_little_endian(&mut bytes);

        hasher.update(bytes);
        bytes = hasher.finalize().into();

        let output_prefix = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];

        let output_prefix_u64 = u64::from_le_bytes(output_prefix);
        let custody_group = output_prefix_u64 % NUMBER_OF_CUSTODY_GROUPS;

        if !custody_groups.contains(&custody_group) {
            custody_groups.push(custody_group);
        }

        if current_id == Uint256::MAX {
            current_id = Uint256::ZERO;
        }

        current_id = current_id + Uint256::one();
    }

    custody_groups.sort_unstable();
    custody_groups
}

// #[cfg(test)]
// mod tests {
//     use duplicate::duplicate_item;
//     use helper_functions::predicates::{index_at_commitment_depth, is_valid_merkle_branch};
//     use serde::Deserialize;
//     use spec_test_utils::Case;
//     use ssz::{SszHash as _, H256};
//     use test_generator::test_resources;
//     use typenum::Unsigned as _;
//     use types::{
//         electra::containers::BeaconBlockBody as ElectraBeaconBlockBody,
//         phase0::primitives::NodeId,
//         preset::{Mainnet, Minimal, Preset},
//     };
//
//     use crate::{get_custody_columns, kzg_commitment_inclusion_proof, ColumnIndex};
//
//     #[derive(Deserialize)]
//     #[serde(deny_unknown_fields)]
//     struct Meta {
//         description: Option<String>,
//         node_id: NodeId,
//         custody_subnet_count: u64,
//         result: Vec<ColumnIndex>,
//     }
//
//     #[duplicate_item(
//         glob                                                                              function_name                 preset;
//         ["consensus-spec-tests/tests/mainnet/eip7594/networking/get_custody_columns/*/*"] [get_custody_columns_mainnet] [Mainnet];
//         ["consensus-spec-tests/tests/minimal/eip7594/networking/get_custody_columns/*/*"] [get_custody_columns_minimal] [Minimal];
//     )]
//     #[test_resources(glob)]
//     fn function_name(case: Case) {
//         run_case::<preset>(case);
//     }
//
//     fn run_case<P: Preset>(case: Case) {
//         let Meta {
//             description: _description,
//             node_id,
//             custody_subnet_count,
//             result,
//         } = case.yaml::<Meta>("meta");
//
//         assert_eq!(get_custody_columns(node_id, custody_subnet_count), result);
//     }
//
//     #[derive(Deserialize)]
//     #[serde(deny_unknown_fields)]
//     struct Proof {
//         leaf: H256,
//         leaf_index: u64,
//         branch: Vec<H256>,
//     }
//
//     #[duplicate_item(
//         glob                                                                                              function_name                            preset;
//         ["consensus-spec-tests/tests/mainnet/eip7594/merkle_proof/single_merkle_proof/BeaconBlockBody/blob_kzg_commitments_*"] [kzg_commitment_inclusion_proof_mainnet] [Mainnet];
//         ["consensus-spec-tests/tests/minimal/eip7594/merkle_proof/single_merkle_proof/BeaconBlockBody/blob_kzg_commitments_*"] [kzg_commitment_inclusion_proof_minimal] [Minimal];
//     )]
//     #[test_resources(glob)]
//     fn function_name(case: Case) {
//         run_beacon_block_body_proof_case::<preset>(case);
//     }
//
//     fn run_beacon_block_body_proof_case<P: Preset>(case: Case) {
//         let Proof {
//             leaf,
//             leaf_index,
//             branch,
//         } = case.yaml("proof");
//
//         // Unlike the name suggests, `leaf_index` is actually a generalized index.
//         // `is_valid_merkle_branch` expects an index that includes only leaves.
//         let commitment_index = leaf_index % P::MaxBlobCommitmentsPerBlock::U64;
//         let index_at_commitment_depth = index_at_commitment_depth::<P>(commitment_index);
//         // vs
//         // let index_at_leaf_depth = leaf_index - leaf_index.prev_power_of_two();
//
//         let block_body: ElectraBeaconBlockBody<P> =
//             case.ssz_default::<ElectraBeaconBlockBody<P>>("object");
//
//         let root = block_body.hash_tree_root();
//
//         // > Check that `is_valid_merkle_branch` confirms `leaf` at `leaf_index` to verify
//         // > against `has_tree_root(state)` and `proof`.
//         assert!(is_valid_merkle_branch(
//             leaf,
//             branch.iter().copied(),
//             index_at_commitment_depth,
//             root,
//         ));
//
//         // > If the implementation supports generating merkle proofs, check that the
//         // > self-generated proof matches the `proof` provided with the test.
//         //
//         let proof = kzg_commitment_inclusion_proof(&block_body, commitment_index);
//
//         assert_eq!(proof.as_slice(), branch);
//     }
// }

#[cfg(test)]
mod test {
    use duplicate::duplicate_item;
    use serde::Deserialize;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::{
        eip7594::CustodyIndex,
        phase0::primitives::NodeId,
        preset::{Mainnet, Minimal, Preset},
    };

    use crate::get_custody_groups;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Meta {
        description: Option<String>,
        node_id: NodeId,
        custody_group_count: u64,
        result: Vec<CustodyIndex>,
    }

    #[duplicate_item(
        glob                                                                              function_name                 preset;
        ["consensus-spec-tests/tests/mainnet/fulu/networking/get_custody_groups/*/*"] [get_custody_groups_mainnet] [Mainnet];
        ["consensus-spec-tests/tests/minimal/fulu/networking/get_custody_groups/*/*"] [get_custody_groups_minimal] [Minimal];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_case::<preset>(case);
    }

    #[expect(clippy::extra_unused_type_parameters)]
    fn run_case<P: Preset>(case: Case) {
        let Meta {
            description: _description,
            node_id,
            custody_group_count,
            result,
        } = case.yaml::<Meta>("meta");

        assert_eq!(get_custody_groups(node_id, custody_group_count), result);
    }
}
