use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use anyhow::Result;
use c_kzg::{Blob, Bytes32, Bytes48, Cell, KzgProof, KzgSettings};
use hashing::hash_64;
use helper_functions::{
    accessors,
    error::SignatureKind,
    misc,
    predicates::{index_at_commitment_depth, is_valid_merkle_branch},
    signing::SignForSingleFork,
};
use sha3::{Digest, Sha3_256};
use ssz::{ContiguousList, SszHash, SszWrite, H256};
use typenum::U2048;
use types::preset::Preset;
use types::{
    config::Config,
    deneb::{consts::DOMAIN_BLOB_SIDECAR, containers::SignedBeaconBlock, primitives::BlobIndex},
    eip7594::{ColumnIndex, DataColumnSidecar},
    phase0::{
        containers::{BeaconBlockHeader, SignedBeaconBlockHeader},
        primitives::{DomainType, Epoch, NodeId},
    },
    traits::BeaconState,
};

pub const DATA_COLUMN_SIDECAR_SUBNET_COUNT: u64 = 32;
const SAMPLES_PER_SLOT: u64 = 8;
const CUSTODY_REQUIREMENT: u64 = 1;
const TARGET_NUMBER_OF_PEERS: u64 = 70;
const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 2 * FIELD_ELEMENTS_PER_BLOB;
const FIELD_ELEMENTS_PER_CELL: usize = 64;
const BYTES_PER_FIELD_ELEMENT: usize = 32;
const BYTES_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT;
type BytesPerCell = U2048;
const CELLS_PER_BLOB: usize = FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL;
const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: usize = 4;
pub const NUMBER_OF_COLUMNS: u64 = 128;
const MAX_BLOBS_PER_BLOCK: u64 = 6; //todo!();
const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 6; // todo!();

type PolynomialCoeff = [Bytes32; FIELD_ELEMENTS_PER_EXT_BLOB];
type CellID = u64;
type RowIndex = u64;
// type BlobIndex = usize;
type ExtendedMatrix = [Cell; (MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS) as usize];
pub type DataColumnSubnetId = usize; // idejau tam, kad kompiliuotusi, nezinau ar reikia.

pub fn verify_kzg_proofs<P: Preset>(data_column_sidecar: &DataColumnSidecar<P>) -> Result<bool> {
    let DataColumnSidecar {
        index,
        column,
        kzg_commitments,
        kzg_proofs,
        ..
    } = data_column_sidecar;

    assert!(*index < NUMBER_OF_COLUMNS);
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
        .map(|a| Cell::from_bytes(&a.into_iter().collect::<Vec<_>>()[..]).unwrap())
        .collect::<Vec<_>>();

    let commitment = kzg_commitments
        .iter()
        .map(|a| Bytes48::from_bytes(a.as_bytes()).unwrap())
        .collect::<Vec<_>>();

    let kzg_proofs = kzg_proofs
        .iter()
        .map(|a| {
            Bytes48::from_bytes(&a.into_iter().map(|a| a.clone()).collect::<Vec<_>>()[..]).unwrap()
        })
        .collect::<Vec<_>>();

    Ok(KzgProof::verify_cell_proof_batch(
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
pub fn compute_subnet_for_data_column_sidecar(column_index: ColumnIndex) -> DataColumnSubnetId {
    (column_index % DATA_COLUMN_SIDECAR_SUBNET_COUNT)
        .try_into()
        .unwrap()
}

pub fn verify_data_column_sidecar_kzg_proofs<P: Preset>(
    sidecar: DataColumnSidecar<P>,
) -> Result<bool> {
    assert!(sidecar.index < NUMBER_OF_COLUMNS);
    assert!(
        sidecar.column.len() == sidecar.kzg_commitments.len()
            && sidecar.column.len() == sidecar.kzg_proofs.len()
    );
    let mut row_ids = Vec::new();
    for i in 0..sidecar.column.len() {
        row_ids.push(i as u64);
    }

    let trusted_setup_file = Path::new("kzg_utils/trusted_setup.txt");
    let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

    let column = sidecar
        .column
        .into_iter()
        .map(|a| Cell::from_bytes(&a.into_iter().collect::<Vec<_>>()[..]).unwrap())
        .collect::<Vec<_>>();
    let commitment = sidecar
        .kzg_commitments
        .iter()
        .map(|a| Bytes48::from_bytes(a.as_bytes()).unwrap())
        .collect::<Vec<_>>();
    let kzg_proofs = sidecar
        .kzg_proofs
        .iter()
        .map(|a| {
            Bytes48::from_bytes(&a.into_iter().map(|a| a.clone()).collect::<Vec<_>>()[..]).unwrap()
        })
        .collect::<Vec<_>>();

    Ok(KzgProof::verify_cell_proof_batch(
        &commitment[..],
        &row_ids,
        &vec![sidecar.index],
        &column[..],
        &kzg_proofs,
        &kzg_settings,
    )?)
}

pub fn verify_data_column_sidecar_inclusion_proof<P: Preset>(
    sidecar: DataColumnSidecar<P>,
) -> bool {
    let index_at_commitment_depth = index_at_commitment_depth::<P>(sidecar.index);

    // is_valid_blob_sidecar_inclusion_proof
    return is_valid_merkle_branch(
        sidecar.kzg_commitments.hash_tree_root(),
        sidecar.kzg_commitments_inclusion_proof,
        index_at_commitment_depth,
        sidecar.signed_block_header.message.body_root,
    );
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

    let columns_per_subnet = NUMBER_OF_COLUMNS / DATA_COLUMN_SIDECAR_SUBNET_COUNT;
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
    let mut extended_matrix: Vec<Cell> = Vec::new();

    let trusted_setup_file = Path::new("kzg_utils/trusted_setup.txt");

    let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

    for blob in blobs {
        let cells = *Cell::compute_cells(&blob, &kzg_settings)?;
        extended_matrix.extend(cells);
    }

    let mut array = [Cell::default(); (MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS) as usize];
    array.copy_from_slice(&extended_matrix[..]);

    Ok(array)
}

fn recover_matrix(
    cells_dict: &HashMap<(BlobIndex, CellID), Cell>,
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
        let cells: Vec<Cell> = cell_ids
            .iter()
            .map(|&cell_id| cells_dict[&(blob_index as u64, cell_id)])
            .collect();
        let full_polynomial = Cell::recover_polynomial(&cell_ids, &cells, &kzg_settings)?;
        extended_matrix.push(full_polynomial);
    }
    let mut array = [Cell::default(); (MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS) as usize];
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
        cells_and_proofs.push(Cell::compute_cells_and_proofs(&blob, &kzg_settings)?);
    }
    let blob_count = blobs.len();
    // let mut cells: Vec<Vec<Cell>> = Vec::new();
    // let mut proofs: Vec<Vec<KzgProof>> = Vec::new();
    // for i in 0..blob_count {
    //     cells.push(cells_and_proofs[i].0.clone());
    //     proofs.push(cells_and_proofs[i].1.clone());
    // }
    let mut sidecars: Vec<DataColumnSidecar<P>> = Vec::new();
    for column_index in 0..NUMBER_OF_COLUMNS {
        let mut column_cells: Vec<Cell> = Vec::new();
        for row_index in 0..blob_count {
            column_cells.push(cells_and_proofs[row_index].0[column_index as usize].clone());
        }
        let kzg_proof_of_column: Vec<_> = (0..blob_count)
            .map(|row_index| cells_and_proofs[row_index].1[column_index as usize].clone())
            .collect();

        let cells = column_cells.iter().map(|cell| cell.to_bytes());
        let mut cont_cells = Vec::new();
        for cell in cells {
            cont_cells.push(ContiguousList::try_from(cell)?);
        }
        // let mut column_cell_array = [[0; 2048]; MAX_BLOB_COMMITMENTS_PER_BLOCK];
        // column_cell_array.copy_from_slice(&column_cells[..]);

        let mut kzg_proofs_array: [[u8; 48]; MAX_BLOB_COMMITMENTS_PER_BLOCK] =
            [[0; 48]; MAX_BLOB_COMMITMENTS_PER_BLOCK];
        kzg_proofs_array.copy_from_slice(&kzg_proof_of_column[..]);

        let mut continuous_proof_vec = Vec::new();
        for proof in kzg_proofs_array {
            continuous_proof_vec.push(ContiguousList::try_from(proof)?);
        }

        sidecars.push(DataColumnSidecar {
            index: column_index,
            column: ContiguousList::try_from(cont_cells)?,
            kzg_commitments: signed_block.message.body.blob_kzg_commitments.clone(),
            kzg_proofs: ContiguousList::try_from(continuous_proof_vec)?,
            signed_block_header,
            kzg_commitments_inclusion_proof: misc::kzg_commitment_inclusion_proof(
                &signed_block.message.body,
                column_index,
            )?,
        });
    }
    Ok(sidecars)
}

#[cfg(test)]
mod tests {
    use duplicate::duplicate_item;
    use serde::Deserialize;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::{
        phase0::primitives::NodeId,
        preset::{Mainnet, Minimal, Preset},
    };

    use crate::{get_custody_columns, ColumnIndex};

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
}
