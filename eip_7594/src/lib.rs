use anyhow::Result;
use c_kzg::{Blob, Bytes32, Cell, KzgSettings, KzgProof, KzgCommitment};
use sha3::digest::consts::U0;
use sha3::{Digest, Sha3_256};
use ssz::{MerkleTree, SszHash, H256};
use types::preset::Preset;
use std::collections::{HashSet, HashMap};
use std::path::Path;
use std::cmp;
use std::convert::TryInto;
use types::{phase0::containers::{BeaconBlockHeader, SignedBeaconBlockHeader}, deneb::containers::{SignedBeaconBlock}};


const DATA_COLUMN_SIDECAR_SUBNET_COUNT: usize = 32;
const SAMPLES_PER_SLOT: u64 = 8;
const CUSTODY_REQUIREMENT: u64 = 1;
const TARGET_NUMBER_OF_PEERS: u64 = 70;
const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 2 * FIELD_ELEMENTS_PER_BLOB;
const FIELD_ELEMENTS_PER_CELL: usize = 64;
const BYTES_PER_FIELD_ELEMENT: usize = 32;
const BYTES_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT;
const CELLS_PER_BLOB: usize = FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL;
const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: usize = 4;
const NUMBER_OF_COLUMNS: usize = 4; // todo!();
const MAX_BLOBS_PER_BLOCK: usize = 6; //todo!();
const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 6; // todo!();

type PolynomialCoeff = [Bytes32; FIELD_ELEMENTS_PER_EXT_BLOB];
type CellID = u64;
type RowIndex = u64;
type ColumnIndex = usize;
type NodeId = u64;
type BlobIndex = usize;
type ExtendedMatrix = [Cell; MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS];
type DataColumn = [Cell; MAX_BLOB_COMMITMENTS_PER_BLOCK];

struct DataColumnIdentifier {
    block_root: H256,
    index: ColumnIndex,
}

struct DataColumnSidecar {
    index: ColumnIndex,
    column: DataColumn,
    kzg_commitments: Vec<primitive_types::H384>,
    kzg_proofs: [[u8; 48]; MAX_BLOB_COMMITMENTS_PER_BLOCK],
    signed_block_header: SignedBeaconBlockHeader,
    kzg_commitments_inclusion_proof: H256,
}

pub fn get_custody_columns(node_id: NodeId, custody_subnet_count: usize) -> Vec<ColumnIndex> {
    assert!(custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT);

    let mut subnet_ids = HashSet::new();
    let mut i: u64 = 0; // atrodo per mazas
    while subnet_ids.len() < custody_subnet_count.try_into().unwrap() {
        // I haven't tested at all, therefor this part likely contains some errors
        let mut hasher = Sha3_256::new();
        let bytes: [u8; 8] = (node_id + i).to_le_bytes();
        hasher.update(bytes);
        let mut output = hasher.finalize();
        let last_8_bytes: &[u8] = &output[output.len() - 8..];
        let bytes_as_u64 = u64::from_be_bytes([
            last_8_bytes[0],
            last_8_bytes[1],
            last_8_bytes[2],
            last_8_bytes[3],
            last_8_bytes[4],
            last_8_bytes[5],
            last_8_bytes[6],
            last_8_bytes[7],
        ]);
        if let Ok(bytes_as_usize) = usize::try_from(bytes_as_u64) {
            let subnet_id = bytes_as_usize % DATA_COLUMN_SIDECAR_SUBNET_COUNT;
            if !subnet_ids.contains(&subnet_id) {
                subnet_ids.insert(subnet_id);
            }
        } else {
            assert!(false);
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
            result.push(DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnet_id);
        }
    }

    result.sort_unstable();
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

    let mut array = [Cell::default(); MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS];
    array.copy_from_slice(&extended_matrix[..]);

    Ok(array)
}

fn recover_matrix(cells_dict: &HashMap<(BlobIndex, CellID), Cell>, blob_count: usize) -> Result<ExtendedMatrix> {
    let trusted_setup_file = Path::new("kzg_utils/trusted_setup.txt");
    let kzg_settings = KzgSettings::load_trusted_setup_file(trusted_setup_file).unwrap();

    let mut extended_matrix = Vec::new();
    for blob_index in 0..blob_count {
        let mut cell_ids = Vec::new();
        for &(b_index, cell_id) in cells_dict.keys() {
            if b_index == blob_index {
                cell_ids.push(cell_id);
            }
        }
        let cells: Vec<Cell> = cell_ids.iter().map(|&cell_id| cells_dict[&(blob_index, cell_id)]).collect();
        let full_polynomial = Cell::recover_polynomial(&cell_ids, &cells, &kzg_settings)?;
        extended_matrix.push(full_polynomial);
    }
    let mut array = [Cell::default(); MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS];
    array.copy_from_slice(&extended_matrix[..]);

    Ok(array)
}

fn get_data_column_sidecars<P: Preset>(
    signed_block: SignedBeaconBlock<P>,
    blobs: Vec<Blob>,
) -> Result<Vec<DataColumnSidecar>> {
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
        signature: signed_block.signature
    };
    // &signed_block.to_header();
    let block  = signed_block.message;
    let kzg_commitments_inclusion_proof = block.body.blob_kzg_commitments.clone();
    let mut bytes_u8: Vec<u8> = Vec::new();
    for com in kzg_commitments_inclusion_proof.into_iter()
    {
        for bt in com.as_bytes().into_iter()
        {
            bytes_u8.push(bt.clone());
        }
    }
    // let bytes = kzg_commitments_inclusion_proof.into_iter().map(|a| a.as_bytes().into_iter().collect::<Vec<_>>()).flatten().collect::<Vec<_>>();
    let kzg_commitments_inclusion_proof = MerkleTree::<U0>::merkleize_bytes(<Vec<u8> as AsRef<[u8]>>::as_ref(&bytes_u8));
    
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
    let mut sidecars: Vec<DataColumnSidecar> = Vec::new();
    for column_index in 0..NUMBER_OF_COLUMNS {
        let mut column_cells: Vec<Cell> = Vec::new();
        for row_index in 0..blob_count {
            column_cells.push(cells_and_proofs[row_index].0[column_index].clone());
        }
        let kzg_proof_of_column: Vec<_> = (0..blob_count)
            .map(|row_index| cells_and_proofs[row_index].1[column_index].clone())
            .collect();

        let mut column_cell_array = [Cell::default(); MAX_BLOB_COMMITMENTS_PER_BLOCK];
        column_cell_array.copy_from_slice(&column_cells[..]);

        let mut kzg_proofs_array: [[u8; 48]; MAX_BLOB_COMMITMENTS_PER_BLOCK] = [[0; 48]; MAX_BLOB_COMMITMENTS_PER_BLOCK];
        kzg_proofs_array.copy_from_slice(&kzg_proof_of_column[..]);



        sidecars.push(DataColumnSidecar {
            index: column_index,
            column: column_cell_array,
            kzg_commitments: block.body.blob_kzg_commitments.clone().into_iter().collect::<Vec<_>>(),
            kzg_proofs: kzg_proofs_array,
            signed_block_header: signed_block_header,
            kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
        });
    }
    Ok(sidecars)
}