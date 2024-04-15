use anyhow::Result;
use c_kzg::{Blob, Bytes32, Cell, KzgSettings};
use sha3::{Digest, Sha3_256};
use ssz::H256;
use std::collections::{HashSet, HashMap};
use std::path::Path;
use std::cmp;
use std::convert::TryInto;

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
const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64 = 4;
const NUMBER_OF_COLUMNS: usize = 4; // todo!();
const MAX_BLOBS_PER_BLOCK: usize = 6; //todo!();
const MAX_BLOB_COMMITMENTS_PER_BLOCK = 6; // todo!();

type PolynomialCoeff = [Bytes32; FIELD_ELEMENTS_PER_EXT_BLOB];
type CellID = u64;
type RowIndex = u64;
type ColumnIndex = usize;
type NodeId = u64;
type BlobIndex = usize;
type ExtendedMatrix = [Cell; MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS];

struct DataColumnIdentifier {
    block_root: H256,
    index: ColumnIndex,
}

struct DataColumnSidecar {
    index: ColumnIndex,                                 // Index of column in extended matrix
    column: DataColumn,                                 // Instance of DataColumn
    kzg_commitments: Vec<KZGCommitment>,               // List of KZGCommitment with MAX_BLOB_COMMITMENTS_PER_BLOCK length
    kzg_proofs: [KZGProof; MAX_BLOB_COMMITMENTS_PER_BLOCK],
    signed_block_header: SignedBeaconBlockHeader,       // Instance of SignedBeaconBlockHeader
    kzg_commitments_inclusion_proof: [Bytes32; KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH],
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

fn construct_vanishing_polynomial(
    missing_cell_ids: Vec<CellID>,
) -> (
    Vec<Bytes32>,
    Vec<Bytes32>,
    Vec<Bytes32>,
) {
    todo!();
    // let roots_of_unity_reduced = compute_roots_of_unity(CELLS_PER_BLOB);

    // Compute polynomial that vanishes at all the missing cells (over the small domain)
    // let short_zero_poly = vanishing_polynomial_coeff(
    //     missing_cell_ids
    //         .iter()
    //         .map(|&missing_cell_id| {
    //             roots_of_unity_reduced[reverse_bits(missing_cell_id, CELLS_PER_BLOB)]
    //         })
    //         .collect(),
    // );

    // // Extend vanishing polynomial to full domain using the closed form of the vanishing polynomial over a coset
    // let mut zero_poly_coeff = vec![BLSFieldElement::zero(); FIELD_ELEMENTS_PER_EXT_BLOB];
    // for (i, &coeff) in short_zero_poly.iter().enumerate() {
    //     zero_poly_coeff[i * FIELD_ELEMENTS_PER_CELL] = coeff;
    // }

    // // Compute evaluations of the extended vanishing polynomial
    // let zero_poly_eval = fft_field(
    //     &zero_poly_coeff,
    //     &compute_roots_of_unity(FIELD_ELEMENTS_PER_EXT_BLOB),
    // );
    // let zero_poly_eval_brp = bit_reversal_permutation(&zero_poly_eval);

    // // Sanity check
    // for cell_id in 0..CELLS_PER_BLOB {
    //     let start = cell_id * FIELD_ELEMENTS_PER_CELL;
    //     let end = (cell_id + 1) * FIELD_ELEMENTS_PER_CELL;
    //     if missing_cell_ids.contains(&cell_id) {
    //         assert!(zero_poly_eval_brp[start..end].iter().all(|&a| a == BLSFieldElement::zero()));
    //     } else {
    //         assert!(zero_poly_eval_brp[start..end].iter().all(|&a| a != BLSFieldElement::zero()));
    //     }
    // }

    // (
    //     zero_poly_coeff,
    //     zero_poly_eval,
    //     zero_poly_eval_brp,
    // )
}


fn recover_matrix(cells_dict: &HashMap<(BlobIndex, CellID), Cell>, blob_count: usize) -> ExtendedMatrix {
    let mut extended_matrix = Vec::new();
    for blob_index in 0..blob_count {
        let mut cell_ids = Vec::new();
        for &(b_index, cell_id) in cells_dict.keys() {
            if b_index == blob_index {
                cell_ids.push(cell_id);
            }
        }
        let cells: Vec<Cell> = cell_ids.iter().map(|&cell_id| cells_dict[&(blob_index, cell_id)]).collect();
        todo!();
        // let cells_bytes: Vec<Vec<[u8; BLS_FIELD_SIZE]>> = cells.iter().map(|cell| cell.to_bytes()).collect();
        
        // let full_polynomial = recover_polynomial(&cell_ids, &cells_bytes);
        // let mut cells_from_full_polynomial = Vec::new();
        // for i in 0..CELLS_PER_BLOB {
        //     cells_from_full_polynomial.push(full_polynomial[i * FIELD_ELEMENTS_PER_CELL..(i + 1) * FIELD_ELEMENTS_PER_CELL].to_vec());
        // }
        // extended_matrix.extend(cells_from_full_polynomial);
    }
    let mut array = [Cell::default(); MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS];
    array.copy_from_slice(&extended_matrix[..]);

    array
}