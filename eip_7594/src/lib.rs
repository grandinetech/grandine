use anyhow::Result;
use c_kzg::{Blob, Bytes32, Bytes48, Cell, KzgCommitment, KzgProof, KzgSettings};
use helper_functions::misc;
use helper_functions::predicates::index_at_commitment_depth;
use helper_functions::predicates::is_valid_merkle_branch;
use sha3::digest::consts::U0;
use sha3::{Digest, Sha3_256};
use ssz::ContiguousList;
use ssz::Ssz;
use ssz::{ContiguousVector, MerkleTree, SszHash, H256};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::path::Path;
use typenum::{U2048, U48, U6};
use types::preset::Preset;
use types::{
    deneb::containers::SignedBeaconBlock,
    phase0::containers::{BeaconBlockHeader, SignedBeaconBlockHeader},
};

use std::fmt;

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
type MaxBlobCommitmentsPerBlock = U6;

type PolynomialCoeff = [Bytes32; FIELD_ELEMENTS_PER_EXT_BLOB];
type CellID = u64;
type RowIndex = u64;
type ColumnIndex = u64;
type NodeId = u64;
type BlobIndex = usize;
type ExtendedMatrix = [Cell; (MAX_BLOBS_PER_BLOCK * NUMBER_OF_COLUMNS) as usize];
type DataColumn = ContiguousList<ContiguousList<u8, U48>, U6>;
pub type DataColumnSubnetId = usize; // idejau tam, kad kompiliuotusi, nezinau ar reikia.

pub struct DataColumnIdentifier {
    block_root: H256,
    index: ColumnIndex,
}

// #[derive(PartialEq)]
#[derive(Ssz, PartialEq, Clone)]
pub struct DataColumnSidecar<P: Preset> {
    pub index: ColumnIndex,
    pub column: DataColumn,
    pub kzg_commitments: ContiguousList<primitive_types::H384, P::MaxBlobCommitmentsPerBlock>,
    pub kzg_proofs: ContiguousList<ContiguousList<u8, U48>, MaxBlobCommitmentsPerBlock>,
    pub signed_block_header: SignedBeaconBlockHeader,
    pub kzg_commitments_inclusion_proof:
        ContiguousVector<H256, P::KzgCommitmentInclusionProofDepth>,
}

impl<P: Preset> DataColumnSidecar<P> {
    pub fn slot(&self) -> u64 {
        self.signed_block_header.message.slot
    }
}

impl<P: Preset> fmt::Debug for DataColumnSidecar<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataColumnSidecar")
            .field("index", &self.index)
            .finish()
    }
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
        let subnet_id = bytes_as_u64 % DATA_COLUMN_SIDECAR_SUBNET_COUNT;
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
            if b_index == blob_index {
                cell_ids.push(cell_id);
            }
        }
        let cells: Vec<Cell> = cell_ids
            .iter()
            .map(|&cell_id| cells_dict[&(blob_index, cell_id)])
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
