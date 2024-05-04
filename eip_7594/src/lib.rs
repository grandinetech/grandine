use anyhow::Result;
use c_kzg::{Blob, Bytes32, Bytes48, Cell, KzgCommitment, KzgProof, KzgSettings};
use helper_functions::accessors;
use helper_functions::error::SignatureKind;
use helper_functions::misc;
use helper_functions::predicates::index_at_commitment_depth;
use helper_functions::predicates::is_valid_merkle_branch;
use helper_functions::signing::SignForSingleFork;
use sha3::digest::consts::U0;
use sha3::{Digest, Sha3_256};
use ssz::ContiguousList;
use ssz::Ssz;
use ssz::{ContiguousVector, MerkleTree, SszHash, H256};
use std::cmp;
use ssz::SszWrite;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::path::Path;
use typenum::{U2048, U48, U6};
use types::config::Config;
use types::deneb::consts::DOMAIN_BLOB_SIDECAR;
use types::phase0::primitives::DomainType;
use hashing::hash_64;
use types::phase0::primitives::Epoch;
use types::preset::Preset;
use types::{
    deneb::containers::SignedBeaconBlock,
    deneb::primitives::BlobIndex, // galimai is cia reikia ir ktius (KzgCommitment, KzgProof ir pan.)
    phase0::containers::{BeaconBlockHeader, SignedBeaconBlockHeader},
    phase0::primitives::NodeId,
    traits::BeaconState,
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
pub type ColumnIndex = u64;
// type BlobIndex = usize;
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

// labai gali buti, kad neteisingas
impl<P: Preset> SignForSingleFork<P> for DataColumnSidecar<P> {
    const DOMAIN_TYPE: DomainType = DOMAIN_BLOB_SIDECAR;
    const SIGNATURE_KIND: SignatureKind = SignatureKind::BlobSidecar;

    fn epoch(&self) -> Epoch {
        misc::compute_epoch_at_slot::<P>(self.signed_block_header.message.slot)
    }

    fn signing_root(&self, config: &Config, beacon_state: &(impl BeaconState<P> + ?Sized)) -> H256 {
        let domain = accessors::get_domain(config, beacon_state, Self::DOMAIN_TYPE, None);
        misc::compute_signing_root(self, domain)
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
    use crate::{get_custody_columns, ColumnIndex};
    use ssz::*;
    use types::phase0::primitives::NodeId;
    // use ethereum_types::{U256 as RawUint256};

    // use num_traits::ops::bytes::ToBytes;
    use std::str::FromStr;
    // use std::str::FromStr;

    #[test]
    // https://github.com/ethereum/consensus-spec-tests/tree/master/tests/mainnet/eip7594/networking/get_custody_columns/pyspec_tests/get_custody_columns__min_node_id_min_custody_subnet_count
    fn test_min_min() {
        let expected:Vec<ColumnIndex> = Vec::new();
        assert_eq!(get_custody_columns(NodeId::from_u64(0), 0), expected);
    }

    #[test]
    // https://github.com/ethereum/consensus-spec-tests/tree/master/tests/mainnet/eip7594/networking/get_custody_columns/pyspec_tests/get_custody_columns__min_node_id_max_custody_subnet_count
    fn test_min_max()
    {
        let expected:Vec<ColumnIndex> = (0..=127).collect();
        let node_id = NodeId::from_u64(0);
        let custody_subnet_count = 32;
        assert_eq!(get_custody_columns(node_id, custody_subnet_count), expected);
    }

    #[test]
    // https://github.com/ethereum/consensus-spec-tests/blob/master/tests/mainnet/eip7594/networking/get_custody_columns/pyspec_tests/get_custody_columns__max_node_id_max_custody_subnet_count/meta.yaml
    fn test_max_min()
    {
        let expected:Vec<ColumnIndex> = vec![];
        let str_node_id = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let node_id = Uint256::from_str(str_node_id).unwrap();
        let custody_subnet_count = 0;
        assert_eq!(get_custody_columns(node_id, custody_subnet_count), expected);
    }

    #[test]
    // https://github.com/ethereum/consensus-spec-tests/tree/master/tests/mainnet/eip7594/networking/get_custody_columns/pyspec_tests/get_custody_columns__max_node_id_min_custody_subnet_count
    fn test_max_max()
    {
        let expected:Vec<ColumnIndex> = vec![];
        let str_node_id = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let node_id = Uint256::from_str(str_node_id).unwrap();
        let custody_subnet_count = 32;
        assert_eq!(get_custody_columns(node_id, custody_subnet_count), expected);
    }

    #[test]
    // https://github.com/ethereum/consensus-spec-tests/tree/master/tests/mainnet/eip7594/networking/get_custody_columns/pyspec_tests/get_custody_columns__1
    fn test_case_1() {
        let expected:Vec<ColumnIndex> = (0..=127).collect();
        let str_node_id = "51781405571328938149219259614021022118347017557305093857689627172914154745642";
        let node_id = Uint256::from_str(str_node_id).unwrap();
        let custody_subnet_count = 32;
        assert_eq!(get_custody_columns(node_id, custody_subnet_count), expected);
    }

    #[test]
    // https://github.com/ethereum/consensus-spec-tests/blob/master/tests/mainnet/eip7594/networking/get_custody_columns/pyspec_tests/get_custody_columns__2
    fn test_case_2() {
        let expected:Vec<ColumnIndex> = vec![27, 59, 91, 123];
        let str_node_id = "84065159290331321853352677657753050104170032838956724170714636178275273565505";
        let node_id = Uint256::from_str(str_node_id).unwrap();
        let custody_subnet_count = 1;
        assert_eq!(get_custody_columns(node_id, custody_subnet_count), expected);
    }

    #[test]
    // https://github.com/ethereum/consensus-spec-tests/blob/master/tests/mainnet/eip7594/networking/get_custody_columns/pyspec_tests/get_custody_columns__3/meta.yaml
    fn test_case_3() {
        let expected:Vec<ColumnIndex> = vec![1, 2, 4, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 18, 21, 22, 24, 25, 26, 27, 28, 29, 31, 33, 34, 36, 38, 39, 40, 41, 42, 44, 45, 46, 47, 48, 50, 53, 54, 56, 57, 58, 59, 60, 61, 63, 65, 66, 68, 70, 71, 72, 73, 74, 76, 77, 78, 79, 80, 82, 85, 86, 88, 89, 90, 91, 92, 93, 95, 97, 98, 100, 102, 103, 104, 105, 106, 108, 109, 110, 111, 112, 114, 117, 118, 120, 121, 122, 123, 124, 125, 127];
        let str_node_id = "62524992026686681062927724650084164361416283301810167550777687366062873585350";
        let node_id = Uint256::from_str(str_node_id).unwrap();
        let custody_subnet_count = 23;
        assert_eq!(get_custody_columns(node_id, custody_subnet_count), expected);
    }

}
