use c_kzg::{Cell, Bytes32};
use sha3::{Digest, Sha3_256};

const DATA_COLUMN_SIDECAR_SUBNET_COUNT: usize = 32;
const SAMPLES_PER_SLOT: u64 = 8;
const CUSTODY_REQUIREMENT: u64 = 1;
const TARGET_NUMBER_OF_PEERS: u64 = 70;
const FIELD_ELEMENTS_PER_BLOB: usize = 4; // todo!();
const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 2 * FIELD_ELEMENTS_PER_BLOB;
const FIELD_ELEMENTS_PER_CELL: usize = 64;
const BYTES_PER_FIELD_ELEMENT: usize = 4; // todo!();
const BYTES_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT;
const CELLS_PER_BLOB: usize = FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL;
const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u64 = 4;
const NUMBER_OF_COLUMNS:usize = 4; // todo!();

type PolynomialCoeff = [Bytes32; FIELD_ELEMENTS_PER_EXT_BLOB];
type CellID = u64;
type RowIndex = u64;
type ColumnIndex = usize;
pub type NodeId = u64;

use std::collections::HashSet;

fn get_custody_columns(node_id: NodeId, custody_subnet_count: usize) -> Vec<ColumnIndex> {
    assert!(custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT);

    let mut subnet_ids = HashSet::new();
    let mut i: u64 = 0; // atrodo per mazas
    while subnet_ids.len() < custody_subnet_count.try_into().unwrap()  {
        // I haven't tested at all, therefor this part likely contains some errors
        let mut hasher = Sha3_256::new();
        let bytes: [u8; 8] = (node_id + i).to_le_bytes();
        hasher.update(bytes); 
        let mut output = hasher.finalize();
        let last_8_bytes: &[u8] = &output[output.len() - 8..];
        let bytes_as_u64 = u64::from_be_bytes([
            last_8_bytes[0], last_8_bytes[1], last_8_bytes[2], last_8_bytes[3],
            last_8_bytes[4], last_8_bytes[5], last_8_bytes[6], last_8_bytes[7]
        ]);
        if let Ok(bytes_as_usize) = usize::try_from(bytes_as_u64) {
            let subnet_id = bytes_as_usize
                % DATA_COLUMN_SIDECAR_SUBNET_COUNT;
            if !subnet_ids.contains(&subnet_id) {
                subnet_ids.insert(subnet_id);
            }

        } else {
            assert!(false);
        }
        i += 1;
    }
    assert_eq!(subnet_ids.len(), custody_subnet_count);

    let columns_per_subnet = NUMBER_OF_COLUMNS / DATA_COLUMN_SIDECAR_SUBNET_COUNT;
    let mut result = Vec::new();
    for i in 0..columns_per_subnet {
        for &subnet_id in &subnet_ids {
            result.push(
                DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnet_id,
            );
        }
    }
    result
}
