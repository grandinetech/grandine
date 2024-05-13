use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use anyhow::{anyhow, Result};
use c_kzg::{
    Blob as CKzgBlob, Bytes32, Bytes48, Cell as CKzgCell, KzgProof as CKzgProof, KzgSettings,
};
use hashing::{hash_64, ZERO_HASHES};
use helper_functions::{
    accessors,
    error::SignatureKind,
    misc,
    predicates::{index_at_commitment_depth, is_valid_merkle_branch},
    signing::SignForSingleFork,
};
use kzg::eip_4844::{load_trusted_setup_string, BYTES_PER_G1, BYTES_PER_G2};
use sha3::{Digest, Sha3_256};
use ssz::{
    ByteVector, ContiguousList, ContiguousVector, MerkleElements, MerkleTree, SszHash, SszWrite,
    H256,
};
use try_from_iterator::TryFromIterator as _;
use typenum::{Unsigned as _, U2048};
use types::{
    combined::SignedBeaconBlock,
    config::Config,
    deneb::{
        consts::DOMAIN_BLOB_SIDECAR,
        primitives::{Blob, BlobIndex, KzgCommitment, KzgProof},
    },
    eip7594::{BlobCommitmentsInclusionProof, ColumnIndex, DataColumnSidecar, NumberOfColumns},
    phase0::{
        containers::{BeaconBlockHeader, SignedBeaconBlockHeader},
        primitives::{DomainType, Epoch, NodeId, SubnetId},
    },
    traits::{BeaconBlock as _, BeaconState, PostDenebBeaconBlockBody, SignedBeaconBlock as _},
};
use types::{
    eip7594::{Cell, DATA_COLUMN_SIDECAR_SUBNET_COUNT},
    preset::Preset,
};

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

    let kzg_settings = load_kzg_settings()?;

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

pub fn verify_data_column_sidecar_kzg_proofs<P: Preset>(
    sidecar: DataColumnSidecar<P>,
) -> Result<bool> {
    assert!(sidecar.index < NumberOfColumns::U64);
    assert!(
        sidecar.column.len() == sidecar.kzg_commitments.len()
            && sidecar.column.len() == sidecar.kzg_proofs.len()
    );
    let mut row_ids = Vec::new();
    for i in 0..sidecar.column.len() {
        row_ids.push(i as u64);
    }

    let kzg_settings = load_kzg_settings()?;

    let column = sidecar
        .column
        .into_iter()
        .map(|a| CKzgCell::from_bytes(&a.as_bytes()).unwrap())
        .collect::<Vec<_>>();
    let commitment = sidecar
        .kzg_commitments
        .iter()
        .map(|a| Bytes48::from_bytes(a.as_bytes()).unwrap())
        .collect::<Vec<_>>();
    let kzg_proofs = sidecar
        .kzg_proofs
        .iter()
        .map(|a| Bytes48::from_bytes(&a.as_bytes()).unwrap())
        .collect::<Vec<_>>();

    Ok(CKzgProof::verify_cell_proof_batch(
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

    let kzg_settings = load_kzg_settings()?;

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
    let kzg_settings = load_kzg_settings()?;

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

        let kzg_settings = load_kzg_settings()?;

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
                kzg_commitments: post_deneb_beacon_block_body.blob_kzg_commitments().clone(),
                kzg_proofs: ContiguousList::try_from(continuous_proof_vec)?,
                signed_block_header,
                kzg_commitments_inclusion_proof,
            });
        }
    }

    Ok(vec![])
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

fn load_kzg_settings() -> Result<KzgSettings> {
    let contents = include_str!("../../kzg_utils/src/trusted_setup.txt");
    let (g1_bytes, g2_bytes) =
        load_trusted_setup_string(contents).map_err(|error| anyhow!(error))?;

    KzgSettings::load_trusted_setup(
        &g1_bytes
            .chunks_exact(BYTES_PER_G1)
            .map(|chunk| TryInto::<[u8; BYTES_PER_G1]>::try_into(chunk).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
        &g2_bytes
            .chunks_exact(BYTES_PER_G2)
            .map(|chunk| TryInto::<[u8; BYTES_PER_G2]>::try_into(chunk).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
    )
    .map_err(|error| anyhow!(error))
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
