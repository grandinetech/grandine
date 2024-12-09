#![expect(clippy::manual_let_else)]

use kzg::{eip_4844::bytes_to_blob, Fr as _, G1 as _};
use spec_test_utils::Case;
use test_generator::test_resources;
use types::preset::Mainnet;

use crate::{
    eip_4844::{
        blob_to_kzg_commitment, compute_blob_kzg_proof, compute_kzg_proof, verify_blob_kzg_proof,
        verify_blob_kzg_proof_batch, verify_kzg_proof,
    },
    spec_tests::{containers, utils::deserialize, Fr, G1},
};

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/blob_to_kzg_commitment/*/*")]
fn test_blob_to_kzg_commitment(case: Case) {
    let test: containers::blob_to_kzg_commitment::Test = case.yaml("data");

    let blob = match deserialize(&test.input.blob) {
        Ok(blob) => blob,
        Err(_) => {
            assert!(test.output.is_none());
            return;
        }
    };

    if test.output.is_none() {
        return;
    }

    let output = test.output.as_ref().expect("test output should exist");
    let expected_commitment = deserialize(output).expect("should decode commitment bytes");

    let commitment =
        blob_to_kzg_commitment::<Mainnet>(&blob).expect("should compute blob to kzg commitment");

    assert_eq!(commitment, expected_commitment);
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/compute_blob_kzg_proof/*/*")]
fn test_compute_blob_kzg_proof(case: Case) {
    let test: containers::compute_blob_kzg_proof::Test = case.yaml("data");

    let blob = match deserialize(&test.input.blob) {
        Ok(blob) => blob,
        Err(_) => {
            assert!(test.output.is_none());
            return;
        }
    };

    if G1::from_bytes(&test.input.get_commitment_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    let commitment =
        deserialize(&test.input.commitment).expect("should deserialize test input to commitment");

    match compute_blob_kzg_proof::<Mainnet>(&blob, commitment) {
        Ok(proof) => {
            let output = test.output.as_ref().expect("test output should exist");
            let expected_proof =
                deserialize(output).expect("should deserialize test output to proof");

            assert_eq!(proof, expected_proof);
        }
        Err(_) => {
            assert!(test.output.is_none());
        }
    }
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/compute_kzg_proof/*/*")]
fn test_compute_kzg_proof(case: Case) {
    let test: containers::compute_kzg_proof::Test = case.yaml("data");

    if bytes_to_blob::<Fr>(&test.input.get_blob_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    let blob = deserialize(&test.input.blob).expect("should deserialize test input to blob");

    if Fr::from_bytes(&test.input.get_z_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    let (expected_proof, expected_y) = test.get_output();

    let (proof, y) = compute_kzg_proof::<Mainnet>(&blob, test.input.get_z_bytes_fixed())
        .expect("should compute kzg proof");

    assert_eq!(proof, expected_proof);
    assert_eq!(y, expected_y);
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/verify_blob_kzg_proof/*/*")]
fn test_verify_blob_kzg_proof(case: Case) {
    let test: containers::verify_blob_kzg_proof::Test = case.yaml("data");

    let blob = match deserialize(&test.input.blob) {
        Ok(blob) => blob,
        Err(_) => {
            assert!(test.output.is_none());
            return;
        }
    };

    if G1::from_bytes(&test.input.get_commitment_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    if G1::from_bytes(&test.input.get_proof_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    let commitment =
        deserialize(&test.input.commitment).expect("should deserialize test input to commitment");
    let proof = deserialize(&test.input.proof).expect("should deserialize test input to proof");

    match verify_blob_kzg_proof::<Mainnet>(&blob, commitment, proof) {
        Ok(output) => {
            let expected_output = test.output.expect("test output should exist");
            assert_eq!(output, expected_output);
        }
        Err(_) => {
            assert!(test.output.is_none());
        }
    }
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/verify_blob_kzg_proof_batch/*/*")]
fn test_verify_blob_kzg_proof_batch(case: Case) {
    let test: containers::verify_blob_kzg_proof_batch::Test = case.yaml("data");

    let mut blobs = vec![];

    for blob in &test.input.blobs {
        let blob = match deserialize(blob) {
            Ok(blob) => blob,
            Err(_) => {
                assert!(test.output.is_none());
                return;
            }
        };
        blobs.push(blob);
    }

    for commitment_bytes in test.input.get_commitments_bytes() {
        if G1::from_bytes(&commitment_bytes).is_err() {
            assert!(test.output.is_none());
            return;
        }
    }

    for proof_bytes in test.input.get_proofs_bytes() {
        if G1::from_bytes(&proof_bytes).is_err() {
            assert!(test.output.is_none());
            return;
        }
    }

    let commitments = test
        .input
        .commitments
        .iter()
        .map(|c| deserialize(c).expect("should deserialize test input to commitment"))
        .collect::<Vec<_>>();

    let proofs = test
        .input
        .proofs
        .iter()
        .map(|c| deserialize(c).expect("should deserialize test input to proof"))
        .collect::<Vec<_>>();

    match verify_blob_kzg_proof_batch::<Mainnet>(blobs.iter(), commitments, proofs) {
        Ok(output) => {
            let expected_output = test.output.expect("test output should exist");
            assert_eq!(output, expected_output);
        }
        Err(_) => {
            assert!(test.output.is_none());
        }
    }
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/verify_kzg_proof/*/*")]
fn test_verify_kzg_proof(case: Case) {
    let test: containers::verify_kzg_proof::Test = case.yaml("data");

    if G1::from_bytes(&test.input.get_commitment_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    if Fr::from_bytes(&test.input.get_z_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    if Fr::from_bytes(&test.input.get_y_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    if G1::from_bytes(&test.input.get_proof_bytes()).is_err() {
        assert!(test.output.is_none());
        return;
    }

    let commitment =
        deserialize(&test.input.commitment).expect("should deserialize test input to commitment");
    let z = test.input.get_z_bytes_fixed();
    let y = test.input.get_y_bytes_fixed();
    let proof = deserialize(&test.input.proof).expect("should deserialize test input to proof");

    match verify_kzg_proof(commitment, z, y, proof) {
        Ok(output) => {
            let expected_output = test.output.expect("test output should exist");
            assert_eq!(output, expected_output);
        }
        Err(_) => {
            assert!(test.output.is_none());
        }
    }
}
