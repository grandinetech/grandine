#![expect(clippy::manual_let_else)]

use spec_test_utils::Case;
use test_generator::test_resources;
use types::preset::Mainnet;

use crate::{
    eip_4844::{
        blob_to_kzg_commitment, compute_blob_kzg_proof, compute_kzg_proof, verify_blob_kzg_proof,
        verify_blob_kzg_proof_batch, verify_kzg_proof,
    },
    spec_tests::{containers, utils::deserialize},
    KzgBackend,
};

fn available_backends() -> impl Iterator<Item = KzgBackend> {
    let backends = [
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks,
        #[cfg(feature = "blst")]
        KzgBackend::Blst,
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine,
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl,
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto,
    ];

    assert_ne!(
        backends.len(),
        0,
        "no backend selected - please provide at least one backend (arkworks, blst, constantine, mcl or zkcrypto)"
    );

    backends.into_iter()
}

macro_rules! unwrap_test_input {
    ($val:expr, $test:ident) => {
        match $val {
            Ok(v) => v,
            Err(_) => {
                assert!($test.output.is_none());
                return;
            }
        }
    };
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/blob_to_kzg_commitment/*/*")]
fn test_blob_to_kzg_commitment(case: Case) {
    let test: containers::blob_to_kzg_commitment::Test = case.yaml("data");

    let blob = unwrap_test_input!(deserialize(&test.input.blob), test);

    for backend in available_backends() {
        match blob_to_kzg_commitment::<Mainnet>(&blob, backend) {
            Ok(commitment) => {
                let output = test.output.as_ref().expect("test output should exist");
                let expected_commitment =
                    deserialize(output).expect("should decode commitment bytes");

                assert_eq!(
                    commitment, expected_commitment,
                    "commitments do not match, backend {backend}"
                )
            }
            Err(_) => assert!(
                test.output.is_none(),
                "test output should not exist (backend {backend})"
            ),
        }
    }
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/compute_blob_kzg_proof/*/*")]
fn test_compute_blob_kzg_proof(case: Case) {
    let test: containers::compute_blob_kzg_proof::Test = case.yaml("data");

    let blob = unwrap_test_input!(deserialize(&test.input.blob), test);
    let commitment = unwrap_test_input!(deserialize(&test.input.commitment), test);

    for backend in available_backends() {
        match compute_blob_kzg_proof::<Mainnet>(&blob, commitment, backend) {
            Ok(proof) => {
                let output = test
                    .output
                    .as_ref()
                    .unwrap_or_else(|| panic!("test output should exist (backend {backend})"));

                let expected_proof = deserialize(output).unwrap_or_else(|_| {
                    panic!("should deserialize test output to proof (backend {backend})")
                });

                assert_eq!(
                    proof, expected_proof,
                    "proofs do not match (backend {backend})"
                );
            }
            Err(_) => {
                assert!(
                    test.output.is_none(),
                    "test output should not exist (backend {backend})"
                );
            }
        }
    }
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/compute_kzg_proof/*/*")]
fn test_compute_kzg_proof(case: Case) {
    let test: containers::compute_kzg_proof::Test = case.yaml("data");

    let blob = unwrap_test_input!(deserialize(&test.input.blob), test);
    let z_bytes = unwrap_test_input!(test.input.get_z_bytes_fixed(), test);

    for backend in available_backends() {
        match compute_kzg_proof::<Mainnet>(&blob, z_bytes, backend) {
            Ok((proof, y)) => {
                let (expected_proof, expected_y) = test.get_output();

                assert_eq!(
                    proof, expected_proof,
                    "proofs do not match (backend {backend})"
                );
                assert_eq!(y, expected_y, "ys do not match (backend {backend}");
            }
            Err(_) => {
                assert!(
                    test.output.is_none(),
                    "should compute kzg proof (backend {backend})"
                )
            }
        }
    }
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

    let commitment = unwrap_test_input!(deserialize(&test.input.commitment), test);
    let proof = unwrap_test_input!(deserialize(&test.input.proof), test);

    for backend in available_backends() {
        match verify_blob_kzg_proof::<Mainnet>(&blob, commitment, proof, backend) {
            Ok(output) => {
                let expected_output = test
                    .output
                    .unwrap_or_else(|| panic!("test output should exist (backend {backend})"));

                assert_eq!(
                    output, expected_output,
                    "outputs do not match (backend {backend})"
                );
            }
            Err(_) => {
                assert!(
                    test.output.is_none(),
                    "test output should not exist (backend {backend})"
                );
            }
        }
    }
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/verify_blob_kzg_proof_batch/*/*")]
fn test_verify_blob_kzg_proof_batch(case: Case) {
    let test: containers::verify_blob_kzg_proof_batch::Test = case.yaml("data");

    let mut blobs = vec![];

    for blob in &test.input.blobs {
        let blob = unwrap_test_input!(deserialize(blob), test);
        blobs.push(blob);
    }

    let commitments = unwrap_test_input!(
        test.input
            .commitments
            .iter()
            .map(|c| deserialize(c))
            .collect::<Result<Vec<_>, _>>(),
        test
    );

    let proofs = unwrap_test_input!(
        test.input
            .proofs
            .iter()
            .map(|c| deserialize(c))
            .collect::<Result<Vec<_>, _>>(),
        test
    );

    for backend in available_backends() {
        match verify_blob_kzg_proof_batch::<Mainnet>(
            blobs.iter(),
            commitments.clone(),
            proofs.clone(),
            backend,
        ) {
            Ok(output) => {
                let expected_output = test
                    .output
                    .unwrap_or_else(|| panic!("test output should exist (backend {backend})"));

                assert_eq!(
                    output, expected_output,
                    "outputs do not match (backend {backend})"
                );
            }
            Err(_) => {
                assert!(
                    test.output.is_none(),
                    "test output should not exist (backend {backend})"
                );
            }
        }
    }
}

#[test_resources("consensus-spec-tests/tests/general/deneb/kzg/verify_kzg_proof/*/*")]
fn test_verify_kzg_proof(case: Case) {
    let test: containers::verify_kzg_proof::Test = case.yaml("data");

    let commitment = unwrap_test_input!(deserialize(&test.input.commitment), test);
    let z = unwrap_test_input!(test.input.get_z_bytes_fixed(), test);
    let y = unwrap_test_input!(test.input.get_y_bytes_fixed(), test);
    let proof = unwrap_test_input!(deserialize(&test.input.proof), test);

    for backend in available_backends() {
        match verify_kzg_proof(commitment, z, y, proof, backend) {
            Ok(output) => {
                let expected_output = test
                    .output
                    .unwrap_or_else(|| panic!("test output should exist (backend {backend})"));

                assert_eq!(
                    output, expected_output,
                    "outputs do not match (backend: {backend})"
                );
            }
            Err(_) => {
                assert!(
                    test.output.is_none(),
                    "test output should not exist (backend {backend})"
                );
            }
        }
    }
}
