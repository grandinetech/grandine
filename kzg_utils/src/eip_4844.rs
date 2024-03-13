use anyhow::Result;
use kzg::{
    eip_4844::{
        blob_to_kzg_commitment_raw, compute_blob_kzg_proof_raw, compute_kzg_proof_raw,
        verify_blob_kzg_proof_batch_raw, verify_blob_kzg_proof_raw, verify_kzg_proof_raw,
    },
    Fr, G1,
};
use types::{
    deneb::primitives::{Blob, KzgCommitment, KzgProof},
    preset::Preset,
};

use crate::{error::KzgError, trusted_setup::settings};

pub fn blob_to_kzg_commitment<P: Preset>(blob: &Blob<P>) -> Result<KzgCommitment> {
    let blob_bytes = blob.as_bytes().try_into()?;

    let commitment = blob_to_kzg_commitment_raw(blob_bytes, settings())
        .map_err(KzgError::KzgError)?
        .to_bytes()
        .into();

    Ok(commitment)
}

pub fn compute_blob_kzg_proof<P: Preset>(
    blob: &Blob<P>,
    commitment: KzgCommitment,
) -> Result<KzgProof> {
    let blob_bytes = blob.as_bytes().try_into()?;
    let commitment_bytes = commitment.to_fixed_bytes();

    let proof = compute_blob_kzg_proof_raw(blob_bytes, commitment_bytes, settings())
        .map_err(KzgError::KzgError)?
        .to_bytes()
        .into();

    Ok(proof)
}

pub fn compute_kzg_proof<P: Preset>(
    blob: &Blob<P>,
    z_bytes: [u8; 32],
) -> Result<(KzgProof, [u8; 32])> {
    let blob_bytes = blob.as_bytes().try_into()?;

    let (proof, y) =
        compute_kzg_proof_raw(blob_bytes, z_bytes, settings()).map_err(KzgError::KzgError)?;

    Ok((proof.to_bytes().into(), y.to_bytes()))
}

pub fn verify_blob_kzg_proof<P: Preset>(
    blob: &Blob<P>,
    commitment: KzgCommitment,
    proof: KzgProof,
) -> Result<bool> {
    let blob_bytes = blob.as_bytes().try_into()?;
    let commitment_bytes = commitment.to_fixed_bytes();
    let proof_bytes = proof.to_fixed_bytes();

    verify_blob_kzg_proof_raw(blob_bytes, commitment_bytes, proof_bytes, settings())
        .map_err(KzgError::KzgError)
        .map_err(Into::into)
}

pub fn verify_blob_kzg_proof_batch<'blob, P: Preset>(
    blobs: impl IntoIterator<Item = &'blob Blob<P>>,
    commitments: impl IntoIterator<Item = KzgCommitment>,
    proofs: impl IntoIterator<Item = KzgProof>,
) -> Result<bool> {
    let raw_blobs = blobs
        .into_iter()
        .map(|blob| blob.as_bytes().try_into().map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let raw_commitments = commitments
        .into_iter()
        .map(KzgCommitment::to_fixed_bytes)
        .collect::<Vec<_>>();

    let raw_proofs = proofs
        .into_iter()
        .map(KzgProof::to_fixed_bytes)
        .collect::<Vec<_>>();

    verify_blob_kzg_proof_batch_raw(&raw_blobs, &raw_commitments, &raw_proofs, settings())
        .map_err(KzgError::KzgError)
        .map_err(Into::into)
}

pub fn verify_kzg_proof(
    commitment: KzgCommitment,
    z_bytes: [u8; 32],
    y_bytes: [u8; 32],
    proof: KzgProof,
) -> Result<bool> {
    let commitment_bytes = commitment.to_fixed_bytes();
    let proof_bytes = proof.to_fixed_bytes();

    verify_kzg_proof_raw(commitment_bytes, z_bytes, y_bytes, proof_bytes, settings())
        .map_err(KzgError::KzgError)
        .map_err(Into::into)
}
