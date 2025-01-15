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

use crate::{error::KzgError, trusted_setup, KzgBackend};

pub fn blob_to_kzg_commitment<P: Preset>(
    blob: &Blob<P>,
    backend: KzgBackend,
) -> Result<KzgCommitment> {
    let blob_bytes = blob.as_bytes().try_into()?;

    let commitment = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => {
            blob_to_kzg_commitment_raw(blob_bytes, trusted_setup::arkworks_settings())
                .map_err(KzgError::KzgError)?
                .to_bytes()
        }
        #[cfg(feature = "blst")]
        KzgBackend::Blst => blob_to_kzg_commitment_raw(blob_bytes, trusted_setup::blst_settings())
            .map_err(KzgError::KzgError)?
            .to_bytes(),
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => {
            blob_to_kzg_commitment_raw(blob_bytes, trusted_setup::constantine_settings())
                .map_err(KzgError::KzgError)?
                .to_bytes()
        }
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => blob_to_kzg_commitment_raw(blob_bytes, trusted_setup::mcl_settings())
            .map_err(KzgError::KzgError)?
            .to_bytes(),
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => {
            blob_to_kzg_commitment_raw(blob_bytes, trusted_setup::zkcrypto_settings())
                .map_err(KzgError::KzgError)?
                .to_bytes()
        }
    };

    Ok(commitment.into())
}

pub fn compute_blob_kzg_proof<P: Preset>(
    blob: &Blob<P>,
    commitment: KzgCommitment,
    backend: KzgBackend,
) -> Result<KzgProof> {
    let blob_bytes = blob.as_bytes().try_into()?;
    let commitment_bytes = commitment.to_fixed_bytes();

    let proof = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => compute_blob_kzg_proof_raw(
            blob_bytes,
            commitment_bytes,
            trusted_setup::arkworks_settings(),
        )
        .map_err(KzgError::KzgError)?
        .to_bytes(),
        #[cfg(feature = "blst")]
        KzgBackend::Blst => {
            compute_blob_kzg_proof_raw(blob_bytes, commitment_bytes, trusted_setup::blst_settings())
                .map_err(KzgError::KzgError)?
                .to_bytes()
        }
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => compute_blob_kzg_proof_raw(
            blob_bytes,
            commitment_bytes,
            trusted_setup::constantine_settings(),
        )
        .map_err(KzgError::KzgError)?
        .to_bytes(),
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => {
            compute_blob_kzg_proof_raw(blob_bytes, commitment_bytes, trusted_setup::mcl_settings())
                .map_err(KzgError::KzgError)?
                .to_bytes()
        }
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => compute_blob_kzg_proof_raw(
            blob_bytes,
            commitment_bytes,
            trusted_setup::zkcrypto_settings(),
        )
        .map_err(KzgError::KzgError)?
        .to_bytes(),
    };

    Ok(proof.into())
}

pub fn compute_kzg_proof<P: Preset>(
    blob: &Blob<P>,
    z_bytes: [u8; 32],
    backend: KzgBackend,
) -> Result<(KzgProof, [u8; 32])> {
    let blob_bytes = blob.as_bytes().try_into()?;

    let (proof, y) = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => {
            compute_kzg_proof_raw(blob_bytes, z_bytes, trusted_setup::arkworks_settings())
                .map_err(KzgError::KzgError)
                .map(|(proof, y)| (proof.to_bytes(), y.to_bytes()))?
        }
        #[cfg(feature = "blst")]
        KzgBackend::Blst => {
            compute_kzg_proof_raw(blob_bytes, z_bytes, trusted_setup::blst_settings())
                .map_err(KzgError::KzgError)
                .map(|(proof, y)| (proof.to_bytes(), y.to_bytes()))?
        }
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => {
            compute_kzg_proof_raw(blob_bytes, z_bytes, trusted_setup::constantine_settings())
                .map_err(KzgError::KzgError)
                .map(|(proof, y)| (proof.to_bytes(), y.to_bytes()))?
        }
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => {
            compute_kzg_proof_raw(blob_bytes, z_bytes, trusted_setup::mcl_settings())
                .map_err(KzgError::KzgError)
                .map(|(proof, y)| (proof.to_bytes(), y.to_bytes()))?
        }
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => {
            compute_kzg_proof_raw(blob_bytes, z_bytes, trusted_setup::zkcrypto_settings())
                .map_err(KzgError::KzgError)
                .map(|(proof, y)| (proof.to_bytes(), y.to_bytes()))?
        }
    };

    Ok((proof.into(), y))
}

pub fn verify_blob_kzg_proof<P: Preset>(
    blob: &Blob<P>,
    commitment: KzgCommitment,
    proof: KzgProof,
    backend: KzgBackend,
) -> Result<bool> {
    let blob_bytes = blob.as_bytes().try_into()?;
    let commitment_bytes = commitment.to_fixed_bytes();
    let proof_bytes = proof.to_fixed_bytes();

    let result = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => verify_blob_kzg_proof_raw(
            blob_bytes,
            commitment_bytes,
            proof_bytes,
            trusted_setup::arkworks_settings(),
        ),
        #[cfg(feature = "blst")]
        KzgBackend::Blst => verify_blob_kzg_proof_raw(
            blob_bytes,
            commitment_bytes,
            proof_bytes,
            trusted_setup::blst_settings(),
        ),
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => verify_blob_kzg_proof_raw(
            blob_bytes,
            commitment_bytes,
            proof_bytes,
            trusted_setup::constantine_settings(),
        ),
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => verify_blob_kzg_proof_raw(
            blob_bytes,
            commitment_bytes,
            proof_bytes,
            trusted_setup::mcl_settings(),
        ),
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => verify_blob_kzg_proof_raw(
            blob_bytes,
            commitment_bytes,
            proof_bytes,
            trusted_setup::zkcrypto_settings(),
        ),
    };

    result.map_err(KzgError::KzgError).map_err(Into::into)
}

pub fn verify_blob_kzg_proof_batch<'blob, P: Preset>(
    blobs: impl IntoIterator<Item = &'blob Blob<P>>,
    commitments: impl IntoIterator<Item = KzgCommitment>,
    proofs: impl IntoIterator<Item = KzgProof>,
    backend: KzgBackend,
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

    let result = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => verify_blob_kzg_proof_batch_raw(
            &raw_blobs,
            &raw_commitments,
            &raw_proofs,
            trusted_setup::arkworks_settings(),
        ),
        #[cfg(feature = "blst")]
        KzgBackend::Blst => verify_blob_kzg_proof_batch_raw(
            &raw_blobs,
            &raw_commitments,
            &raw_proofs,
            trusted_setup::blst_settings(),
        ),
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => verify_blob_kzg_proof_batch_raw(
            &raw_blobs,
            &raw_commitments,
            &raw_proofs,
            trusted_setup::constantine_settings(),
        ),
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => verify_blob_kzg_proof_batch_raw(
            &raw_blobs,
            &raw_commitments,
            &raw_proofs,
            trusted_setup::mcl_settings(),
        ),
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => verify_blob_kzg_proof_batch_raw(
            &raw_blobs,
            &raw_commitments,
            &raw_proofs,
            trusted_setup::zkcrypto_settings(),
        ),
    };

    result.map_err(KzgError::KzgError).map_err(Into::into)
}

pub fn verify_kzg_proof(
    commitment: KzgCommitment,
    z_bytes: [u8; 32],
    y_bytes: [u8; 32],
    proof: KzgProof,
    backend: KzgBackend,
) -> Result<bool> {
    let commitment_bytes = commitment.to_fixed_bytes();
    let proof_bytes = proof.to_fixed_bytes();

    let result = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => verify_kzg_proof_raw(
            commitment_bytes,
            z_bytes,
            y_bytes,
            proof_bytes,
            trusted_setup::arkworks_settings(),
        ),
        #[cfg(feature = "blst")]
        KzgBackend::Blst => verify_kzg_proof_raw(
            commitment_bytes,
            z_bytes,
            y_bytes,
            proof_bytes,
            trusted_setup::blst_settings(),
        ),
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => verify_kzg_proof_raw(
            commitment_bytes,
            z_bytes,
            y_bytes,
            proof_bytes,
            trusted_setup::constantine_settings(),
        ),
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => verify_kzg_proof_raw(
            commitment_bytes,
            z_bytes,
            y_bytes,
            proof_bytes,
            trusted_setup::mcl_settings(),
        ),
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => verify_kzg_proof_raw(
            commitment_bytes,
            z_bytes,
            y_bytes,
            proof_bytes,
            trusted_setup::zkcrypto_settings(),
        ),
    };

    result.map_err(KzgError::KzgError).map_err(Into::into)
}
