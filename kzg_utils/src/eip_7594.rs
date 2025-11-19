use anyhow::Result;
use kzg::eth::eip_7594::{
    compute_cells_and_kzg_proofs_raw, compute_cells_raw, recover_cells_and_kzg_proofs_raw,
    verify_cell_kzg_proof_batch_raw,
};
#[cfg(feature = "arkworks")]
use rust_kzg_arkworks5::eip_7594::ArkBackend;
#[cfg(feature = "blst")]
use rust_kzg_blst::eip_7594::BlstBackend;
#[cfg(feature = "constantine")]
use rust_kzg_constantine::eip_7594::CtBackend;
#[cfg(feature = "mcl")]
use rust_kzg_mcl::eip_7594::MclBackend;
#[cfg(feature = "zkcrypto")]
use rust_kzg_zkcrypto::eip_7594::ZBackend;
use ssz::{ByteVector, ContiguousVector};
use tracing::instrument;
use try_from_iterator::TryFromIterator;
use types::{
    deneb::primitives::{Blob, KzgCommitment, KzgProof},
    fulu::primitives::{Cell, CellIndex, CellsAndKzgProofs},
    preset::Preset,
};

use crate::{error::KzgError, trusted_setup, KzgBackend};

#[instrument(level = "debug", skip_all)]
pub fn verify_cell_kzg_proof_batch<'a, P: Preset>(
    commitments: impl IntoIterator<Item = &'a KzgCommitment>,
    cell_indices: impl IntoIterator<Item = CellIndex>,
    cells: impl IntoIterator<Item = &'a Cell<P>>,
    proofs: impl IntoIterator<Item = &'a KzgProof>,
    backend: KzgBackend,
) -> Result<bool> {
    let raw_commitments = commitments
        .into_iter()
        .map(|c| c.to_fixed_bytes())
        .collect::<Vec<_>>();

    let cell_indices = cell_indices
        .into_iter()
        .map(|index| usize::try_from(index).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let raw_cells = cells
        .into_iter()
        .map(|c| c.as_bytes().try_into().map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let raw_proofs = proofs
        .into_iter()
        .map(|p| p.to_fixed_bytes())
        .collect::<Vec<_>>();

    let result = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => verify_cell_kzg_proof_batch_raw::<ArkBackend>(
            &raw_commitments,
            &cell_indices,
            &raw_cells,
            &raw_proofs,
            trusted_setup::arkworks_settings(),
        ),
        #[cfg(feature = "blst")]
        KzgBackend::Blst => verify_cell_kzg_proof_batch_raw::<BlstBackend>(
            &raw_commitments,
            &cell_indices,
            &raw_cells,
            &raw_proofs,
            trusted_setup::blst_settings(),
        ),
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => verify_cell_kzg_proof_batch_raw::<CtBackend>(
            &raw_commitments,
            &cell_indices,
            &raw_cells,
            &raw_proofs,
            trusted_setup::constantine_settings(),
        ),
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => verify_cell_kzg_proof_batch_raw::<MclBackend>(
            &raw_commitments,
            &cell_indices,
            &raw_cells,
            &raw_proofs,
            trusted_setup::mcl_settings(),
        ),
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => verify_cell_kzg_proof_batch_raw::<ZBackend>(
            &raw_commitments,
            &cell_indices,
            &raw_cells,
            &raw_proofs,
            trusted_setup::zkcrypto_settings(),
        ),
    };

    result.map_err(KzgError::KzgError).map_err(Into::into)
}

pub fn compute_cells_and_kzg_proofs<P: Preset>(
    blob: &Blob<P>,
    backend: KzgBackend,
) -> Result<CellsAndKzgProofs<P>> {
    let raw_blob = blob.as_bytes().try_into()?;

    let (raw_cells, raw_proofs) = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => compute_cells_and_kzg_proofs_raw::<ArkBackend>(
            raw_blob,
            trusted_setup::arkworks_settings(),
        )
        .map_err(KzgError::KzgError)?,
        #[cfg(feature = "blst")]
        KzgBackend::Blst => compute_cells_and_kzg_proofs_raw::<BlstBackend>(
            raw_blob,
            trusted_setup::blst_settings(),
        )
        .map_err(KzgError::KzgError)?,
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => compute_cells_and_kzg_proofs_raw::<CtBackend>(
            raw_blob,
            trusted_setup::constantine_settings(),
        )
        .map_err(KzgError::KzgError)?,
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => {
            compute_cells_and_kzg_proofs_raw::<MclBackend>(raw_blob, trusted_setup::mcl_settings())
                .map_err(KzgError::KzgError)?
        }
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => compute_cells_and_kzg_proofs_raw::<ZBackend>(
            raw_blob,
            trusted_setup::zkcrypto_settings(),
        )
        .map_err(KzgError::KzgError)?,
    };

    let cells = raw_cells
        .into_iter()
        .map(try_convert_to_cell::<P>)
        .collect::<Result<Vec<_>>>()?;

    let ext_cells = ContiguousVector::try_from_iter(cells)?;
    let ext_proofs = ContiguousVector::try_from_iter(raw_proofs.into_iter().map(Into::into))?;

    Ok((ext_cells, ext_proofs))
}

pub fn recover_cells_and_kzg_proofs<'cell, P: Preset>(
    cell_indices: impl IntoIterator<Item = CellIndex>,
    cells: impl IntoIterator<Item = &'cell Cell<P>>,
    backend: KzgBackend,
) -> Result<CellsAndKzgProofs<P>> {
    let cell_indices = cell_indices
        .into_iter()
        .map(|index| usize::try_from(index).map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let raw_cells = cells
        .into_iter()
        .map(|c| c.as_bytes().try_into().map_err(Into::into))
        .collect::<Result<Vec<_>>>()?;

    let (raw_cells, raw_proofs) = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => recover_cells_and_kzg_proofs_raw::<ArkBackend>(
            &cell_indices,
            &raw_cells,
            trusted_setup::arkworks_settings(),
        )
        .map_err(KzgError::KzgError)?,
        #[cfg(feature = "blst")]
        KzgBackend::Blst => recover_cells_and_kzg_proofs_raw::<BlstBackend>(
            &cell_indices,
            &raw_cells,
            trusted_setup::blst_settings(),
        )
        .map_err(KzgError::KzgError)?,
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => recover_cells_and_kzg_proofs_raw::<CtBackend>(
            &cell_indices,
            &raw_cells,
            trusted_setup::constantine_settings(),
        )
        .map_err(KzgError::KzgError)?,
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => recover_cells_and_kzg_proofs_raw::<MclBackend>(
            &cell_indices,
            &raw_cells,
            trusted_setup::mcl_settings(),
        )
        .map_err(KzgError::KzgError)?,
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => recover_cells_and_kzg_proofs_raw::<ZBackend>(
            &cell_indices,
            &raw_cells,
            trusted_setup::zkcrypto_settings(),
        )
        .map_err(KzgError::KzgError)?,
    };

    let cells = raw_cells
        .into_iter()
        .map(try_convert_to_cell::<P>)
        .collect::<Result<Vec<_>>>()?;
    let ext_cells = ContiguousVector::try_from_iter(cells)?;
    let ext_proofs = ContiguousVector::try_from_iter(raw_proofs.into_iter().map(Into::into))?;

    Ok((ext_cells, ext_proofs))
}

pub fn compute_cells<P: Preset>(
    blob: &Blob<P>,
    backend: KzgBackend,
) -> Result<ContiguousVector<Cell<P>, P::CellsPerExtBlob>> {
    let raw_blob = blob.as_bytes().try_into()?;

    let raw_cells = match backend {
        #[cfg(feature = "arkworks")]
        KzgBackend::Arkworks => {
            compute_cells_raw::<ArkBackend>(raw_blob, trusted_setup::arkworks_settings())
                .map_err(KzgError::KzgError)?
        }
        #[cfg(feature = "blst")]
        KzgBackend::Blst => {
            compute_cells_raw::<BlstBackend>(raw_blob, trusted_setup::blst_settings())
                .map_err(KzgError::KzgError)?
        }
        #[cfg(feature = "constantine")]
        KzgBackend::Constantine => {
            compute_cells_raw::<CtBackend>(raw_blob, trusted_setup::constantine_settings())
                .map_err(KzgError::KzgError)?
        }
        #[cfg(feature = "mcl")]
        KzgBackend::Mcl => compute_cells_raw::<MclBackend>(raw_blob, trusted_setup::mcl_settings())
            .map_err(KzgError::KzgError)?,
        #[cfg(feature = "zkcrypto")]
        KzgBackend::Zkcrypto => {
            compute_cells_raw::<ZBackend>(raw_blob, trusted_setup::zkcrypto_settings())
                .map_err(KzgError::KzgError)?
        }
    };

    let cells = raw_cells
        .into_iter()
        .map(try_convert_to_cell::<P>)
        .collect::<Result<Vec<_>>>()?;

    ContiguousVector::try_from_iter(cells).map_err(Into::into)
}

pub(crate) fn try_convert_to_cell<P: Preset>(
    cell: impl IntoIterator<Item = u8>,
) -> Result<Cell<P>> {
    ContiguousVector::try_from_iter(cell)
        .map(ByteVector::from)
        .map(Cell::<P>::from)
        .map_err(Into::into)
}
