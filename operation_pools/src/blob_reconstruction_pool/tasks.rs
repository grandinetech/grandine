use std::sync::Arc;

use anyhow::Result;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::misc;
use logging::{debug_with_peers, info_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use tap::Tap as _;
use typenum::Unsigned as _;
use types::{
    combined::SignedBeaconBlock, fulu::containers::DataColumnIdentifier, phase0::primitives::H256,
    preset::Preset,
};

use crate::misc::PoolTask;
pub struct ReconstructDataColumnSidecarsTask<P: Preset, W: Wait> {
    pub controller: ApiController<P, W>,
    pub wait_group: W,
    pub block_root: H256,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> PoolTask for ReconstructDataColumnSidecarsTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            controller,
            wait_group,
            block_root,
            block,
            metrics,
        } = self;

        let Ok(available_columns) = controller.data_column_sidecars_by_ids(
            (0..P::NumberOfColumns::U64).map(|index| DataColumnIdentifier { block_root, index }),
        ) else {
            warn_with_peers!("failed to retrieve data column sidecar from storage");
            return Ok(());
        };

        if available_columns.len() == P::NumberOfColumns::USIZE {
            debug_with_peers!("no need to reconstruct data columns: {block_root:?}");
            return Ok(());
        }

        if available_columns.len() * 2 < P::NumberOfColumns::USIZE {
            warn_with_peers!(
                "cannot start reconstruction for block {block_root:?}: \
                insufficient data columns (available: {})",
                available_columns.len(),
            );

            return Ok(());
        }

        debug_with_peers!("starting reconstruction for block: {block_root:?}");

        let columns_reconstruction_timer = metrics
            .as_ref()
            .map(|metrics| metrics.columns_reconstruction_time.start_timer());

        let reconstructed_count = P::NumberOfColumns::USIZE.saturating_sub(available_columns.len());
        let partial_matrix = available_columns
            .into_iter()
            .flat_map(|sidecar| misc::compute_matrix_for_data_column_sidecar(&sidecar))
            .collect::<Vec<_>>();

        let reconstruction_result =
            eip_7594::recover_matrix(&partial_matrix, controller.store_config().kzg_backend)
                .tap(|_| prometheus_metrics::stop_and_record(columns_reconstruction_timer))
                .and_then(|full_matrix| {
                    let timer = metrics
                        .as_ref()
                        .map(|metrics| metrics.data_column_sidecar_computation.start_timer());

                    let cells_and_kzg_proofs =
                        eip_7594::construct_cells_and_kzg_proofs(full_matrix)?;

                    let data_column_sidecars =
                        eip_7594::construct_data_column_sidecars(&block, &cells_and_kzg_proofs)?;

                    prometheus_metrics::stop_and_record(timer);

                    Ok(data_column_sidecars)
                });

        match reconstruction_result {
            Ok(data_column_sidecars) => {
                info_with_peers!("reconstructed missing data columns for block: {block_root:?}");

                controller.on_reconstruction(wait_group, block_root, block, data_column_sidecars);

                if let Some(metrics) = metrics.as_ref() {
                    metrics
                        .reconstructed_columns
                        .inc_by(reconstructed_count as u64);
                }
            }
            Err(error) => {
                controller.mark_sidecar_construction_failed(&block_root);

                warn_with_peers!(
                    "failed to reconstruct missing data column sidecars for \
                    block_root: {block_root:?}: {error:?}",
                );
            }
        }

        Ok(())
    }
}
