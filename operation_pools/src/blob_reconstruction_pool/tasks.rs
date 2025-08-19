use anyhow::Result;
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::misc;
use log::{debug, info, warn};
use prometheus_metrics::Metrics;
use std::sync::Arc;
use typenum::Unsigned as _;
use types::{fulu::containers::DataColumnIdentifier, phase0::primitives::H256, preset::Preset};

use crate::misc::PoolTask;
pub struct ReconstructDataColumnSidecarsTask<P: Preset, W: Wait> {
    pub controller: ApiController<P, W>,
    pub wait_group: W,
    pub block_root: H256,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W: Wait> PoolTask for ReconstructDataColumnSidecarsTask<P, W> {
    type Output = ();

    async fn run(self) -> Result<Self::Output> {
        let Self {
            controller,
            wait_group,
            block_root,
            metrics,
        } = self;

        let Ok(available_columns) = controller.data_column_sidecars_by_ids(
            (0..P::NumberOfColumns::U64).map(|index| DataColumnIdentifier { block_root, index }),
        ) else {
            warn!("failed to retrieve data column sidecar from storage");
            return Ok(());
        };

        if available_columns.len() == P::NumberOfColumns::USIZE {
            debug!("no need to reconstruct data columns: {block_root:?}");
            return Ok(());
        }

        if available_columns.len() * 2 < P::NumberOfColumns::USIZE {
            warn!(
                "cannot start reconstruction for block {block_root:?}: \
                insufficient data columns (available: {})",
                available_columns.len(),
            );

            return Ok(());
        }

        debug!("starting reconstruction for block: {block_root:?}");

        let _columns_reconstruction_timer = metrics
            .as_ref()
            .map(|metrics| metrics.columns_reconstruction_time.start_timer());

        let reconstructed_count = P::NumberOfColumns::USIZE.saturating_sub(available_columns.len());
        let partial_matrix = available_columns
            .into_iter()
            .flat_map(|sidecar| misc::compute_matrix_for_data_column_sidecar(&sidecar))
            .collect::<Vec<_>>();

        match eip_7594::recover_matrix(&partial_matrix, controller.store_config().kzg_backend) {
            Ok(full_matrix) => {
                info!("reconstructed missing data columns for block: {block_root:?}");
                controller.on_reconstruction(wait_group, block_root, full_matrix);

                if let Some(metrics) = metrics.as_ref() {
                    metrics
                        .reconstructed_columns
                        .inc_by(reconstructed_count as u64);
                }
            }
            Err(error) => {
                controller.mark_sidecar_construction_failed(&block_root);

                warn!(
                    "failed to reconstruct missing data column sidecars for \
                    block_root: {block_root:?}: {error:?}",
                );
            }
        }

        Ok(())
    }
}
