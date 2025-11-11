use anyhow::{ensure, Result};
use ssz::Hc;
use types::{
    preset::Preset,
    traits::{BeaconBlock, BeaconState},
};

use crate::unphased::Error;

pub enum StateRootPolicy {
    Verify,
    Trust,
}

impl StateRootPolicy {
    #[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
    pub fn verify<P: Preset>(
        self,
        state: &Hc<impl BeaconState<P>>,
        block: &impl BeaconBlock<P>,
    ) -> Result<()> {
        match self {
            Self::Verify => {
                let computed = state.hash_tree_root();
                let in_block = block.state_root();

                ensure!(
                    computed == in_block,
                    Error::<P>::StateRootMismatch { computed, in_block },
                );
            }
            Self::Trust => {
                state.set_cached_root(block.state_root());
            }
        }

        Ok(())
    }
}
