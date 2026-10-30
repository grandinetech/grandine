use anyhow::{Result, ensure};
use bytesize::ByteSize;
use itertools::Itertools as _;
use logging::warn_with_peers;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};
use types::nonstandard::StorageMode;

use crate::hierarchy::Hierarchy;

/// Estimated memory one cached frame takes on mainnet.
const ESTIMATED_FRAME_SIZE: ByteSize = ByteSize::mib(640);

/// Estimated memory one cached state below the frame takes on mainnet however close it is to its
/// parent.
const ESTIMATED_PATCHED_STATE_BASE_SIZE: ByteSize = ByteSize::mib(24);

/// Estimated memory one cached state below the frame takes on mainnet for every slot between it and
/// its parent.
const ESTIMATED_PATCHED_STATE_SIZE_PER_SLOT: u64 = 128;

/// Frames are rewritten at every fork, and a mainnet phase lasts about `2^21` slots.
const MAX_PARENT_DISTANCE_EXPONENT: u8 = 21;

/// Share of system memory the caches may be estimated to occupy before it is worth warning about.
const MEMORY_WARNING_PERCENT: u64 = 80;

/// Tuning options for how beacon states are persisted.
#[derive(Clone, Debug)]
pub struct StateStorageConfig {
    /// Layout of state frames and deltas written to the database.
    pub hierarchy: Hierarchy,
    /// Number of states cached in memory for every hierarchy layer, starting
    /// from the shallowest one - the full state snapshot, in the same order
    /// `hierarchy` exponents are listed in. Layers left unlisted are uncached.
    pub cache_sizes: Vec<usize>,
}

impl StateStorageConfig {
    #[must_use]
    pub fn default_for_mode(storage_mode: StorageMode) -> Self {
        let hierarchy = Hierarchy::default();

        Self {
            cache_sizes: Self::default_cache_sizes(storage_mode, hierarchy.depth()),
            hierarchy,
        }
    }

    #[must_use]
    pub fn default_cache_sizes(storage_mode: StorageMode, depth: usize) -> Vec<usize> {
        let cache_sizes: &[usize] = if storage_mode.is_archive() {
            &[10, 20, 40, 40]
        } else {
            &[2, 4, 8, 8]
        };

        cache_sizes.iter().copied().take(depth).collect()
    }

    /// Memory the state caches are expected to take once every layer is full.
    fn estimated_cache_size(&self) -> ByteSize {
        let patched_state_sizes = self.hierarchy.exponents().iter().map(|parent_exponent| {
            let parent_distance = 1_u64 << (*parent_exponent).min(MAX_PARENT_DISTANCE_EXPONENT);

            ESTIMATED_PATCHED_STATE_BASE_SIZE.as_u64().saturating_add(
                parent_distance.saturating_mul(ESTIMATED_PATCHED_STATE_SIZE_PER_SLOT),
            )
        });

        let state_sizes =
            core::iter::once(ESTIMATED_FRAME_SIZE.as_u64()).chain(patched_state_sizes);

        let bytes = self
            .cache_sizes
            .iter()
            .zip(state_sizes)
            .map(|(size, state_size)| {
                u64::try_from(*size)
                    .unwrap_or(u64::MAX)
                    .saturating_mul(state_size)
            })
            .fold(0, u64::saturating_add);

        ByteSize::b(bytes)
    }

    /// A `total_memory` of zero means `sysinfo` could not probe this platform, which makes the
    /// share meaningless rather than exceeded.
    const fn exceeds_memory_share(estimated_cache_size: ByteSize, total_memory: ByteSize) -> bool {
        total_memory.as_u64() > 0
            && estimated_cache_size.as_u64()
                > total_memory
                    .as_u64()
                    .saturating_div(100)
                    .saturating_mul(MEMORY_WARNING_PERCENT)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.cache_sizes.len() <= self.hierarchy.depth(),
            "number of state cache sizes ({}) must not exceed the number of \
            hierarchy layers ({})",
            self.cache_sizes.len(),
            self.hierarchy.depth(),
        );

        let total_memory = ByteSize::b(
            System::new_with_specifics(
                RefreshKind::nothing().with_memory(MemoryRefreshKind::nothing().with_ram()),
            )
            .total_memory(),
        );

        let estimated_cache_size = self.estimated_cache_size();

        if Self::exceeds_memory_share(estimated_cache_size, total_memory) {
            warn_with_peers!(
                "state caches sized {} are estimated to take up to {estimated_cache_size} once \
                full, over {MEMORY_WARNING_PERCENT}% of the {total_memory} of memory this machine \
                has; the node may be OOM-killed if they fill up, so consider lowering \
                --state-cache-sizes",
                self.cache_sizes.iter().join(","),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_storage_config_accepts_fewer_cache_sizes_than_hierarchy_layers() -> Result<()> {
        let single = StateStorageConfig {
            cache_sizes: vec![5],
            ..StateStorageConfig::default_for_mode(StorageMode::default())
        };

        single.validate()?;

        let exactly_as_deep = StateStorageConfig {
            hierarchy: Hierarchy::new([9, 5]).expect("exponents in tests are valid"),
            cache_sizes: vec![5, 3],
        };

        exactly_as_deep.validate()?;

        let empty = StateStorageConfig {
            cache_sizes: vec![],
            ..StateStorageConfig::default_for_mode(StorageMode::default())
        };

        empty.validate()?;

        assert_eq!(empty.estimated_cache_size(), ByteSize::b(0));

        Ok(())
    }

    #[test]
    fn state_storage_config_rejects_more_cache_sizes_than_hierarchy_layers() {
        let too_many = StateStorageConfig {
            hierarchy: Hierarchy::new([9, 5]).expect("exponents in tests are valid"),
            cache_sizes: vec![5, 3, 3],
        };

        let error = too_many
            .validate()
            .expect_err("3 cache sizes do not fit into 2 hierarchy layers");

        assert_eq!(
            error.to_string(),
            "number of state cache sizes (3) must not exceed the number of hierarchy layers (2)",
        );
    }

    #[test]
    fn state_storage_config_accepts_an_oversized_cache() -> Result<()> {
        let oversized = StateStorageConfig {
            hierarchy: Hierarchy::new([5]).expect("exponents in tests are valid"),
            cache_sizes: vec![usize::MAX],
        };

        oversized.validate()?;

        Ok(())
    }

    #[test]
    fn estimated_cache_size_scales_with_the_number_of_cached_states() {
        let config = StateStorageConfig {
            hierarchy: Hierarchy::new([9, 5]).expect("exponents in tests are valid"),
            cache_sizes: vec![5, 3],
        };

        assert_eq!(
            config.estimated_cache_size(),
            ByteSize::b(
                ESTIMATED_FRAME_SIZE.as_u64() * 5
                    + (ESTIMATED_PATCHED_STATE_BASE_SIZE.as_u64() + (1 << 9) * 128) * 3,
            ),
        );

        let uncached = StateStorageConfig {
            cache_sizes: vec![],
            ..StateStorageConfig::default_for_mode(StorageMode::default())
        };

        assert_eq!(uncached.estimated_cache_size(), ByteSize::b(0));

        let saturating = StateStorageConfig {
            hierarchy: Hierarchy::new([5]).expect("exponents in tests are valid"),
            cache_sizes: vec![usize::MAX],
        };

        assert_eq!(saturating.estimated_cache_size(), ByteSize::b(u64::MAX));
    }

    #[test]
    fn estimated_cache_size_caps_the_distance_to_the_parent_at_a_phase() {
        let config = StateStorageConfig {
            hierarchy: Hierarchy::new([23, 18]).expect("exponents in tests are valid"),
            cache_sizes: vec![0, 1],
        };

        assert_eq!(config.estimated_cache_size(), ByteSize::mib(24 + 256));
    }

    #[test]
    fn estimated_cache_size_of_the_default_cache_sizes() {
        for (storage_mode, estimated_cache_size) in [
            (StorageMode::Archive, ByteSize::mib(15_520)),
            (StorageMode::default(), ByteSize::mib(3_104)),
        ] {
            let config = StateStorageConfig::default_for_mode(storage_mode);

            assert_eq!(config.estimated_cache_size(), estimated_cache_size);
        }
    }

    #[test]
    fn the_memory_warning_triggers_at_80_percent_of_total_memory() {
        let total_memory = ByteSize::b(16_000_000_000);
        let threshold = ByteSize::b(12_800_000_000);

        assert!(!StateStorageConfig::exceeds_memory_share(
            threshold,
            total_memory,
        ));

        assert!(StateStorageConfig::exceeds_memory_share(
            ByteSize::b(threshold.as_u64() + 1),
            total_memory,
        ));

        assert!(!StateStorageConfig::exceeds_memory_share(
            ByteSize::b(0),
            ByteSize::b(0),
        ));

        // `sysinfo` reports no memory at all on platforms it cannot probe.
        assert!(!StateStorageConfig::exceeds_memory_share(
            ByteSize::gib(64),
            ByteSize::b(0),
        ));
    }

    #[test]
    fn default_cache_sizes_depend_on_the_storage_mode() {
        assert_eq!(
            StateStorageConfig::default_cache_sizes(StorageMode::Archive, 7),
            vec![10, 20, 40, 40],
        );

        assert_eq!(
            StateStorageConfig::default_cache_sizes(StorageMode::default(), 7),
            vec![2, 4, 8, 8],
        );

        assert_eq!(
            StateStorageConfig::default_cache_sizes(StorageMode::Prune, 7),
            vec![2, 4, 8, 8],
        );
    }

    #[test]
    fn default_cache_sizes_are_truncated_to_the_hierarchy_depth() {
        assert!(StateStorageConfig::default_cache_sizes(StorageMode::Archive, 0).is_empty());

        assert_eq!(
            StateStorageConfig::default_cache_sizes(StorageMode::Archive, 2),
            vec![10, 20],
        );
    }

    #[test]
    fn state_storage_config_accepts_a_sub_epoch_deepest_layer() -> Result<()> {
        for deepest_exponent in [4, 3, 2, 1, 0] {
            let sub_epoch = StateStorageConfig {
                hierarchy: Hierarchy::new([9, deepest_exponent])
                    .expect("exponents in tests are valid"),
                cache_sizes: StateStorageConfig::default_cache_sizes(StorageMode::default(), 2),
            };

            sub_epoch.validate()?;
        }

        Ok(())
    }
}
