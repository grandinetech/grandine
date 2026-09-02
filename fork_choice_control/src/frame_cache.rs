use std::sync::Arc;

use anyhow::{Result, anyhow};
use cached::{Cached, SizedCache};
use parking_lot::Mutex;
use ssz::H256;
use types::{combined::BeaconState, preset::Preset};

type Layers<P> = Arc<Vec<Option<Mutex<SizedCache<H256, Arc<BeaconState<P>>>>>>>;

#[derive(Clone)]
pub struct FrameCache<P: Preset> {
    layers: Layers<P>,
}

impl<P: Preset> FrameCache<P> {
    pub fn new(capacity: impl IntoIterator<Item = usize>) -> Result<Self> {
        capacity
            .into_iter()
            .map(|cap| {
                // A layer sized zero disables caching for that layer. `SizedCache::try_with_size`
                // reports that as `EINVAL`, but so does a capacity overflow, so it is checked here
                // rather than by matching on the error.
                if cap == 0 {
                    return Ok(None);
                }

                SizedCache::try_with_size(cap)
                    .map(|cache| Some(Mutex::new(cache)))
                    .map_err(|error| {
                        anyhow!("unable to instantiate a state cache layer of size {cap}: {error}")
                    })
            })
            .collect::<Result<_>>()
            .map(Arc::new)
            .map(|layers| Self { layers })
    }

    pub fn set(&self, layer: usize, block_root: H256, value: Arc<BeaconState<P>>) -> Result<()> {
        let layer = self
            .layers
            .get(layer)
            .ok_or_else(|| anyhow!("Failed to cache state: layer {layer} is not valid"))?;

        if let Some(layer) = layer {
            let mut lock = layer.lock();
            lock.cache_set(block_root, value);
        }

        Ok(())
    }

    #[cfg(test)]
    pub fn clear(&self) {
        for layer in self.layers.iter().flatten() {
            layer.lock().cache_clear();
        }
    }

    pub fn get(&self, layer: usize, hash: &H256) -> Result<Option<Arc<BeaconState<P>>>> {
        let layer = self
            .layers
            .get(layer)
            .ok_or_else(|| anyhow!("Failed to get state from cache: layer {layer} is not valid"))?;

        if let Some(layer) = layer {
            let mut lock = layer.lock();
            Ok(lock.cache_get(hash).cloned())
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use types::{
        phase0::beacon_state::BeaconState as Phase0BeaconState, preset::Mainnet,
        traits::BeaconState as _,
    };

    use super::*;

    fn state(slot: u64) -> Arc<BeaconState<Mainnet>> {
        Arc::new(BeaconState::Phase0(
            Phase0BeaconState {
                slot,
                ..Phase0BeaconState::default()
            }
            .into(),
        ))
    }

    #[test]
    fn zero_sized_layer_never_stores_anything() -> Result<()> {
        let cache = FrameCache::<Mainnet>::new([0, 1])?;
        let block_root = H256::repeat_byte(1);

        cache.set(0, block_root, state(32))?;

        assert!(cache.get(0, &block_root)?.is_none());

        // A sized layer of the same cache still works.
        cache.set(1, block_root, state(64))?;

        assert_eq!(
            cache.get(1, &block_root)?.map(|state| state.slot()),
            Some(64)
        );

        Ok(())
    }

    #[test]
    fn out_of_range_layer_is_an_error() -> Result<()> {
        let cache = FrameCache::<Mainnet>::new([1, 1])?;
        let block_root = H256::repeat_byte(1);

        cache
            .set(2, block_root, state(32))
            .expect_err("layer 2 is outside a two-layer cache");

        cache
            .get(2, &block_root)
            .expect_err("layer 2 is outside a two-layer cache");

        Ok(())
    }

    #[test]
    fn eviction_respects_the_configured_layer_size() -> Result<()> {
        let cache = FrameCache::<Mainnet>::new([2, 1])?;

        let entries = [
            (H256::repeat_byte(1), 32),
            (H256::repeat_byte(2), 64),
            (H256::repeat_byte(3), 96),
        ];

        for (root, slot) in entries {
            cache.set(0, root, state(slot))?;
        }

        // The layer holds two states, so the least recently used one is gone.
        assert!(cache.get(0, &entries[0].0)?.is_none());
        assert!(cache.get(0, &entries[1].0)?.is_some());
        assert!(cache.get(0, &entries[2].0)?.is_some());

        for (root, slot) in entries {
            cache.set(1, root, state(slot))?;
        }

        assert!(cache.get(1, &entries[0].0)?.is_none());
        assert!(cache.get(1, &entries[1].0)?.is_none());
        assert!(cache.get(1, &entries[2].0)?.is_some());

        Ok(())
    }
}
