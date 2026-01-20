use std::{collections::HashMap, sync::Arc};

use ssz::H256;
use std_ext::ArcExt as _;
use types::{
    gloas::containers::SignedExecutionPayloadEnvelope, phase0::primitives::Slot, preset::Preset,
};

#[derive(Clone, Default)]
pub struct ExecutionPayloadEnvelopeCache<P: Preset> {
    envelopes: HashMap<H256, (Arc<SignedExecutionPayloadEnvelope<P>>, Slot, bool)>,
}

impl<P: Preset> ExecutionPayloadEnvelopeCache<P> {
    pub fn get(&self, block_root: H256) -> Option<Arc<SignedExecutionPayloadEnvelope<P>>> {
        Some(self.envelopes.get(&block_root)?.0.clone_arc())
    }

    pub fn insert(&mut self, envelope: Arc<SignedExecutionPayloadEnvelope<P>>) {
        let slot = envelope.message.slot;
        let block_root = envelope.message.beacon_block_root;

        self.envelopes.insert(block_root, (envelope, slot, false));
    }

    pub fn prune_finalized(&mut self, finalized_slot: Slot) {
        self.envelopes
            .retain(|_, (_, envelope_slot, _)| finalized_slot <= *envelope_slot);
    }

    pub fn has_unpersisted_envelopes(&self) -> bool {
        self.envelopes
            .iter()
            .any(|(_, (_, _, persisted))| !persisted)
    }

    pub fn mark_persisted_envelopes(&mut self, persisted_roots: Vec<H256>) {
        for root in persisted_roots {
            self.envelopes
                .entry(root)
                .and_modify(|entry| entry.2 = true);
        }
    }

    pub fn unpersisted_envelopes(
        &self,
    ) -> impl Iterator<Item = (H256, Arc<SignedExecutionPayloadEnvelope<P>>)> + '_ {
        self.envelopes
            .iter()
            .filter(|(_, (_, _, persisted))| !persisted)
            .map(|(root, (envelope, _, _))| (*root, envelope.clone_arc()))
    }

    pub fn size(&self) -> usize {
        self.envelopes.len()
    }
}
