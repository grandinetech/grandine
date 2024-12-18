use bls::{traits::SignatureBytes as _, AggregateSignatureBytes};

use crate::{altair::containers::SyncAggregate, preset::Preset};

impl<P: Preset> SyncAggregate<P> {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            sync_committee_signature: AggregateSignatureBytes::empty(),
            ..Self::default()
        }
    }
}
