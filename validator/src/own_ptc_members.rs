use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use bls::PublicKeyBytes;
use helper_functions::accessors;
use logging::warn_with_peers;
use scc::HashMap as SccHashMap;
use signer::Signer;
use ssz::H256;
use std_ext::ArcExt as _;
use tap::{Conv as _, Pipe as _};
use tracing::instrument;
use types::{
    combined::BeaconState,
    phase0::primitives::{Slot, ValidatorIndex},
    preset::Preset,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PTCMember {
    pub public_key: PublicKeyBytes,
    pub validator_index: ValidatorIndex,
    pub position_in_committee: usize,
}

pub struct OwnPTCMembers {
    signer: Arc<Signer>,
    members: SccHashMap<(H256, Slot), Arc<[PTCMember]>>,
}

impl OwnPTCMembers {
    pub fn new(signer: Arc<Signer>) -> Self {
        Self {
            signer,
            members: SccHashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    #[instrument(skip_all, level = "debug", fields(slot = slot, dependent_root = ?dependent_root))]
    pub async fn get_or_init_at_slot<P: Preset>(
        &self,
        state: &BeaconState<P>,
        dependent_root: H256,
        slot: Slot,
    ) -> Option<Arc<[PTCMember]>> {
        if let Some(members) = self.members.get_async(&(dependent_root, slot)).await {
            return Some(members.clone_arc());
        }

        match self.compute_members_at_slot(state, slot) {
            Ok(members) => {
                if let Some(members) = members {
                    self.members
                        .upsert_async((dependent_root, slot), members.clone_arc())
                        .await;

                    Some(members)
                } else {
                    None
                }
            }
            Err(error) => {
                warn_with_peers!(
                    "failed to compute own beacon committee members at slot {slot}: {error:?}"
                );
                None
            }
        }
    }

    pub async fn prune(&self, up_to_slot: Slot) {
        self.members
            .retain_async(|(_, slot), _| *slot >= up_to_slot)
            .await
    }

    #[instrument(skip_all, level = "debug", fields(slot = slot))]
    fn compute_members_at_slot<P: Preset>(
        &self,
        state: &BeaconState<P>,
        slot: Slot,
    ) -> Result<Option<Arc<[PTCMember]>>> {
        let signer_snapshot = self.signer.load();

        let own_public_keys = signer_snapshot
            .keys()
            .copied()
            .filter_map(|public_key| {
                let validator_index = accessors::index_of_public_key(state, &public_key)?;
                Some((validator_index, public_key))
            })
            .collect::<HashMap<_, _>>();

        if own_public_keys.is_empty() {
            return Ok(None);
        }

        accessors::get_ptc(state, slot)?
            .into_iter()
            .zip(0..)
            .filter_map(|(validator_index, position_in_committee)| {
                own_public_keys
                    .get(&validator_index)
                    .copied()
                    .map(|public_key| PTCMember {
                        public_key,
                        validator_index,
                        position_in_committee,
                    })
            })
            .collect::<Vec<_>>()
            .conv::<Arc<[_]>>()
            .pipe(Some)
            .pipe(Ok)
    }
}
