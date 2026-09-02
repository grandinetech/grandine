use std::{collections::HashMap, sync::Arc};

use anyhow::{Result, ensure};
use bls::PublicKeyBytes;
use fork_choice_control::Wait;
use helper_functions::{accessors, misc};
use itertools::Itertools as _;
use logging::warn_with_peers;
use scc::HashMap as SccHashMap;
use signer::Signer;
use ssz::H256;
use std_ext::ArcExt as _;
use tap::{Conv as _, Pipe as _};
use tokio::sync::Mutex;
use tracing::instrument;
use types::{
    combined::BeaconState,
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::{BeaconNodeApi as _, PtcDuties},
    beacon_nodes::BeaconNodes,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PTCMember {
    pub public_key: PublicKeyBytes,
    pub validator_index: ValidatorIndex,
}

pub struct OwnPTCMembers {
    signer: Arc<Signer>,
    members: SccHashMap<(H256, Slot), Arc<[PTCMember]>>,
    /// The indices the members were computed for; a key imported at runtime changes the set.
    requested: Mutex<Arc<[ValidatorIndex]>>,
}

impl OwnPTCMembers {
    pub fn new(signer: Arc<Signer>) -> Self {
        Self {
            signer,
            members: SccHashMap::new(),
            requested: Mutex::new(Arc::from([])),
        }
    }

    async fn discard_for_other_keys(&self, validator_indices: &[ValidatorIndex]) {
        let mut requested = self.requested.lock().await;

        if **requested == *validator_indices {
            return;
        }

        *requested = validator_indices.into();
        self.members.clear_async().await;
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
        let validator_indices = self
            .signer
            .load()
            .keys()
            .filter_map(|public_key| accessors::index_of_public_key(state, public_key))
            .sorted()
            .collect::<Vec<_>>();

        self.discard_for_other_keys(&validator_indices).await;

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

    pub async fn get_at_slot(&self, dependent_root: H256, slot: Slot) -> Option<Arc<[PTCMember]>> {
        self.members
            .get_async(&(dependent_root, slot))
            .await
            .map(|members| members.clone_arc())
    }

    /// Fetches the members of `epoch` as duties unless they are already known under
    /// `dependent_root`, for nodes whose state is not at hand.
    pub async fn init_at_epoch<P: Preset, W: Wait + Sync>(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        epoch: Epoch,
        dependent_root: H256,
        validator_indices: &[ValidatorIndex],
    ) -> Result<()> {
        self.discard_for_other_keys(validator_indices).await;

        let slots = misc::slots_in_epoch::<P>(epoch)?;

        // Every slot of a fetched epoch is cached, so the first one stands for all of them.
        if self
            .get_at_slot(dependent_root, slots.start)
            .await
            .is_some()
        {
            return Ok(());
        }

        let PtcDuties {
            dependent_root: reported_root,
            duties,
        } = beacon_nodes.ptc_duties(epoch, validator_indices).await?;

        // Another root is another shuffling; the duties cannot stand in for the ones asked for.
        ensure!(
            reported_root == dependent_root,
            "PTC duties for epoch {epoch} were reported under dependent root {reported_root:?} \
             rather than {dependent_root:?}",
        );

        let signer_snapshot = self.signer.load();
        let mut members_by_slot = slots
            .map(|slot| (slot, Vec::<PTCMember>::new()))
            .collect::<HashMap<_, _>>();

        for duty in duties {
            // A duty for a key we do not hold would fail the whole signing batch.
            if !signer_snapshot.has_key(duty.pubkey) {
                continue;
            }

            let Some(members) = members_by_slot.get_mut(&duty.slot) else {
                continue;
            };

            let member = PTCMember {
                public_key: duty.pubkey,
                validator_index: duty.validator_index,
            };

            // A validator drawn into several positions still sends a single message.
            if !members.contains(&member) {
                members.push(member);
            }
        }

        for (slot, mut members) in members_by_slot {
            members.sort_unstable_by_key(|member| member.validator_index);

            self.members
                .upsert_async((dependent_root, slot), members.into())
                .await;
        }

        Ok(())
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
            .filter_map(|validator_index| {
                own_public_keys
                    .get(&validator_index)
                    .copied()
                    .map(|public_key| PTCMember {
                        public_key,
                        validator_index,
                    })
            })
            // A validator drawn into several positions still sends a single message.
            .unique()
            .collect::<Vec<_>>()
            .conv::<Arc<[_]>>()
            .pipe(Some)
            .pipe(Ok)
    }
}
