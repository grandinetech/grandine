use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use bls::PublicKeyBytes;
use fork_choice_control::Wait;
use helper_functions::misc;
use http_api_utils::ValidatorPTCDutyResponse;
use itertools::Itertools as _;
use logging::{debug_with_peers, warn_with_peers};
use scc::HashMap as SccHashMap;
use signer::Signer;
use ssz::H256;
use std_ext::ArcExt as _;
use tracing::instrument;
use types::{
    combined::BeaconState,
    config::Config,
    phase0::primitives::{Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::{BeaconNodeApi as _, PtcDuties},
    beacon_nodes::BeaconNodes,
    local_beacon_node::ptc_duties_at_slot,
    misc::RequestedIndices,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PTCMember {
    pub public_key: PublicKeyBytes,
    pub validator_index: ValidatorIndex,
}

pub struct OwnPTCMembers {
    signer: Arc<Signer>,
    members: SccHashMap<(H256, Slot), Arc<[PTCMember]>>,
    requested: RequestedIndices,
}

impl OwnPTCMembers {
    pub fn new(signer: Arc<Signer>) -> Self {
        Self {
            signer,
            members: SccHashMap::new(),
            requested: RequestedIndices::default(),
        }
    }

    // Members cached for other keys would miss added keys and fail signing on removed ones.
    async fn discard_for_other_keys(&self, validator_indices: &[ValidatorIndex]) {
        if self.requested.changed(validator_indices).await {
            self.members.clear_async().await;
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    #[instrument(skip_all, level = "debug", fields(slot = slot, dependent_root = ?dependent_root))]
    pub async fn get_or_init_at_slot<P: Preset>(
        &self,
        config: &Config,
        state: &BeaconState<P>,
        dependent_root: H256,
        slot: Slot,
        validator_indices: &[ValidatorIndex],
    ) -> Option<Arc<[PTCMember]>> {
        self.discard_for_other_keys(validator_indices).await;

        if validator_indices.is_empty() {
            return None;
        }

        if let Some(members) = self.members.get_async(&(dependent_root, slot)).await {
            return Some(members.clone_arc());
        }

        let indices = validator_indices.iter().copied().collect::<HashSet<_>>();

        let duties = match ptc_duties_at_slot(config, state, slot, &indices) {
            Ok(duties) => duties,
            Err(error) => {
                warn_with_peers!("failed to compute own PTC members at slot {slot}: {error:?}");
                return None;
            }
        };

        let members = self.members_from_duties(&duties);

        self.members
            .upsert_async((dependent_root, slot), members.clone_arc())
            .await;

        Some(members)
    }

    pub async fn get_at_slot(&self, dependent_root: H256, slot: Slot) -> Option<Arc<[PTCMember]>> {
        self.members
            .get_async(&(dependent_root, slot))
            .await
            .map(|members| members.clone_arc())
    }

    /// Returns the members fetched for each slot, or nothing if cached under `dependent_root`.
    pub async fn init_at_epoch<P: Preset, W: Wait + Sync>(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        epoch: Epoch,
        dependent_root: H256,
        validator_indices: &[ValidatorIndex],
    ) -> Result<HashMap<Slot, Arc<[PTCMember]>>> {
        self.discard_for_other_keys(validator_indices).await;

        let slots = misc::slots_in_epoch::<P>(epoch)?;

        // The built-in node caches one slot at a time, so only a complete epoch needs no fetch.
        let mut cached = true;

        for slot in slots.clone() {
            if self.get_at_slot(dependent_root, slot).await.is_none() {
                cached = false;
                break;
            }
        }

        if cached {
            return Ok(HashMap::new());
        }

        let PtcDuties {
            dependent_root: reported_root,
            duties,
        } = beacon_nodes.ptc_duties(epoch, validator_indices).await?;

        // Cached under the reported root, as another root may or may not be the same shuffling.
        if reported_root != dependent_root {
            debug_with_peers!(
                "PTC duties for epoch {epoch} were reported under dependent root \
                 {reported_root:?} rather than {dependent_root:?}",
            );
        }

        Ok(self
            .record(reported_root, slots, &duties, validator_indices)
            .await)
    }

    async fn record(
        &self,
        dependent_root: H256,
        slots: impl IntoIterator<Item = Slot>,
        duties: &[ValidatorPTCDutyResponse],
        validator_indices: &[ValidatorIndex],
    ) -> HashMap<Slot, Arc<[PTCMember]>> {
        // A node could pair our keys with indices never asked for, each costing a signature.
        let indices = validator_indices.iter().copied().collect::<HashSet<_>>();

        let mut members_by_slot = HashMap::new();

        for slot in slots {
            let members = self.members_from_duties(
                duties
                    .iter()
                    .filter(|duty| duty.slot == slot && indices.contains(&duty.validator_index)),
            );

            self.members
                .upsert_async((dependent_root, slot), members.clone_arc())
                .await;

            members_by_slot.insert(slot, members);
        }

        members_by_slot
    }

    pub async fn prune(&self, up_to_slot: Slot) {
        self.members
            .retain_async(|(_, slot), _| *slot >= up_to_slot)
            .await
    }

    // Members of one slot that the signer holds keys for.
    fn members_from_duties<'duties>(
        &self,
        duties: impl IntoIterator<Item = &'duties ValidatorPTCDutyResponse>,
    ) -> Arc<[PTCMember]> {
        let signer_snapshot = self.signer.load();

        duties
            .into_iter()
            // A duty for a key we do not hold would fail the whole signing batch.
            .filter(|duty| signer_snapshot.has_key(duty.pubkey))
            .map(|duty| PTCMember {
                public_key: duty.pubkey,
                validator_index: duty.validator_index,
            })
            // A validator drawn into several positions still sends a single message.
            .unique_by(|member| member.validator_index)
            .sorted_unstable_by_key(|member| member.validator_index)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::bail;
    use bls::traits::SecretKey as _;
    use helper_functions::{accessors, fork};
    use itertools::Itertools as _;
    use pubkey_cache::PubkeyCache;
    use reqwest::Client;
    use signer::{KeyOrigin, Web3SignerConfig};
    use types::{nonstandard::Phase, preset::Minimal};

    use super::*;

    // The interop Gloas genesis leaves the PTC window empty, so the state is upgraded from Fulu.
    fn gloas_state() -> Result<(Config, BeaconState<Minimal>)> {
        let fulu_config = Config::minimal().start_and_stay_in(Phase::Fulu);
        let config = Config::minimal().start_and_stay_in(Phase::Gloas);
        let pubkey_cache = PubkeyCache::default();
        let (state, _) = factory::min_genesis_state::<Minimal>(&fulu_config, &pubkey_cache)?;

        let BeaconState::Fulu(fulu_state) = state.as_ref() else {
            bail!("genesis state should be Fulu");
        };

        let state = fork::upgrade_to_gloas(&config, &pubkey_cache, fulu_state.as_ref().clone())?;

        Ok((config, state.into()))
    }

    fn signer_with_keys(validator_indices: impl IntoIterator<Item = ValidatorIndex>) -> Signer {
        Signer::new(
            validator_indices.into_iter().map(|validator_index| {
                let secret_key = Arc::new(interop::secret_key(validator_index));

                (
                    secret_key.to_public_key().into(),
                    secret_key,
                    KeyOrigin::External,
                )
            }),
            Client::new(),
            Web3SignerConfig::default(),
            None,
        )
    }

    fn member(validator_index: ValidatorIndex) -> PTCMember {
        PTCMember {
            public_key: interop::secret_key(validator_index).to_public_key().into(),
            validator_index,
        }
    }

    // What is cached for a slot must not depend on whether the state or the duties filled it.
    #[tokio::test]
    async fn members_from_state_match_members_from_duties() -> Result<()> {
        let (config, state) = gloas_state()?;
        let slot = 1;

        let members_in_ptc_order = accessors::get_ptc(&config, &state, slot)?
            .into_iter()
            .unique()
            .collect_vec();

        // A pair out of order in the PTC shows whether the members get sorted.
        let Some((higher, lower)) = members_in_ptc_order
            .iter()
            .copied()
            .tuple_combinations()
            .find(|(first, second)| first > second)
        else {
            bail!("the PTC at slot {slot} should not list its members in ascending order");
        };

        let Some(not_held) = members_in_ptc_order
            .iter()
            .copied()
            .find(|validator_index| ![higher, lower].contains(validator_index))
        else {
            bail!("the PTC at slot {slot} should have at least three distinct members");
        };

        let validator_indices = [higher, lower, not_held];
        let own_members = OwnPTCMembers::new(Arc::new(signer_with_keys([higher, lower])));
        let expected = [member(lower), member(higher)];

        let from_state = own_members
            .get_or_init_at_slot(&config, &state, H256::zero(), slot, &validator_indices)
            .await
            .expect("members should be computed from the state");

        let duties = ptc_duties_at_slot(
            &config,
            &state,
            slot,
            &validator_indices.into_iter().collect(),
        )?;

        let from_duties = own_members.members_from_duties(&duties);

        assert_eq!(from_state.as_ref(), expected);
        assert_eq!(from_duties.as_ref(), expected);

        Ok(())
    }

    // A node repeating a duty, or reporting one for an index never asked about, must not get it
    // signed.
    #[tokio::test]
    async fn only_requested_held_members_are_kept_once() {
        let own_members = OwnPTCMembers::new(Arc::new(signer_with_keys([40, 41, 42])));

        let duty = |validator_index: ValidatorIndex| ValidatorPTCDutyResponse {
            pubkey: member(validator_index).public_key,
            validator_index,
            slot: 1,
        };

        // 42 is held but not requested, 7 is requested but not held.
        let members = own_members
            .record(
                H256::zero(),
                [1],
                &[duty(41), duty(40), duty(41), duty(42), duty(7)],
                &[7, 40, 41],
            )
            .await;

        assert_eq!(
            members.get(&1).map(AsRef::as_ref),
            Some([member(40), member(41)].as_slice()),
        );
    }
}
