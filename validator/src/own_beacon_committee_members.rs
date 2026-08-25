use core::ops::Range;
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use bls::{PublicKeyBytes, SignatureBytes};
use eth1_api::ApiController;
use fork_choice_control::Wait;
use helper_functions::{accessors, misc, predicates, signing::SignForSingleFork as _};
use http_api_utils::ValidatorAttesterDutyResponse;
use itertools::Itertools as _;
use logging::warn_with_peers;
use p2p::BeaconCommitteeSubscription;
use scc::{HashMap as SccHashMap, hash_map::Entry};
use signer::{Signer, SigningMessage, SigningTriple};
use ssz::H256;
use std_ext::ArcExt;
use tracing::instrument;
use types::{
    combined::BeaconState,
    config::Config as ChainConfig,
    nonstandard::ForkInfo,
    phase0::primitives::{CommitteeIndex, Epoch, Slot, ValidatorIndex},
    preset::Preset,
};

use crate::{
    beacon_node_api::{AttesterDuties, BeaconNodeApi as _},
    beacon_nodes::BeaconNodes,
    local_beacon_node::duties_at_slot,
    misc::slots_by_epoch,
};

type MembersBySlot = BTreeMap<Slot, Arc<[BeaconCommitteeMember]>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconCommitteeMember {
    pub public_key: PublicKeyBytes,
    pub validator_index: ValidatorIndex,
    pub committee_index: CommitteeIndex,
    pub committee_size: usize,
    pub committees_at_slot: u64,
    pub position_in_committee: usize,
    pub slot: Slot,
    pub is_aggregator: bool,
    pub selection_proof: Option<SignatureBytes>,
}

impl From<BeaconCommitteeMember> for BeaconCommitteeSubscription {
    fn from(member: BeaconCommitteeMember) -> Self {
        let BeaconCommitteeMember {
            validator_index,
            committee_index,
            committees_at_slot,
            slot,
            is_aggregator,
            ..
        } = member;

        Self {
            validator_index,
            committee_index,
            committees_at_slot,
            slot,
            is_aggregator,
        }
    }
}

pub struct OwnBeaconCommitteeMembers {
    config: Arc<ChainConfig>,
    signer: Arc<Signer>,
    members: SccHashMap<Epoch, (H256, MembersBySlot)>,
}

impl OwnBeaconCommitteeMembers {
    pub fn new(config: Arc<ChainConfig>, signer: Arc<Signer>) -> Self {
        Self {
            config,
            signer,
            members: SccHashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    #[instrument(skip_all, level = "debug", fields(slot = slot))]
    pub async fn get_or_init_at_slot<P: Preset, W: Wait + Sync>(
        &self,
        controller: &ApiController<P, W>,
        beacon_state: Option<&Arc<BeaconState<P>>>,
        slot: Slot,
    ) -> Result<Option<(Arc<[BeaconCommitteeMember]>, bool)>> {
        let dependent_root = match beacon_state {
            Some(state) => controller.attestation_committee_dependent_root_for_slot(state, slot)?,
            None => {
                let epoch = misc::compute_epoch_at_slot::<P>(slot);

                match self.cached_dependent_root(epoch).await {
                    Some(dependent_root) => dependent_root,
                    None => {
                        // Asked of the signer rather than a state, as there is none to ask.
                        if self.signer.load().keys().next().is_some() {
                            warn_with_peers!(
                                "no attester duties were prefetched for slot {slot}, so no \
                                 attestation will be produced; check that the beacon nodes given \
                                 with --beacon-node-urls are reachable",
                            );
                        }

                        return Ok(None);
                    }
                }
            }
        };

        let needs_to_compute = self
            .needs_to_compute_members_at_slot::<P>(dependent_root, slot)
            .await;

        if needs_to_compute && let Some(state) = beacon_state {
            self.init_at_slot(state, dependent_root, slot).await?;
        }

        Ok(self
            .get_at_slot::<P>(slot)
            .await
            .map(|members| (members, needs_to_compute)))
    }

    async fn init_at_slot<P: Preset>(
        &self,
        state: &BeaconState<P>,
        dependent_root: H256,
        slot: Slot,
    ) -> Result<()> {
        let indices = self
            .own_validator_indices(state)
            .into_iter()
            .collect::<HashSet<_>>();

        let duties = tokio::task::block_in_place(|| duties_at_slot(state, slot, &indices))?;

        self.init_from_duties(
            state.into(),
            dependent_root,
            slot..slot.saturating_add(1),
            duties,
        )
        .await
    }

    async fn cached_dependent_root(&self, epoch: Epoch) -> Option<H256> {
        self.members.get_async(&epoch).await.map(|entry| entry.0)
    }

    pub async fn get_at_slot<P: Preset>(&self, slot: Slot) -> Option<Arc<[BeaconCommitteeMember]>> {
        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        self.members
            .get_async(&epoch)
            .await
            .and_then(|entry| entry.1.get(&slot).map(ArcExt::clone_arc))
    }

    pub async fn init_at_slots<P: Preset, W: Wait + Sync>(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        fork_info: ForkInfo<P>,
        slots: Range<Slot>,
        validator_indices: &[ValidatorIndex],
    ) -> Result<()> {
        // Split per epoch because a shuffling, and so a dependent root, covers exactly one.
        for (_, slots) in slots_by_epoch::<P>(slots) {
            let AttesterDuties {
                dependent_root,
                duties,
            } = beacon_nodes
                .attester_duties_at_slots(slots.clone(), validator_indices)
                .await?;

            self.init_from_duties(fork_info, dependent_root, slots, duties)
                .await?;
        }

        Ok(())
    }

    pub fn own_validator_indices<P: Preset>(&self, state: &BeaconState<P>) -> Vec<ValidatorIndex> {
        self.signer
            .load()
            .keys()
            .filter_map(|public_key| accessors::index_of_public_key(state, public_key))
            .sorted()
            .collect()
    }

    pub async fn needs_to_compute_members_at_slot<P: Preset>(
        &self,
        dependent_root: H256,
        slot: Slot,
    ) -> bool {
        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        self.members
            .get_async(&epoch)
            .await
            .is_none_or(|entry| entry.0 != dependent_root || !entry.1.contains_key(&slot))
    }

    async fn slots_to_compute<P: Preset>(
        &self,
        dependent_root: H256,
        slots: Range<Slot>,
    ) -> Option<Range<Slot>> {
        let mut first = None;
        let mut last = None;

        for slot in slots {
            if self
                .needs_to_compute_members_at_slot::<P>(dependent_root, slot)
                .await
            {
                first.get_or_insert(slot);
                last = Some(slot);
            }
        }

        Some(first?..last?.saturating_add(1))
    }

    pub async fn slots_to_compute_at_epoch<P: Preset, W: Wait + Sync>(
        &self,
        beacon_nodes: &BeaconNodes<P, W>,
        epoch: Epoch,
        slots: Range<Slot>,
        validator_index: ValidatorIndex,
    ) -> Result<Option<Range<Slot>>> {
        // The request that fetches the duties reports the dependent root anyway.
        if self.cached_dependent_root(epoch).await.is_none() {
            return Ok(Some(slots));
        }

        let dependent_root = beacon_nodes
            .dependent_root(epoch, Some(validator_index))
            .await?;

        Ok(self.slots_to_compute::<P>(dependent_root, slots).await)
    }

    pub async fn prune<P: Preset>(&self, up_to_slot: Slot) {
        let up_to_epoch = misc::compute_epoch_at_slot::<P>(up_to_slot);

        self.members
            .retain_async(|epoch, _| *epoch >= up_to_epoch)
            .await;
    }

    #[instrument(skip_all, level = "debug", fields(dependent_root = ?dependent_root))]
    async fn init_from_duties<P: Preset>(
        &self,
        fork_info: ForkInfo<P>,
        dependent_root: H256,
        slots: Range<Slot>,
        duties: Vec<ValidatorAttesterDutyResponse>,
    ) -> Result<()> {
        if slots.is_empty() {
            return Ok(());
        }

        let epoch = misc::compute_epoch_at_slot::<P>(slots.start);

        let mut members_by_slot = BTreeMap::<Slot, Vec<BeaconCommitteeMember>>::new();

        for slot in slots {
            if self
                .needs_to_compute_members_at_slot::<P>(dependent_root, slot)
                .await
            {
                // Cached as empty so that a later pass does not mistake "nothing to do" for
                // "not computed yet".
                members_by_slot.insert(slot, vec![]);
            }
        }

        let signer_snapshot = self.signer.load();

        // A duty for a key we do not hold would fail the whole signing batch.
        let mut duties = duties
            .into_iter()
            .filter(|duty| {
                signer_snapshot.has_key(duty.pubkey) && members_by_slot.contains_key(&duty.slot)
            })
            .collect::<Vec<_>>();

        // Members keep the order the committees are laid out in: by committee, then by position
        // within it.
        duties.sort_unstable_by_key(|duty| {
            (
                duty.slot,
                duty.committee_index,
                duty.validator_committee_index,
            )
        });

        let triples = duties
            .iter()
            .map(|duty| SigningTriple::<P> {
                message: SigningMessage::AggregationSlot { slot: duty.slot },
                signing_root: duty
                    .slot
                    .signing_root_from_fork_info(&self.config, fork_info),
                public_key: duty.pubkey,
            })
            .collect::<Vec<_>>();

        let selection_proofs = signer_snapshot
            .sign_triples_without_slashing_protection(triples, Some(fork_info))
            .await?;

        for (duty, selection_proof) in duties.into_iter().zip(selection_proofs) {
            let ValidatorAttesterDutyResponse {
                committee_index,
                committee_length,
                committees_at_slot,
                pubkey,
                slot,
                validator_committee_index,
                validator_index,
            } = duty;

            let selection_proof = SignatureBytes::from(selection_proof);

            // The committee length comes from the duty, so no state lookup is needed.
            let is_aggregator =
                predicates::is_aggregator_from_committee_length(committee_length, selection_proof)?;

            members_by_slot
                .entry(slot)
                .or_default()
                .push(BeaconCommitteeMember {
                    public_key: pubkey,
                    validator_index,
                    committee_index,
                    committee_size: committee_length,
                    committees_at_slot,
                    position_in_committee: validator_committee_index,
                    slot,
                    is_aggregator,
                    selection_proof: Some(selection_proof),
                });
        }

        let members_by_slot = members_by_slot
            .into_iter()
            .map(|(slot, members)| (slot, members.into()))
            .collect::<BTreeMap<_, Arc<[_]>>>();

        // A different root means a different shuffling, so what was cached under the old one no
        // longer applies.
        match self.members.entry_async(epoch).await {
            Entry::Occupied(mut occupied) => {
                if occupied.0 == dependent_root {
                    occupied.1.extend(members_by_slot);
                } else {
                    *occupied.get_mut() = (dependent_root, members_by_slot);
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert_entry((dependent_root, members_by_slot));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bls::traits::SecretKey as _;
    use pubkey_cache::PubkeyCache;
    use reqwest::Client;
    use signer::{KeyOrigin, Web3SignerConfig};
    use types::preset::Minimal;

    use super::*;

    fn own_members_with_keys() -> Result<(OwnBeaconCommitteeMembers, Arc<BeaconState<Minimal>>)> {
        let secret_keys = [40, 41, 42].map(|index| Arc::new(interop::secret_key(index)));

        let signer = Arc::new(Signer::new(
            secret_keys.map(|secret_key| {
                (
                    secret_key.to_public_key().into(),
                    secret_key,
                    KeyOrigin::External,
                )
            }),
            Client::new(),
            Client::new(),
            Web3SignerConfig::default(),
            None,
        ));

        let config = Arc::new(ChainConfig::minimal());
        let pubkey_cache = PubkeyCache::default();
        let (state, _) = factory::min_genesis_state::<Minimal>(&config, &pubkey_cache)?;

        Ok((OwnBeaconCommitteeMembers::new(config, signer), state))
    }

    fn public_key(validator_index: ValidatorIndex) -> PublicKeyBytes {
        interop::secret_key(validator_index).to_public_key().into()
    }

    #[tokio::test]
    async fn test_computing_own_beacon_committee_members() -> Result<()> {
        // beacon committees at slot 1:
        //
        // committee 0: validators 41, 45,  0, 24
        // committee 1: validators 17, 47, 40, 29
        //
        let (own_members, state) = own_members_with_keys()?;
        let public_key_1 = public_key(40);
        let public_key_2 = public_key(41);
        let dependent_root = H256::zero();

        assert_eq!(own_members.own_validator_indices(&state), vec![40, 41, 42]);

        for slot in crate::misc::slots_to_compute_in_advance(1) {
            assert!(
                own_members
                    .needs_to_compute_members_at_slot::<Minimal>(dependent_root, slot)
                    .await
            );
        }

        // Deliberately out of order, to check that members come back committee-major.
        own_members
            .init_from_duties::<Minimal>(
                state.as_ref().into(),
                dependent_root,
                misc::slots_in_epoch::<Minimal>(0)?,
                vec![
                    duty(public_key_1, 40, 1, 2, 1),
                    duty(public_key_2, 41, 0, 0, 1),
                ],
            )
            .await?;

        let members_at_slot_1 = own_members
            .get_at_slot::<Minimal>(1)
            .await
            .expect("there should be 2 own beacon committee members at slot 1");

        assert_eq!(
            *members_at_slot_1,
            vec![
                BeaconCommitteeMember {
                    public_key: public_key_2,
                    validator_index: 41,
                    committee_index: 0,
                    committee_size: 4,
                    committees_at_slot: 2,
                    position_in_committee: 0,
                    slot: 1,
                    is_aggregator: true,
                    selection_proof: members_at_slot_1
                        .first()
                        .expect("there should be 2 own beacon committee members at slot 1")
                        .selection_proof,
                },
                BeaconCommitteeMember {
                    public_key: public_key_1,
                    validator_index: 40,
                    committee_index: 1,
                    committee_size: 4,
                    committees_at_slot: 2,
                    position_in_committee: 2,
                    slot: 1,
                    is_aggregator: true,
                    selection_proof: members_at_slot_1
                        .get(1)
                        .expect("there should be 2 own beacon committee members at slot 1")
                        .selection_proof,
                },
            ],
        );

        // One request covers the epoch, so a slot without duties is cached as empty rather than
        // left looking uncomputed.
        assert_eq!(
            *own_members
                .get_at_slot::<Minimal>(2)
                .await
                .expect("slots without duties are cached as empty"),
            vec![],
        );

        assert_eq!(
            own_members
                .slots_to_compute::<Minimal>(dependent_root, misc::slots_in_epoch::<Minimal>(0)?)
                .await,
            None,
        );

        // Nothing was said about the next epoch.
        assert!(
            own_members
                .needs_to_compute_members_at_slot::<Minimal>(
                    dependent_root,
                    misc::compute_start_slot_at_epoch::<Minimal>(1),
                )
                .await
        );

        Ok(())
    }

    // A different root is a different shuffling, so what was cached under the old one goes.
    #[tokio::test]
    async fn a_changed_dependent_root_replaces_the_epoch() -> Result<()> {
        let (own_members, state) = own_members_with_keys()?;
        let public_key = public_key(41);
        let old_root = H256::repeat_byte(1);
        let new_root = H256::repeat_byte(2);

        for (dependent_root, slot) in [(old_root, 1), (new_root, 2)] {
            own_members
                .init_from_duties::<Minimal>(
                    state.as_ref().into(),
                    dependent_root,
                    slot..slot.saturating_add(1),
                    vec![duty(public_key, 41, 0, 0, slot)],
                )
                .await?;
        }

        assert!(own_members.get_at_slot::<Minimal>(1).await.is_none());
        assert!(own_members.get_at_slot::<Minimal>(2).await.is_some());

        assert!(
            own_members
                .needs_to_compute_members_at_slot::<Minimal>(old_root, 2)
                .await
        );

        assert!(
            !own_members
                .needs_to_compute_members_at_slot::<Minimal>(new_root, 2)
                .await
        );

        Ok(())
    }

    fn duty(
        pubkey: PublicKeyBytes,
        validator_index: ValidatorIndex,
        committee_index: CommitteeIndex,
        validator_committee_index: usize,
        slot: Slot,
    ) -> ValidatorAttesterDutyResponse {
        ValidatorAttesterDutyResponse {
            committee_index,
            committee_length: 4,
            committees_at_slot: 2,
            pubkey,
            slot,
            validator_committee_index,
            validator_index,
        }
    }
}
