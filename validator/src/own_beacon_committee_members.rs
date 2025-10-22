use std::{collections::HashMap, sync::Arc};

use anyhow::Result;
use bls::{PublicKeyBytes, SignatureBytes};
use helper_functions::{accessors, misc, predicates, signing::SignForSingleFork as _};
use logging::warn_with_peers;
use p2p::BeaconCommitteeSubscription;
use signer::{Signer, SigningMessage, SigningTriple};
use std_ext::ArcExt as _;
use tap::{Conv as _, Pipe as _};
use tokio::sync::Mutex;
use typenum::{assert_type, op, True, Unsigned as _, U1, U8};
use types::{
    combined::BeaconState,
    config::Config as ChainConfig,
    phase0::primitives::{CommitteeIndex, Slot, ValidatorIndex},
    preset::Preset,
};

type ComputeInAdvanceSlots = U8;

#[expect(clippy::declare_interior_mutable_const)]
const NONE_MUTEX: Mutex<Option<SlotBeaconCommitteeMembers>> = Mutex::const_new(None);

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

#[derive(Debug)]
struct SlotBeaconCommitteeMembers {
    slot: Slot,
    members: Arc<[BeaconCommitteeMember]>,
}

pub struct OwnBeaconCommitteeMembers {
    config: Arc<ChainConfig>,
    signer: Arc<Signer>,
    slots: [Mutex<Option<SlotBeaconCommitteeMembers>>; ComputeInAdvanceSlots::USIZE],
}

impl OwnBeaconCommitteeMembers {
    pub const fn new(config: Arc<ChainConfig>, signer: Arc<Signer>) -> Self {
        Self {
            config,
            signer,
            slots: [NONE_MUTEX; ComputeInAdvanceSlots::USIZE],
        }
    }

    pub async fn get_or_init_at_slot<P: Preset>(
        &self,
        state: &BeaconState<P>,
        slot: Slot,
    ) -> Option<Arc<[BeaconCommitteeMember]>> {
        let slot_index = slot_index_from_slot(slot);
        let mut slot_members_opt = self.slots[slot_index].lock().await;

        if let Some(slot_members) = slot_members_opt.as_ref() {
            if slot_members.slot == slot {
                return Some(slot_members.members.clone_arc());
            }
        }

        *slot_members_opt = match self.compute_members_at_slot(state, slot).await {
            Ok(members) => members.map(|members| SlotBeaconCommitteeMembers { slot, members }),
            Err(error) => {
                warn_with_peers!(
                    "failed to compute own beacon committee members at slot {slot}: {error:?}"
                );
                None
            }
        };

        slot_members_opt
            .as_ref()
            .map(|slot_members| slot_members.members.clone_arc())
    }

    pub async fn needs_to_compute_members_at_slot(&self, slot: Slot) -> bool {
        let slot_index = slot_index_from_slot(slot);

        if let Some(slot_members) = self.slots[slot_index].lock().await.as_ref() {
            if slot_members.slot == slot {
                return false;
            }
        }

        true
    }

    pub fn slots_to_compute_in_advance(current_slot: Slot) -> impl Iterator<Item = Slot> {
        current_slot..current_slot + ComputeInAdvanceSlots::U64
    }

    async fn compute_members_at_slot<P: Preset>(
        &self,
        state: &BeaconState<P>,
        slot: Slot,
    ) -> Result<Option<Arc<[BeaconCommitteeMember]>>> {
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

        let mut members = vec![];
        let mut triples = vec![];

        let beacon_committees = (0..).zip(accessors::beacon_committees(state, slot)?);
        let epoch = misc::compute_epoch_at_slot::<P>(slot);
        let relative_epoch = accessors::relative_epoch(state, epoch)?;
        let committees_at_slot = accessors::get_committee_count_per_slot(state, relative_epoch);

        for (committee_index, committee) in beacon_committees {
            let committee_size = committee.len();

            for (position_in_committee, validator_index) in committee.into_iter().enumerate() {
                let Some(public_key) = own_public_keys.get(&validator_index).copied() else {
                    continue;
                };

                members.push(BeaconCommitteeMember {
                    public_key,
                    validator_index,
                    committee_index,
                    committee_size,
                    committees_at_slot,
                    position_in_committee,
                    slot,
                    is_aggregator: false,
                    selection_proof: None,
                });

                triples.push(SigningTriple::<P> {
                    message: SigningMessage::AggregationSlot { slot },
                    signing_root: slot.signing_root(&self.config, state),
                    public_key,
                });
            }
        }

        let selection_proofs = signer_snapshot
            .sign_triples_without_slashing_protection(triples, Some(state.into()))
            .await?;

        members
            .into_iter()
            .zip(selection_proofs)
            .map(|(member, selection_proof)| {
                let BeaconCommitteeMember {
                    public_key,
                    validator_index,
                    committee_index,
                    committee_size,
                    committees_at_slot,
                    position_in_committee,
                    slot,
                    ..
                } = member;

                let is_aggregator = predicates::is_aggregator(
                    state,
                    slot,
                    committee_index,
                    selection_proof.into(),
                )?;

                Ok(BeaconCommitteeMember {
                    public_key,
                    validator_index,
                    committee_index,
                    committee_size,
                    committees_at_slot,
                    position_in_committee,
                    slot,
                    is_aggregator,
                    selection_proof: Some(selection_proof.into()),
                })
            })
            .collect::<Result<Vec<_>>>()?
            .conv::<Arc<[_]>>()
            .pipe(Some)
            .pipe(Ok)
    }
}

#[cfg(target_pointer_width = "32")]
use typenum::U32;

#[cfg(target_pointer_width = "64")]
use typenum::U64;

#[cfg(target_pointer_width = "32")]
assert_type!(op!(ComputeInAdvanceSlots < U1 << U32));

#[cfg(target_pointer_width = "64")]
assert_type!(op!(ComputeInAdvanceSlots < U1 << U64));

fn slot_index_from_slot(slot: Slot) -> usize {
    usize::try_from(slot % ComputeInAdvanceSlots::U64).expect(
        "ComputeInAdvanceSlots should always fit in usize due to compile-time assertions above",
    )
}

#[cfg(test)]
mod tests {
    use bls::traits::SecretKey as _;
    use pubkey_cache::PubkeyCache;
    use reqwest::Client;
    use signer::{KeyOrigin, Web3SignerConfig};
    use types::preset::Minimal;

    use super::*;

    #[tokio::test]
    async fn test_computing_own_beacon_committee_members() -> Result<()> {
        // beacon committees at slot 1:
        //
        // committee 0: validators 41, 45,  0, 24
        // committee 1: validators 17, 47, 40, 29
        //
        // beacon committees at slot 2:
        //
        // committee 0: validators 6, 50, 33, 11
        // committee 1: validators 2, 54, 22, 63
        //
        let secret_key_1 = Arc::new(interop::secret_key(40));
        let secret_key_2 = Arc::new(interop::secret_key(41));
        let secret_key_3 = Arc::new(interop::secret_key(42));

        let public_key_1 = secret_key_1.to_public_key().into();
        let public_key_2 = secret_key_2.to_public_key().into();
        let public_key_3 = secret_key_3.to_public_key().into();

        let signer = Arc::new(Signer::new(
            [
                (public_key_1, secret_key_1, KeyOrigin::LocalFileSystem),
                (public_key_2, secret_key_2, KeyOrigin::LocalFileSystem),
                (public_key_3, secret_key_3, KeyOrigin::LocalFileSystem),
            ],
            Client::new(),
            Web3SignerConfig::default(),
            None,
        ));

        let config = Arc::new(ChainConfig::minimal());
        let pubkey_cache = PubkeyCache::default();
        let (state, _) = factory::min_genesis_state::<Minimal>(&config, &pubkey_cache)?;

        let own_members = OwnBeaconCommitteeMembers::new(config, signer);

        assert!(own_members.needs_to_compute_members_at_slot(1).await);

        let members_at_slot_1 = own_members
            .get_or_init_at_slot(&state, 1)
            .await
            .expect("there should be 2 own beacon committee members at slot 1");

        assert_eq!(
            members_at_slot_1.as_ref(),
            [
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

        assert!(!own_members.needs_to_compute_members_at_slot(1).await);

        for slot in OwnBeaconCommitteeMembers::slots_to_compute_in_advance(2) {
            assert!(own_members.needs_to_compute_members_at_slot(slot).await);
        }

        let members_at_slot_2 = own_members.get_or_init_at_slot(&state, 2).await;

        assert_eq!(
            members_at_slot_2
                .expect("should return empty collection")
                .as_ref(),
            [],
        );

        assert!(!own_members.needs_to_compute_members_at_slot(2).await);

        Ok(())
    }
}
