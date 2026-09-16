use core::ops::Range;
use std::sync::Arc;

use anyhow::{Result, ensure};
use arithmetic::UsizeExt as _;
use block_producer::BlockProducer;
use bls::{PublicKeyBytes, SignatureBytes};
use clock::Tick;
use eth1_api::ApiController;
use fork_choice_control::{EventChannels, Wait};
use helper_functions::misc::{compute_epoch_at_slot, compute_start_slot_at_epoch};
use operation_pools::{AttestationAggPool, PayloadAttestationAggPool, SyncCommitteeAggPool};
use ssz::BitVector;
use tokio::sync::Mutex;
use typenum::{True, U1, U8, Unsigned as _, assert_type, op};
use types::{
    altair::consts::SyncCommitteeSubnetCount,
    config::Config as ChainConfig,
    phase0::primitives::{Epoch, H256, Slot, UnixSeconds, ValidatorIndex},
    preset::{Preset, SyncSubcommitteeSize},
};

use crate::{
    own_beacon_committee_members::OwnBeaconCommitteeMembers,
    own_proposer_duties::OwnProposerDuties, own_ptc_members::OwnPTCMembers,
    own_sync_committee_members::OwnSyncCommitteeMembers,
    own_validator_indices::OwnValidatorIndices, remote_beacon_nodes::RemoteBeaconNodes,
};

type ComputeInAdvanceSlots = U8;

#[must_use]
pub const fn slots_to_compute_in_advance(current_slot: Slot) -> Range<Slot> {
    current_slot..current_slot.saturating_add(ComputeInAdvanceSlots::U64)
}

pub fn slots_by_epoch<P: Preset>(slots: Range<Slot>) -> impl Iterator<Item = (Epoch, Range<Slot>)> {
    let first = compute_epoch_at_slot::<P>(slots.start);
    let last = compute_epoch_at_slot::<P>(slots.end.saturating_sub(1));

    (first..=last).filter_map(move |epoch| {
        let start = compute_start_slot_at_epoch::<P>(epoch).max(slots.start);
        let end = compute_start_slot_at_epoch::<P>(epoch.saturating_add(1)).min(slots.end);

        (start < end).then_some((epoch, start..end))
    })
}

/// The validator indices a cache was filled for; a key imported at runtime changes the set.
#[derive(Default)]
pub struct RequestedIndices(Mutex<Arc<[ValidatorIndex]>>);

impl RequestedIndices {
    pub async fn changed(&self, validator_indices: &[ValidatorIndex]) -> bool {
        let mut requested = self.0.lock().await;

        if **requested == *validator_indices {
            return false;
        }

        *requested = validator_indices.into();
        true
    }
}

pub fn subnets_from_sync_committee_indices<P: Preset>(
    indices: impl IntoIterator<Item = usize>,
) -> Result<BitVector<SyncCommitteeSubnetCount>> {
    let mut subnets = BitVector::default();

    for index in indices {
        // Positions come from a remote beacon node and `BitVector::set` panics outside the vector.
        ensure!(
            index < P::SyncCommitteeSize::USIZE,
            "beacon node reported sync committee position {index}, \
             which is outside a committee of {}",
            P::SyncCommitteeSize::USIZE,
        );

        subnets.set(index.div_typenum::<SyncSubcommitteeSize<P>>(), true);
    }

    Ok(subnets)
}

/// The validator's own duties, cached across slots and refreshed by the tasks it spawns.
pub struct OwnDuties {
    /// Shared with the Validator API through [`ChainSource`].
    pub validator_indices: Arc<OwnValidatorIndices>,
    pub beacon_committee_members: OwnBeaconCommitteeMembers,
    pub proposer_duties: OwnProposerDuties,
    pub ptc_members: OwnPTCMembers,
    pub sync_committee_members: OwnSyncCommitteeMembers,
}

/// Where duties are performed and chain facts are read from.
pub struct ChainSource<P: Preset, W: Wait> {
    pub chain_config: Arc<ChainConfig>,
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
    /// Shared with the Validator API.
    pub own_validator_indices: Arc<OwnValidatorIndices>,
    pub chain: Chain<P, W>,
}

/// The built-in beacon node, or under `vc` the nodes given with `--beacon-node-urls`.
pub enum Chain<P: Preset, W: Wait> {
    Local(Arc<LocalChain<P, W>>),
    Remote(Arc<RemoteBeaconNodes>),
}

/// The built-in beacon node's handles duties are performed through.
pub struct LocalChain<P: Preset, W: Wait> {
    pub controller: ApiController<P, W>,
    pub block_producer: Arc<BlockProducer<P, W>>,
    pub attestation_agg_pool: Arc<AttestationAggPool<P, W>>,
    pub sync_committee_agg_pool: Arc<SyncCommitteeAggPool<P, W>>,
    pub payload_attestation_agg_pool: Arc<PayloadAttestationAggPool<P, W>>,
    pub event_channels: Arc<EventChannels<P>>,
}

impl<P: Preset, W: Wait> ChainSource<P, W> {
    pub fn slot(&self) -> Result<Slot> {
        match &self.chain {
            Chain::Local(local) => Ok(local.controller.slot()),
            Chain::Remote(_) => Ok(Tick::current::<P>(&self.chain_config, self.genesis_time)?.slot),
        }
    }

    /// The built-in beacon node, when duties may be performed against it.
    #[must_use]
    pub const fn local(&self) -> Option<&Arc<LocalChain<P, W>>> {
        match &self.chain {
            Chain::Local(local) => Some(local),
            Chain::Remote(_) => None,
        }
    }

    #[must_use]
    pub fn controller(&self) -> Option<&ApiController<P, W>> {
        self.local().map(|local| &local.controller)
    }

    #[must_use]
    pub fn block_producer(&self) -> Option<&Arc<BlockProducer<P, W>>> {
        self.local().map(|local| &local.block_producer)
    }

    #[must_use]
    pub fn attestation_agg_pool(&self) -> Option<&Arc<AttestationAggPool<P, W>>> {
        self.local().map(|local| &local.attestation_agg_pool)
    }

    #[must_use]
    pub fn sync_committee_agg_pool(&self) -> Option<&Arc<SyncCommitteeAggPool<P, W>>> {
        self.local().map(|local| &local.sync_committee_agg_pool)
    }

    #[must_use]
    pub fn payload_attestation_agg_pool(&self) -> Option<&Arc<PayloadAttestationAggPool<P, W>>> {
        self.local()
            .map(|local| &local.payload_attestation_agg_pool)
    }

    #[must_use]
    pub fn event_channels(&self) -> Option<&Arc<EventChannels<P>>> {
        self.local().map(|local| &local.event_channels)
    }

    #[must_use]
    pub const fn remote_beacon_nodes(&self) -> Option<&Arc<RemoteBeaconNodes>> {
        match &self.chain {
            Chain::Local(_) => None,
            Chain::Remote(remote_beacon_nodes) => Some(remote_beacon_nodes),
        }
    }

    /// Whether duties may be performed against the built-in beacon node.
    #[must_use]
    pub const fn uses_local_node(&self) -> bool {
        matches!(self.chain, Chain::Local(_))
    }
}

#[expect(clippy::struct_field_names)]
pub struct Aggregator {
    pub aggregator_index: ValidatorIndex,
    pub position_in_committee: usize,
    pub public_key: PublicKeyBytes,
    pub selection_proof: SignatureBytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SyncCommitteeMember {
    pub validator_index: ValidatorIndex,
    pub public_key: PublicKeyBytes,
    pub subnets: BitVector<SyncCommitteeSubnetCount>,
}

#[cfg(target_pointer_width = "32")]
use typenum::U32;

#[cfg(target_pointer_width = "64")]
use typenum::U64;

#[cfg(target_pointer_width = "32")]
assert_type!(op!(ComputeInAdvanceSlots < U1 << U32));

#[cfg(target_pointer_width = "64")]
assert_type!(op!(ComputeInAdvanceSlots < U1 << U64));

#[cfg(test)]
mod tests {
    use types::preset::Minimal;

    use super::*;

    #[test]
    fn slots_by_epoch_yields_nothing_for_an_empty_range() {
        assert!(grouped(0..0).is_empty());
        assert!(grouped(9..9).is_empty());
    }

    #[test]
    fn slots_by_epoch_keeps_a_range_inside_one_epoch_whole() {
        assert_eq!(grouped(3..7), [(0, 3..7)]);
        assert_eq!(grouped(8..16), [(1, 8..16)]);
    }

    #[test]
    fn slots_by_epoch_splits_a_range_at_epoch_boundaries() {
        assert_eq!(grouped(6..19), [(0, 6..8), (1, 8..16), (2, 16..19)]);
    }

    #[test]
    fn slots_by_epoch_groups_the_slots_computed_in_advance() {
        assert_eq!(
            grouped(slots_to_compute_in_advance(5)),
            [(0, 5..8), (1, 8..13)]
        );
    }

    // Under the minimal preset a sync committee holds 32 members across 4 subnets, so each
    // subcommittee spans 8 positions.
    #[test]
    fn a_position_maps_to_the_subnet_of_its_subcommittee() -> Result<()> {
        assert_eq!(subnets(&[0])?, [true, false, false, false]);
        assert_eq!(subnets(&[7])?, [true, false, false, false]);
        assert_eq!(subnets(&[8])?, [false, true, false, false]);
        assert_eq!(subnets(&[31])?, [false, false, false, true]);

        Ok(())
    }

    #[test]
    fn a_validator_in_several_subcommittees_joins_every_subnet() -> Result<()> {
        assert_eq!(subnets(&[3, 3])?, [true, false, false, false]);
        assert_eq!(subnets(&[3, 24])?, [true, false, false, true]);

        Ok(())
    }

    #[test]
    fn no_position_means_no_subnet() -> Result<()> {
        assert_eq!(subnets(&[])?, [false, false, false, false]);

        Ok(())
    }

    #[test]
    fn a_position_outside_the_committee_is_rejected() {
        subnets(&[32]).expect_err("position 32 is outside a committee of 32");
        subnets(&[usize::MAX]).expect_err("position usize::MAX is outside a committee of 32");
    }

    fn subnets(indices: &[usize]) -> Result<Vec<bool>> {
        subnets_from_sync_committee_indices::<Minimal>(indices.iter().copied())
            .map(|subnets| subnets.into_iter().collect())
    }

    fn grouped(slots: Range<Slot>) -> Vec<(Epoch, Range<Slot>)> {
        slots_by_epoch::<Minimal>(slots).collect()
    }
}
