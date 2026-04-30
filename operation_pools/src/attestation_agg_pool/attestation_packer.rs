use core::marker::PhantomData;
use std::{collections::btree_map::BTreeMap, sync::Arc};

use anyhow::Result;
use bit_field::BitField as _;
use clock::Tick;
use helper_functions::{
    accessors::{self, get_base_reward, get_base_reward_per_increment},
    misc, phase0,
};
use itertools::Itertools as _;
use typenum::Unsigned as _;
use types::{
    altair::{consts::PARTICIPATION_FLAG_WEIGHTS, primitives::ParticipationFlags},
    combined::BeaconState,
    config::Config,
    nonstandard::AttestationEpoch,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        containers::{AttestationData, PendingAttestation},
        primitives::ValidatorIndex,
    },
    preset::Preset,
    traits::BeaconState as _,
};

use crate::attestation_agg_pool::types::PoolAttestation;

pub struct PackOutcome<P: Preset> {
    pub attestations: Vec<PoolAttestation<P>>,
    pub deadline_reached: bool,
}

// The phantom type parameter is needed to prevent the impl below from causing `E0207`.
// `S` could theoretically implement both `BeaconState<Minimal>` and `BeaconState<Mainnet>`,
// making the impl overlap with itself.
pub struct AttestationPacker<P: Preset> {
    config: Arc<Config>,
    state: Arc<BeaconState<P>>,
    previous_epoch_participation: Vec<ParticipationFlags>,
    current_epoch_participation: Vec<ParticipationFlags>,
    ignore_deadline: bool,
    phantom: PhantomData<P>,
}

impl<P: Preset> AttestationPacker<P> {
    pub fn new(
        config: Arc<Config>,
        state: Arc<BeaconState<P>>,
        ignore_deadline: bool,
    ) -> Result<Self> {
        let previous_epoch_participation =
            compute_epoch_participation(&state, AttestationEpoch::Previous)?;

        let current_epoch_participation =
            compute_epoch_participation(&state, AttestationEpoch::Current)?;

        Ok(Self {
            config,
            state,
            previous_epoch_participation,
            current_epoch_participation,
            ignore_deadline,
            phantom: PhantomData,
        })
    }

    pub fn pack_proposable_attestations_greedily<'a>(
        &self,
        previous_epoch_aggregates: impl IntoIterator<Item = &'a PoolAttestation<P>>,
        current_epoch_aggregates: impl IntoIterator<Item = &'a PoolAttestation<P>>,
    ) -> PackOutcome<P> {
        let mut previous_epoch_participation = self.previous_epoch_participation.clone();
        let mut current_epoch_participation = self.current_epoch_participation.clone();

        // TODO(Grandine Team): Storing candidates in a map allows for quick lookups during
        //                      aggregation without having to manage an index, but prevents the
        //                      algorithm from packing multiple aggregates with the same
        //                      `AttestationData`.

        // Use `BTreeMap` to make attestation packing deterministic for snapshot testing.
        let mut candidates = BTreeMap::new();

        // In general it may be possible to construct better aggregates out of smaller ones, but
        // they must not overlap because aggregating a signature with itself is not idempotent and
        // would require keeping track of aggregation counts rather than bits.
        candidates.extend(
            current_epoch_aggregates
                .into_iter()
                .chain(previous_epoch_aggregates)
                .take_while(|_| !self.deadline_reached())
                .filter(|aggregate| self.is_valid_for_inclusion(aggregate))
                .map(|aggregate| {
                    let added_weight = self
                        .added_weight(
                            aggregate,
                            &previous_epoch_participation,
                            &current_epoch_participation,
                        )
                        .unwrap_or_default();
                    (aggregate, added_weight)
                })
                .filter(|(_, added_weight)| {
                    // Filtering aggregates this way early should have no effect on rewards, but it
                    // may speed up block processing by producing smaller aggregates later.
                    *added_weight > 0
                })
                .into_grouping_map_by(|(aggregate, _)| aggregate.data)
                .max_by_key(|_, (_, added_weight)| *added_weight)
                .into_values()
                .map(|(aggregate, _)| (aggregate.data, aggregate.clone())),
        );

        let mut candidates = candidates.into_values().collect_vec();

        // Picking the best attestations is a variation of the set packing problem, which is
        // NP-complete. See:
        // - <https://en.wikipedia.org/wiki/Set_packing>
        // - <https://cstheory.stackexchange.com/questions/21448/set-packing-with-maximum-coverage-objective>
        // We use a greedy algorithm.

        candidates.sort_by_cached_key(|attestation| {
            self.added_weight(
                attestation,
                &previous_epoch_participation,
                &current_epoch_participation,
            )
            .ok()
        });

        let attestations = core::iter::from_fn(move || {
            let attestation = candidates.pop()?;

            self.add_attestation(
                &attestation,
                &mut previous_epoch_participation,
                &mut current_epoch_participation,
            )
            .unwrap_or_default()
            .then_some(attestation)
        })
        .take(P::MaxAttestations::USIZE)
        .collect();

        PackOutcome {
            attestations,
            deadline_reached: self.deadline_reached(),
        }
    }

    fn is_valid_for_inclusion(&self, attestation: &PoolAttestation<P>) -> bool {
        let low_slot = attestation
            .data
            .slot
            .saturating_add(P::MIN_ATTESTATION_INCLUSION_DELAY.get());

        let high_slot = attestation.data.slot.saturating_add(P::SlotsPerEpoch::U64);

        if !(low_slot..=high_slot).contains(&self.state.slot()) {
            return false;
        }

        let expected_justified_checkpoint = match self.attestation_epoch(attestation) {
            Ok(AttestationEpoch::Previous) => self.state.previous_justified_checkpoint(),
            Ok(AttestationEpoch::Current) => self.state.current_justified_checkpoint(),
            Err(_) => return false,
        };

        // Pre-Electra attestations must not be included in Electra blocks,
        // as this would result in an invalid block due to signature mismatches.
        if self.state.is_post_electra()
            && misc::compute_epoch_at_slot::<P>(attestation.data.slot)
                < self.config.electra_fork_epoch
        {
            return false;
        }

        attestation.data.source.root == expected_justified_checkpoint.root
    }

    fn added_weight(
        &self,
        attestation: &PoolAttestation<P>,
        previous_epoch_participation: &[ParticipationFlags],
        current_epoch_participation: &[ParticipationFlags],
    ) -> Result<u64> {
        let attestation_epoch = self.attestation_epoch(attestation)?;
        let participation_flags = self.participation_flags(attestation)?;
        let base_reward_per_increment = get_base_reward_per_increment(&self.state)?;

        self.attesting_indices(attestation)?
            .map(|validator_index| {
                let index = usize::try_from(validator_index)?;

                let epoch_participation = match attestation_epoch {
                    AttestationEpoch::Previous => previous_epoch_participation[index],
                    AttestationEpoch::Current => current_epoch_participation[index],
                };

                let combined_weight_for_validator = PARTICIPATION_FLAG_WEIGHTS
                    .iter()
                    .filter(|(flag_index, _)| {
                        participation_flags.get_bit(*flag_index)
                            && !epoch_participation.get_bit(*flag_index)
                    })
                    .map(|(_, weight)| {
                        weight.saturating_mul(
                            get_base_reward(
                                &self.state,
                                validator_index,
                                base_reward_per_increment,
                            )
                            .unwrap_or(0),
                        )
                    })
                    .sum::<u64>();

                Ok(combined_weight_for_validator)
            })
            .sum()
    }

    fn add_attestation(
        &self,
        attestation: &PoolAttestation<P>,
        previous_epoch_participation: &mut [ParticipationFlags],
        current_epoch_participation: &mut [ParticipationFlags],
    ) -> Result<bool> {
        let attestation_epoch = self.attestation_epoch(attestation)?;
        let participation_flags = self.participation_flags(attestation)?;

        let mut any_added_participation_flags = false;

        for validator_index in self.attesting_indices(attestation)? {
            let index = usize::try_from(validator_index)?;

            let epoch_participation = match attestation_epoch {
                AttestationEpoch::Previous => &mut previous_epoch_participation[index],
                AttestationEpoch::Current => &mut current_epoch_participation[index],
            };

            any_added_participation_flags |= participation_flags & !*epoch_participation > 0;
            *epoch_participation |= participation_flags;
        }

        Ok(any_added_participation_flags)
    }

    fn attestation_epoch(&self, attestation: &PoolAttestation<P>) -> Result<AttestationEpoch> {
        accessors::attestation_epoch(&self.state, attestation.data.target.epoch)
    }

    fn deadline_reached(&self) -> bool {
        if self.ignore_deadline {
            return false;
        }

        let result = Tick::current::<P>(&self.config, self.state.genesis_time());

        let Ok(tick) = result else {
            return true;
        };

        tick.is_start_of_slot()
    }

    fn participation_flags(&self, attestation: &PoolAttestation<P>) -> Result<ParticipationFlags> {
        accessors::get_attestation_participation_flags(
            &self.state,
            attestation.data,
            self.state.slot().saturating_sub(attestation.data.slot),
        )
    }

    fn attesting_indices<'a>(
        &'a self,
        attestation: &'a PoolAttestation<P>,
    ) -> Result<impl Iterator<Item = ValidatorIndex> + 'a> {
        let data = AttestationData {
            index: attestation.committee_index,
            ..attestation.data
        };

        phase0::get_attesting_indices(&self.state, data, &attestation.aggregation_bits)
    }
}

fn compute_epoch_participation<P: Preset>(
    state: &BeaconState<P>,
    attestation_epoch: AttestationEpoch,
) -> Result<Vec<ParticipationFlags>> {
    if let Some(state) = state.post_altair() {
        let flags = match attestation_epoch {
            AttestationEpoch::Previous => state.previous_epoch_participation(),
            AttestationEpoch::Current => state.current_epoch_participation(),
        };

        return Ok(flags.into_iter().copied().collect());
    }

    match state {
        BeaconState::Phase0(state) => match attestation_epoch {
            AttestationEpoch::Previous => {
                translate_participation(state, &state.previous_epoch_attestations)
            }
            AttestationEpoch::Current => {
                translate_participation(state, &state.current_epoch_attestations)
            }
        },
        _ => unreachable!("beacon state is either post-Altair or Phase 0"),
    }
}

fn translate_participation<'attestations, P: Preset>(
    state: &Phase0BeaconState<P>,
    pending_attestations: impl IntoIterator<Item = &'attestations PendingAttestation<P>>,
) -> Result<Vec<ParticipationFlags>> {
    let mut participation = misc::vec_of_default(state);

    for attestation in pending_attestations {
        let PendingAttestation {
            ref aggregation_bits,
            data,
            inclusion_delay,
            ..
        } = *attestation;

        // TODO(feature/electra): use electra::get_attesting_indices for electra attestations
        let attesting_indices =
            phase0::get_attesting_indices(state, data, aggregation_bits)?.collect_vec();

        // > Translate attestation inclusion info to flag indices
        let participation_flags =
            accessors::get_attestation_participation_flags(state, data, inclusion_delay)?;

        // > Apply flags to all attesting validators
        for attesting_index in attesting_indices {
            let index = usize::try_from(attesting_index)?;
            participation[index] |= participation_flags;
        }
    }

    Ok(participation)
}

#[cfg(test)]
#[cfg(feature = "eth2-cache")]
mod tests {
    use std::collections::hash_map::{Entry as HashMapEntry, HashMap};

    use eth2_cache_utils::{goerli, holesky};
    use pubkey_cache::PubkeyCache;
    use ssz::BitList;
    use std_ext::ArcExt as _;
    use transition_functions::unphased;
    use types::{
        config::Config,
        phase0::containers::{Attestation, AttestationData},
        preset::Mainnet,
    };

    use super::*;

    type BitListMap<P> =
        HashMap<AttestationData, BitList<<P as Preset>::MaxValidatorsPerCommittee>>;

    fn pool_attestations<P: Preset>(attestations: Vec<Attestation<P>>) -> Vec<PoolAttestation<P>> {
        attestations
            .into_iter()
            .map(|attestation| {
                let Attestation {
                    aggregation_bits,
                    data,
                    signature,
                } = attestation;

                PoolAttestation {
                    aggregation_bits,
                    data,
                    committee_index: data.index,
                    signature,
                }
            })
            .collect()
    }

    fn compute_total_reward<P: Preset>(
        packer: &AttestationPacker<P>,
        pack_outcome: &PackOutcome<P>,
    ) -> Result<u64> {
        let mut previous_epoch_participation =
            compute_epoch_participation(&packer.state, AttestationEpoch::Previous)?;
        let mut current_epoch_participation =
            compute_epoch_participation(&packer.state, AttestationEpoch::Current)?;

        let mut total: u64 = 0;

        for attestation in pack_outcome.attestations.clone() {
            let weight = packer.added_weight(
                &attestation,
                &previous_epoch_participation,
                &current_epoch_participation,
            )?;

            total = total.saturating_add(weight);

            let _unused = packer.add_attestation(
                &attestation,
                &mut previous_epoch_participation,
                &mut current_epoch_participation,
            );
        }
        Ok(total)
    }

    #[test]
    #[cfg(feature = "eth2-cache")]
    fn test_goerli_greedy_aggregate_attestation_packing() -> Result<()> {
        let config = Arc::new(Config::goerli());
        let pubkey_cache = PubkeyCache::default();
        let slot = 547_813;
        let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
        let state = goerli::beacon_state(slot, 6);

        // Optimal packing uses the assumption that attestations are sorted by their data (this assumption is fulfilled when values are taken from BTree)
        let previous_epoch_aggregates =
            goerli::attestations_sorted_by_data("aggregate_attestations", epoch - 1);
        let current_epoch_aggregates =
            goerli::attestations_sorted_by_data("aggregate_attestations", epoch);

        let _unused = accessors::initialize_shuffled_indices(&state, &previous_epoch_aggregates);
        let _unused = accessors::initialize_shuffled_indices(&state, &current_epoch_aggregates);
        let previous_epoch_aggregates = pool_attestations(previous_epoch_aggregates);
        let current_epoch_aggregates = pool_attestations(current_epoch_aggregates);

        let packer = AttestationPacker::new(config.clone_arc(), state.clone_arc(), true)?;
        let pack_outcome = packer.pack_proposable_attestations_greedily(
            &previous_epoch_aggregates,
            &current_epoch_aggregates,
        );

        assert_eq!(compute_total_reward(&packer, &pack_outcome)?, 8_308_701_824);

        let proposable_attestations = pack_outcome.attestations;
        assert_eq!(
            proposable_attestations
                .iter()
                .filter(|attestation| attestation.aggregation_bits.count_ones() > 1)
                .count(),
            60,
            "the packer should include as many attestations that add new votes as possible",
        );

        assert_attestations_are_valid_and_add_new_bits(
            &config,
            &pubkey_cache,
            &state,
            &proposable_attestations,
        )
    }

    #[test]
    #[cfg(feature = "eth2-cache")]
    fn test_holesky_greedy_aggregate_attestation_packing() -> Result<()> {
        let config = Arc::new(Config::holesky());
        let pubkey_cache = PubkeyCache::default();
        let slot = 50_015;
        let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
        let state = holesky::beacon_state(slot, 8);

        // Optimal packing uses the assumption that attestations are sorted by their data (this assumption is fulfilled when values are taken from BTree)
        let previous_epoch_aggregates =
            holesky::aggregate_attestations_by_epoch_sorted_by_data(epoch - 1);
        let current_epoch_aggregates =
            holesky::aggregate_attestations_by_epoch_sorted_by_data(epoch);

        let _unused = accessors::initialize_shuffled_indices(&state, &previous_epoch_aggregates);
        let _unused = accessors::initialize_shuffled_indices(&state, &current_epoch_aggregates);
        let previous_epoch_aggregates = pool_attestations(previous_epoch_aggregates);
        let current_epoch_aggregates = pool_attestations(current_epoch_aggregates);

        let packer = AttestationPacker::new(config.clone_arc(), state.clone_arc(), true)?;

        let pack_outcome = packer.pack_proposable_attestations_greedily(
            &previous_epoch_aggregates,
            &current_epoch_aggregates,
        );

        assert_eq!(compute_total_reward(&packer, &pack_outcome)?, 5_250_660_160);

        let proposable_attestations = pack_outcome.attestations;
        assert_eq!(
            proposable_attestations
                .iter()
                .filter(|attestation| attestation.aggregation_bits.count_ones() > 1)
                .count(),
            128,
            "the packer should include as many attestations that add new votes as possible",
        );

        assert_attestations_are_valid_and_add_new_bits(
            &config,
            &pubkey_cache,
            &state,
            &proposable_attestations,
        )
    }

    fn assert_attestations_are_valid_and_add_new_bits<'attestations, P: Preset>(
        config: &Config,
        pubkey_cache: &PubkeyCache,
        state: &BeaconState<P>,
        attestations: impl IntoIterator<Item = &'attestations PoolAttestation<P>>,
    ) -> Result<()> {
        let mut already_added = BitListMap::<P>::new();

        for attestation in attestations {
            let new = &attestation.aggregation_bits;

            match already_added.entry(attestation.data) {
                HashMapEntry::Occupied(occupied) => {
                    let aggregation_bits = occupied.into_mut();
                    let old_bit_count = aggregation_bits.count_ones();
                    *aggregation_bits |= new;
                    let new_bit_count = aggregation_bits.count_ones();

                    assert!(
                        old_bit_count < new_bit_count,
                        "each included attestation should add at least one unique aggregation bit",
                    );
                }
                HashMapEntry::Vacant(vacant) => {
                    vacant.insert(new.clone());
                }
            }

            let attestation = attestation.clone().into_phase0_attestation();
            unphased::validate_attestation(config, pubkey_cache, state, &attestation)?;
        }

        Ok(())
    }
}
