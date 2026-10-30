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
use logging::{info_with_peers, warn_with_peers};
use typenum::Unsigned as _;
use types::{
    altair::{consts::PARTICIPATION_FLAG_WEIGHTS, primitives::ParticipationFlags},
    combined::BeaconState,
    config::Config,
    gloas::containers::Attestation as GloasAttestation,
    nonstandard::AttestationEpoch,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        containers::{AttestationData, PendingAttestation},
        primitives::ValidatorIndex,
    },
    preset::Preset,
    traits::BeaconState as _,
};

use crate::attestation_agg_pool::{
    conversion::{compute_on_chain_aggregate, convert_to_electra_attestation},
    types::PoolAttestation,
};

pub struct PackOutcome<A> {
    pub attestations: Vec<A>,
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
    ) -> PackOutcome<PoolAttestation<P>> {
        let mut previous_epoch_participation = self.previous_epoch_participation.clone();
        let mut current_epoch_participation = self.current_epoch_participation.clone();

        // TODO(Grandine Team): Storing candidates in a map allows for quick lookups during
        //                      aggregation without having to manage an index, but prevents the
        //                      algorithm from packing multiple aggregates with the same
        //                      `AttestationKey`.

        // Candidates are keyed by `AttestationKey` (`AttestationData` + committee index), not by
        // `AttestationData` alone. Post-Electra, `data.index` no longer identifies the committee
        // (Gloas even uses it for the payload presence vote), so aggregates from all committees of
        // a slot share the same `AttestationData` and keying by it alone would keep only one
        // committee per slot.
        //
        // Use `BTreeMap` to make attestation packing deterministic for snapshot testing.
        let mut candidates = BTreeMap::new();

        info_with_peers!("attestation packer start packing attestations greedily");

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
                .into_grouping_map_by(|(aggregate, _)| aggregate.key())
                .max_by_key(|_, (_, added_weight)| *added_weight)
                .into_values()
                .map(|(aggregate, _)| (aggregate.key(), aggregate.clone())),
        );

        let mut candidates = candidates.into_values().collect_vec();

        info_with_peers!("attestation packer candidates count: {}", candidates.len());

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

        info_with_peers!("attestation packer sorted candidates");

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

        info_with_peers!("attestation packer finished packing greedily");

        PackOutcome {
            attestations,
            deadline_reached: self.deadline_reached(),
        }
    }

    #[expect(clippy::too_many_lines)]
    pub fn pack_gloas_attestations_greedily<'a>(
        &self,
        previous_epoch_aggregates: impl IntoIterator<Item = &'a PoolAttestation<P>>,
        current_epoch_aggregates: impl IntoIterator<Item = &'a PoolAttestation<P>>,
    ) -> PackOutcome<GloasAttestation<P>> {
        let mut representatives = BTreeMap::new();

        for attestation in current_epoch_aggregates
            .into_iter()
            .chain(previous_epoch_aggregates)
            .take_while(|_| !self.deadline_reached())
            .filter(|attestation| self.is_valid_for_inclusion(attestation))
        {
            let Ok(weight) = self.added_weight(
                attestation,
                &self.previous_epoch_participation,
                &self.current_epoch_participation,
            ) else {
                continue;
            };
            if weight == 0 {
                continue;
            }
            // Equal scores use the attestation's total ordering, independent of arrival order.
            let candidate = (weight, attestation);
            let representative = representatives
                .entry(attestation.key())
                .or_insert(candidate);
            if candidate > *representative {
                *representative = candidate;
            }
        }

        // shortcut: committee representatives stay fixed, revisit after baseline measurements.
        let mut groups: BTreeMap<AttestationData, Vec<&PoolAttestation<P>>> = BTreeMap::new();
        for (_, attestation) in representatives.into_values() {
            groups
                .entry(attestation.data)
                .or_default()
                .push(attestation);
        }

        let mut previous_participation = self.previous_epoch_participation.clone();
        let mut current_participation = self.current_epoch_participation.clone();
        let mut attestations = Vec::new();

        while attestations.len() < P::MaxAttestationsElectra::USIZE {
            let mut best_group = None;

            for (data, members) in &groups {
                if self.deadline_reached() {
                    return PackOutcome {
                        attestations,
                        deadline_reached: true,
                    };
                }

                // beacon_committee partitions shuffled validators; distinct committees of one
                // slot are disjoint. added_weight checks the committee and bitlist length.
                let Ok(group_weight) = members
                    .iter()
                    .map(|attestation| {
                        self.added_weight(
                            attestation,
                            &previous_participation,
                            &current_participation,
                        )
                    })
                    .sum::<Result<u64>>()
                else {
                    continue;
                };
                // Ties retain the smallest full AttestationData in BTreeMap order.
                if group_weight > 0
                    && best_group
                        .as_ref()
                        .is_none_or(|(_, weight)| group_weight > *weight)
                {
                    best_group = Some((*data, group_weight));
                }
            }

            let Some((data, _)) = best_group else {
                break;
            };

            let members = groups.remove(&data).expect("selected group exists");
            let aggregate = members
                .iter()
                .map(|attestation| convert_to_electra_attestation((*attestation).clone()))
                .collect::<Result<Vec<_>>>()
                .and_then(|members| compute_on_chain_aggregate(members.into_iter()));
            let aggregate = match aggregate {
                Ok(aggregate) => aggregate,
                Err(error) => {
                    warn_with_peers!("unable to construct Gloas aggregate: {error:?}");
                    continue;
                }
            };
            // Commit participation only after construction succeeds, atomically for the group.
            let mut next_previous = previous_participation.clone();
            let mut next_current = current_participation.clone();
            if members
                .iter()
                .try_for_each(|attestation| {
                    self.add_attestation(attestation, &mut next_previous, &mut next_current)
                        .map(|_| ())
                })
                .is_err()
            {
                continue;
            }
            previous_participation = next_previous;
            current_participation = next_current;
            attestations.push(aggregate.into());
        }

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
        // The bid in the state is still the parent block's bid, because the block being packed has
        // not been processed yet, so its slot is the parent block's slot.
        let parent_slot = self
            .state
            .post_gloas()
            .map(|state| state.latest_execution_payload_bid().slot);

        accessors::get_attestation_participation_flags(
            &self.state,
            attestation.data,
            self.state.slot().saturating_sub(attestation.data.slot),
            parent_slot,
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
            accessors::get_attestation_participation_flags(state, data, inclusion_delay, None)?;

        // > Apply flags to all attesting validators
        for attesting_index in attesting_indices {
            let index = usize::try_from(attesting_index)?;
            participation[index] |= participation_flags;
        }
    }

    Ok(participation)
}

#[cfg(test)]
mod gloas_payload_context_tests {
    use bls::{
        AggregateSignature, SecretKey, SecretKeyBytes,
        traits::{SecretKey as _, Signature as _, SignatureBytes as _},
    };
    use helper_functions::{
        signing::SignForSingleFork as _, slot_report::NullSlotReport, verifier::SingleVerifier,
    };
    use pubkey_cache::PubkeyCache;
    use ssz::{BitList, Hc, SszHash as _, SszListMut as _};
    use types::{
        altair::consts::{TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT},
        gloas::{beacon_state::BeaconState as GloasBeaconState, containers::ExecutionRequests},
        phase0::{
            consts::FAR_FUTURE_EPOCH,
            containers::{Checkpoint, Validator},
            primitives::H256,
        },
        preset::{Minimal, SlotsPerHistoricalRoot},
        traits::SszValidatorListMut as _,
    };

    use super::*;

    // A synthetic scoring fixture, not a signed or fully valid chain fixture.
    // Parent block at 100, no block at 101, proposed block at 102.
    fn skipped_slot_state() -> Result<GloasBeaconState<Minimal>> {
        let parent_root = H256::repeat_byte(1);
        let mut state = GloasBeaconState::<Minimal> {
            slot: 102,
            ..GloasBeaconState::default()
        };
        state.latest_block_header.slot = 100;
        state.latest_execution_payload_bid.slot = 100;
        state.latest_execution_payload_bid.block_hash = H256::repeat_byte(2);
        *state.block_roots.mod_index_mut(100) = parent_root;
        *state.block_roots.mod_index_mut(101) = parent_root;
        let epoch_start = misc::compute_start_slot_at_epoch::<Minimal>(
            misc::compute_epoch_at_slot::<Minimal>(101),
        );
        *state.block_roots.mod_index_mut(epoch_start) = H256::repeat_byte(3);

        for _ in 0..64 {
            state.validators.push(Validator {
                effective_balance: 32_000_000_000,
                exit_epoch: FAR_FUTURE_EPOCH,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
                ..Validator::default()
            })?;
            state.balances.push(32_000_000_000)?;
            state.previous_epoch_participation.push(0)?;
            state.current_epoch_participation.push(0)?;
        }

        Ok(state)
    }

    fn packer(state: GloasBeaconState<Minimal>) -> Result<AttestationPacker<Minimal>> {
        AttestationPacker::new(
            Arc::new(Config::minimal().start_and_stay_in(types::nonstandard::Phase::Gloas)),
            Arc::new(BeaconState::Gloas(Hc::new(state))),
            true,
        )
    }

    fn signed_state() -> Result<GloasBeaconState<Minimal>> {
        let mut state = skipped_slot_state()?;
        state.validators = types::gloas::validator_list::ProgressiveValidatorList::default();
        for index in 0..64 {
            state.validators.push(Validator {
                pubkey: secret_key(index).to_public_key().into(),
                effective_balance: 32_000_000_000,
                exit_epoch: FAR_FUTURE_EPOCH,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
                ..Validator::default()
            })?;
        }
        Ok(state)
    }

    fn secret_key(index: u64) -> SecretKey {
        let mut bytes = SecretKeyBytes::default();
        bytes.as_mut()[24..].copy_from_slice(
            &index
                .checked_add(1)
                .expect("small fixture key index")
                .to_be_bytes(),
        );
        bytes.try_into().expect("small nonzero secret key")
    }

    fn signed_candidate(
        packer: &AttestationPacker<Minimal>,
        slot: u64,
        committee_index: u64,
        root: H256,
        vote: u64,
        positions: &[usize],
    ) -> Result<PoolAttestation<Minimal>> {
        let committee = accessors::beacon_committee(&packer.state, slot, committee_index)?;
        let data = AttestationData {
            slot,
            index: vote,
            beacon_block_root: root,
            source: if misc::compute_epoch_at_slot::<Minimal>(slot)
                == accessors::get_current_epoch(&packer.state)
            {
                packer.state.current_justified_checkpoint()
            } else {
                packer.state.previous_justified_checkpoint()
            },
            target: Checkpoint {
                epoch: misc::compute_epoch_at_slot::<Minimal>(slot),
                root: H256::repeat_byte(3),
            },
        };
        let mut aggregation_bits = BitList::new(false, committee.len());
        let mut signature = AggregateSignature::default();
        let indices = committee.into_iter().collect_vec();
        for &position in positions {
            aggregation_bits.set(position, true);
            signature.aggregate_in_place(data.sign(
                &packer.config,
                &packer.state,
                &secret_key(indices[position]),
            ));
        }
        Ok(PoolAttestation {
            aggregation_bits,
            data,
            committee_index,
            signature: signature.into(),
        })
    }

    fn verify_aggregate(
        packer: &AttestationPacker<Minimal>,
        attestation: &GloasAttestation<Minimal>,
    ) -> Result<()> {
        let indexed = helper_functions::gloas::get_indexed_attestation(&packer.state, attestation)?;
        helper_functions::predicates::validate_received_indexed_attestation(
            &packer.config,
            &PubkeyCache::default(),
            &packer.state,
            &indexed,
            SingleVerifier,
        )
    }

    #[test]
    fn mixed_epochs_keep_participation_separate() -> Result<()> {
        let mut state = signed_state()?;
        state.previous_justified_checkpoint = Checkpoint {
            epoch: 10,
            root: H256::repeat_byte(9),
        };
        *state.block_roots.mod_index_mut(88) = H256::repeat_byte(3);
        let packer = packer(state)?;
        let previous = signed_candidate(&packer, 95, 0, H256::repeat_byte(4), 0, &[0, 1, 2, 3])?;
        let current = signed_candidate(&packer, 101, 0, H256::repeat_byte(4), 0, &[0, 1, 2, 3])?;
        let expected = [&previous, &current]
            .into_iter()
            .map(|candidate| {
                packer.added_weight(
                    candidate,
                    &packer.previous_epoch_participation,
                    &packer.current_epoch_participation,
                )
            })
            .sum::<Result<u64>>()?;
        let selected = packer
            .pack_gloas_attestations_greedily([&previous], [&current])
            .attestations;
        assert_eq!(selected.len(), 2);
        assert_eq!(output_weight(&packer, &selected)?, expected);
        for aggregate in &selected {
            verify_aggregate(&packer, aggregate)?;
        }

        // Mark every current-epoch flag as accounted for without suppressing previous-epoch votes.
        let mut packer = packer;
        packer.current_epoch_participation.fill(u8::MAX);
        let selected = packer
            .pack_gloas_attestations_greedily([&previous], [&current])
            .attestations;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].data, previous.data);
        Ok(())
    }

    #[test]
    fn unequal_committee_lengths_preserve_bits_and_signature() -> Result<()> {
        let mut state = signed_state()?;
        state.validators.push(Validator {
            pubkey: secret_key(64).to_public_key().into(),
            effective_balance: 32_000_000_000,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            ..Validator::default()
        })?;
        state.balances.push(32_000_000_000)?;
        state.previous_epoch_participation.push(0)?;
        state.current_epoch_participation.push(0)?;
        let packer = packer(state)?;
        // The last partition receives the remainder when 65 validators form 16 committees.
        let first = signed_candidate(&packer, 103, 0, H256::repeat_byte(4), 0, &[0, 2])?;
        let second = signed_candidate(&packer, 103, 1, H256::repeat_byte(4), 0, &[1, 4])?;
        assert_ne!(first.aggregation_bits.len(), second.aggregation_bits.len());
        let expected = first
            .aggregation_bits
            .iter()
            .chain(second.aggregation_bits.iter())
            .map(|bit| *bit)
            .collect_vec();
        let aggregate = compute_on_chain_aggregate(
            [second, first]
                .into_iter()
                .map(convert_to_electra_attestation)
                .collect::<Result<Vec<_>>>()?
                .into_iter(),
        )?;
        assert_eq!(
            aggregate
                .aggregation_bits
                .iter()
                .map(|bit| *bit)
                .collect_vec(),
            expected
        );
        verify_aggregate(&packer, &aggregate.into())?;
        Ok(())
    }

    #[test]
    fn group_value_ordering_bits_signature_and_marginal_overlap() -> Result<()> {
        let packer = packer(signed_state()?)?;
        // A=3+3 participants beats B=4, even though each A committee loses individually.
        let a0 = signed_candidate(&packer, 101, 0, H256::repeat_byte(4), 0, &[0, 1, 2])?;
        let a1 = signed_candidate(&packer, 101, 1, H256::repeat_byte(4), 0, &[0, 1, 2])?;
        let b = signed_candidate(&packer, 101, 0, H256::repeat_byte(5), 0, &[0, 1, 2, 3])?;
        let duplicate_gain =
            signed_candidate(&packer, 101, 1, H256::repeat_byte(6), 0, &[0, 1, 2])?;
        let candidates = vec![b, a1.clone(), duplicate_gain, a0.clone()];
        let result = packer
            .pack_gloas_attestations_greedily([], &candidates)
            .attestations;
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].data, a0.data);
        assert_eq!(result[1].data.beacon_block_root, H256::repeat_byte(5));
        assert_eq!(
            misc::get_committee_indices::<Minimal>(result[0].committee_bits).collect_vec(),
            vec![0, 1]
        );
        let expected_bits = a0
            .aggregation_bits
            .iter()
            .chain(a1.aggregation_bits.iter())
            .map(|bit| *bit)
            .collect_vec();
        assert_eq!(
            result[0].aggregation_bits.iter().by_vals().collect_vec(),
            expected_bits
        );
        for aggregate in &result {
            verify_aggregate(&packer, aggregate)?;
        }
        let reversed = packer
            .pack_gloas_attestations_greedily([], candidates.iter().rev())
            .attestations;
        assert_eq!(result, reversed);
        Ok(())
    }

    #[test]
    fn payload_votes_stay_separate_and_signature_binds_index() -> Result<()> {
        let packer = packer(signed_state()?)?;
        let empty = signed_candidate(&packer, 101, 0, H256::repeat_byte(1), 0, &[0, 1])?;
        let full = signed_candidate(&packer, 101, 1, H256::repeat_byte(1), 1, &[0, 1])?;
        let result = packer
            .pack_gloas_attestations_greedily([], &[empty, full])
            .attestations;
        assert_eq!(result.len(), 2);
        assert_eq!(
            result.iter().map(|att| att.data.index).collect_vec(),
            vec![0, 1]
        );
        for aggregate in result {
            verify_aggregate(&packer, &aggregate)?;
            let mut corrupted = aggregate;
            corrupted.data.index ^= 1;
            assert!(verify_aggregate(&packer, &corrupted).is_err());
        }
        Ok(())
    }

    #[test]
    fn representatives_consider_candidates_beyond_legacy_capacity() -> Result<()> {
        let packer = packer(signed_state()?)?;
        let low = signed_candidate(&packer, 101, 0, H256::repeat_byte(1), 0, &[0])?;
        let high = signed_candidate(&packer, 101, 0, H256::repeat_byte(1), 0, &[0, 1, 2, 3])?;
        let mut candidates = vec![low; <Minimal as Preset>::MaxAttestations::USIZE];
        candidates.push(high);
        let result = packer
            .pack_gloas_attestations_greedily([], &candidates)
            .attestations;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].aggregation_bits.count_ones(), 4);
        verify_aggregate(&packer, &result[0])
    }

    #[test]
    fn construction_failure_does_not_consume_budget_or_participation() -> Result<()> {
        let packer = packer(signed_state()?)?;
        let mut candidates = Vec::new();
        for slot in [100, 101] {
            for committee in 0..2 {
                for position in 0..4 {
                    candidates.push(signed_candidate(
                        &packer,
                        slot,
                        committee,
                        H256::repeat_byte(u8::try_from(
                            10 + committee * 4 + u64::try_from(position)?,
                        )?),
                        0,
                        &[position],
                    )?);
                }
            }
        }
        let expected = packer
            .pack_gloas_attestations_greedily([], &candidates)
            .attestations;
        assert_eq!(
            expected.len(),
            <Minimal as Preset>::MaxAttestationsElectra::USIZE
        );
        // Highest-scoring group fails signature decoding. Later groups must still fill all slots.
        for committee in 0..2 {
            let mut broken = signed_candidate(
                &packer,
                100,
                committee,
                H256::repeat_byte(1),
                0,
                &[0, 1, 2, 3],
            )?;
            broken.signature = [0_u8; 96].into();
            candidates.push(broken);
        }
        let actual = packer
            .pack_gloas_attestations_greedily([], &candidates)
            .attestations;
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn committee_representatives_are_fixed_and_ties_are_deterministic() -> Result<()> {
        let packer = packer(signed_state()?)?;
        let high = signed_candidate(&packer, 101, 0, H256::repeat_byte(1), 0, &[0, 1, 2])?;
        let initial_best = signed_candidate(&packer, 101, 0, H256::repeat_byte(4), 0, &[0, 1, 2])?;
        let alternative = signed_candidate(&packer, 101, 0, H256::repeat_byte(4), 0, &[3])?;
        let result = packer
            .pack_gloas_attestations_greedily([], &[alternative, initial_best, high.clone()])
            .attestations;
        assert_eq!(result.len(), 1); // Replacing the frozen representative would add validator 3.
        assert_eq!(result[0].data, high.data);
        let left = signed_candidate(&packer, 101, 0, H256::repeat_byte(4), 0, &[0, 1])?;
        let right = signed_candidate(&packer, 101, 0, H256::repeat_byte(4), 0, &[2, 3])?;
        let expected = core::cmp::max(&left, &right);
        let candidates = [left.clone(), right.clone()];
        let result = packer
            .pack_gloas_attestations_greedily([], &candidates)
            .attestations;
        assert_eq!(
            result[0].aggregation_bits.iter().by_vals().collect_vec(),
            expected.aggregation_bits.iter().by_vals().collect_vec()
        );
        assert_eq!(
            result,
            packer
                .pack_gloas_attestations_greedily([], candidates.iter().rev())
                .attestations
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep the signed block-processing scenario together"
    )]
    fn packed_attestations_pass_full_and_empty_block_processing() -> Result<()> {
        use types::{
            combined::BeaconBlock,
            gloas::{consts::BUILDER_INDEX_SELF_BUILD, containers::BeaconBlock as GloasBlock},
        };
        for (full, builder) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut state = signed_state()?;
            if builder {
                state.finalized_checkpoint.epoch = 1;
                state.builders.push(types::gloas::containers::Builder {
                    pubkey: secret_key(64).to_public_key().into(),
                    version: types::gloas::consts::PAYLOAD_BUILDER_VERSION,
                    balance: 32_000_000_000,
                    withdrawable_epoch: FAR_FUTURE_EPOCH,
                    ..Default::default()
                })?;
            }
            state.latest_block_header.slot = 100;
            let root = state.latest_block_header.hash_tree_root();
            *state.block_roots.mod_index_mut(100) = root;
            *state.block_roots.mod_index_mut(101) = root;
            let mut sync_committee = types::altair::containers::SyncCommittee::<Minimal>::default();
            for pubkey in sync_committee.pubkeys.iter_mut() {
                *pubkey = secret_key(0).to_public_key().into();
            }
            state.current_sync_committee = Arc::new(Hc::new(sync_committee));
            state.latest_execution_payload_bid.execution_requests_root =
                ExecutionRequests::<Minimal>::default().hash_tree_root();
            let mut block = GloasBlock::<Minimal> {
                slot: 102,
                parent_root: root,
                ..Default::default()
            };
            block
                .body
                .signed_execution_payload_bid
                .message
                .builder_index = BUILDER_INDEX_SELF_BUILD;
            block.body.signed_execution_payload_bid.signature = bls::SignatureBytes::empty();
            block.body.signed_execution_payload_bid.message.slot = 102;
            block.body.signed_execution_payload_bid.message.block_hash = H256::repeat_byte(4);
            block
                .body
                .signed_execution_payload_bid
                .message
                .parent_block_root = root;
            block
                .body
                .signed_execution_payload_bid
                .message
                .parent_block_hash = if full {
                state.latest_execution_payload_bid.block_hash
            } else {
                state.latest_block_hash
            };
            block.body.sync_aggregate.sync_committee_signature = bls::SignatureBytes::empty();
            let mut scoring_state = state.clone();
            transition_functions::gloas::process_parent_execution_payload(
                &Config::minimal(),
                &PubkeyCache::default(),
                &mut scoring_state,
                block
                    .body
                    .signed_execution_payload_bid
                    .message
                    .parent_block_hash,
                &block.body.parent_execution_requests,
            )?;
            let packer = packer(scoring_state)?;
            if builder {
                let bid = &mut block.body.signed_execution_payload_bid;
                bid.message.builder_index = 0;
                bid.message.value = 1;
                bid.signature = bid
                    .message
                    .sign(&packer.config, &packer.state, &secret_key(64))
                    .into();
            }
            let candidates = [0, 1]
                .into_iter()
                .flat_map(|vote| [0, 1].into_iter().map(move |committee| (vote, committee)))
                .map(|(vote, committee)| {
                    signed_candidate(&packer, 101, committee, root, vote, &[0, 1, 2, 3])
                })
                .collect::<Result<Vec<_>>>()?;
            let result = packer
                .pack_gloas_attestations_greedily([], &candidates)
                .attestations;
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].data.index, u64::from(full));
            let expected_flags = packer.participation_flags(&candidates[usize::from(full) * 2])?;
            let indices =
                helper_functions::gloas::get_indexed_attestation(&packer.state, &result[0])?
                    .attesting_indices;
            block.body.attestations = result.try_into()?;
            let mut processed = BeaconState::Gloas(Hc::new(state));
            // Verify aggregate signatures and all block operations; only RANDAO verification is skipped.
            transition_functions::combined::process_untrusted_block(
                &packer.config,
                &PubkeyCache::default(),
                &mut processed,
                &BeaconBlock::Gloas(Hc::new(block)),
                NullSlotReport,
                true,
            )?;
            let processed = processed.post_gloas().expect("Gloas fixture remains Gloas");
            for index in indices {
                assert_eq!(
                    *processed.current_epoch_participation().get(index)?,
                    expected_flags
                );
            }
        }
        Ok(())
    }

    #[test]
    fn skipped_slot_full_parent_changes_flags_and_added_weight() -> Result<()> {
        compare_parent_contexts(1)?;
        compare_parent_contexts(2)
    }

    fn legacy_final_output(
        packer: &AttestationPacker<Minimal>,
        candidates: &[PoolAttestation<Minimal>],
    ) -> Result<Vec<GloasAttestation<Minimal>>> {
        // Mirror the producer's first-seen data order and post-construction limit.
        let selected = packer
            .pack_proposable_attestations_greedily([], candidates)
            .attestations;
        let mut groups: Vec<(
            AttestationData,
            Vec<types::electra::containers::Attestation<Minimal>>,
        )> = Vec::new();
        for candidate in selected {
            let converted = convert_to_electra_attestation(candidate)?;
            if let Some((_, members)) = groups.iter_mut().find(|(data, _)| *data == converted.data)
            {
                if members
                    .iter()
                    .all(|member| member.committee_bits != converted.committee_bits)
                {
                    members.push(converted);
                }
            } else {
                groups.push((converted.data, vec![converted]));
            }
        }
        Ok(groups
            .into_iter()
            .filter_map(|(_, members)| compute_on_chain_aggregate(members.into_iter()).ok())
            .take(<Minimal as Preset>::MaxAttestationsElectra::USIZE)
            .map(Into::into)
            .collect())
    }

    fn output_weight(
        packer: &AttestationPacker<Minimal>,
        output: &[GloasAttestation<Minimal>],
    ) -> Result<u64> {
        let mut previous_participation = packer.previous_epoch_participation.clone();
        let mut current_participation = packer.current_epoch_participation.clone();
        let base = get_base_reward_per_increment(&packer.state)?;
        let parent_slot = packer
            .state
            .post_gloas()
            .expect("Gloas scoring fixture")
            .latest_execution_payload_bid()
            .slot;
        let mut weight = 0_u64;
        for aggregate in output {
            let participation =
                if aggregate.data.target.epoch == accessors::get_current_epoch(&packer.state) {
                    &mut current_participation
                } else {
                    &mut previous_participation
                };
            let flags = accessors::get_attestation_participation_flags(
                &packer.state,
                aggregate.data,
                packer
                    .state
                    .slot()
                    .checked_sub(aggregate.data.slot)
                    .expect("included attestation precedes proposal"),
                Some(parent_slot),
            )?;
            let indices =
                helper_functions::gloas::get_indexed_attestation(&packer.state, aggregate)?
                    .attesting_indices;
            for index in indices {
                let validator_participation = &mut participation[usize::try_from(index)?];
                for (flag, flag_weight) in PARTICIPATION_FLAG_WEIGHTS {
                    if flags.get_bit(flag) && !validator_participation.get_bit(flag) {
                        let reward = flag_weight
                            .checked_mul(get_base_reward(&packer.state, index, base)?)
                            .expect("fixture reward fits u64");
                        weight = weight
                            .checked_add(reward)
                            .expect("fixture total reward fits u64");
                    }
                }
                *validator_participation |= flags;
            }
        }
        Ok(weight)
    }

    #[test]
    #[ignore = "manual synthetic timing comparison; not a production latency benchmark"]
    #[expect(clippy::print_stdout, reason = "Manual benchmark reports measurements")]
    fn compare_gloas_baseline_quality_and_time() -> Result<()> {
        use std::time::Instant;
        let packer = packer(signed_state()?)?;
        for count in [32, 512, 4096] {
            let mut candidates = Vec::new();
            for group in 0..count / 2 {
                let slot = 96 + group % 6;
                let start = usize::try_from((group / 6) % 2 * 2)?;
                for committee in 0..2 {
                    candidates.push(signed_candidate(
                        &packer,
                        slot,
                        committee,
                        H256::from_low_u64_be(1000 + group),
                        0,
                        &[start, start + 1],
                    )?);
                }
            }
            // Warm committee and balance caches equally; fixture/signature generation is not timed.
            drop(legacy_final_output(&packer, &candidates)?);
            drop(packer.pack_gloas_attestations_greedily([], &candidates));
            let mut old_times = Vec::new();
            let mut new_times = Vec::new();
            let mut old = Vec::new();
            let mut new = Vec::new();
            for _ in 0..5 {
                let started = Instant::now();
                old = legacy_final_output(&packer, &candidates)?;
                old_times.push(started.elapsed().as_micros());
                let started = Instant::now();
                new = packer
                    .pack_gloas_attestations_greedily([], &candidates)
                    .attestations;
                new_times.push(started.elapsed().as_micros());
            }
            for aggregate in old.iter().chain(&new) {
                verify_aggregate(&packer, aggregate)?;
            }
            assert!(new.len() <= <Minimal as Preset>::MaxAttestationsElectra::USIZE);
            println!(
                "synthetic Minimal/64 validators candidates={count}: legacy aggregates={} weight={} time_us={old_times:?}; Gloas aggregates={} weight={} time_us={new_times:?}; both times include construction",
                old.len(),
                output_weight(&packer, &old)?,
                new.len(),
                output_weight(&packer, &new)?
            );
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep the scoring-context controls together"
    )]
    fn compare_parent_contexts(inclusion_delay: u64) -> Result<()> {
        let mut state = skipped_slot_state()?;
        state.slot = 101_u64
            .checked_add(inclusion_delay)
            .expect("small fixture delay");
        let requests = ExecutionRequests::<Minimal>::default();
        state.latest_execution_payload_bid.execution_requests_root = requests.hash_tree_root();
        let before = packer(state.clone())?;
        let committee = accessors::beacon_committee(&before.state, 101, 0)?;
        assert!(committee.len() > 0);
        let attestation = PoolAttestation {
            aggregation_bits: BitList::new(true, committee.len()),
            data: AttestationData {
                slot: 101,
                beacon_block_root: H256::repeat_byte(1),
                source: state.current_justified_checkpoint,
                target: Checkpoint {
                    epoch: misc::compute_epoch_at_slot::<Minimal>(101),
                    root: H256::repeat_byte(3),
                },
                ..AttestationData::default()
            },
            committee_index: 0,
            signature: bls::AggregateSignatureBytes::default(),
        };
        assert!(!helper_functions::predicates::is_attestation_same_slot(
            &before.state,
            &attestation.data,
        )?);

        let mut full_state = state.clone();
        // Model the EMPTY branch's early return with an unchanged state. This
        // unit test does not execute process_parent_execution_payload.
        let empty_state = state.clone();

        transition_functions::gloas::apply_parent_execution_payload(
            &Config::minimal(),
            &PubkeyCache::default(),
            &mut full_state,
            &requests,
        )?;
        let availability_index = 100 % SlotsPerHistoricalRoot::<Minimal>::USIZE;
        assert!(
            !state
                .execution_payload_availability
                .get(availability_index)
                .expect("availability index is within the history window")
        );
        assert!(
            full_state
                .execution_payload_availability
                .get(availability_index)
                .expect("availability index is within the history window")
        );
        assert!(
            !empty_state
                .execution_payload_availability
                .get(availability_index)
                .expect("availability index is within the history window")
        );

        let full = packer(full_state)?;
        let empty = packer(empty_state)?;
        let mut availability_only = state;
        availability_only
            .execution_payload_availability
            .set(availability_index, true);
        let availability_only = packer(availability_only)?;
        let base_reward_per_increment = get_base_reward_per_increment(&before.state)?;
        let expected_head_weight = committee
            .into_iter()
            .map(|index| {
                get_base_reward(&before.state, index, base_reward_per_increment).map(|reward| {
                    reward
                        .checked_mul(TIMELY_HEAD_WEIGHT)
                        .expect("fixture head reward fits u64")
                })
            })
            .sum::<Result<u64>>()?;
        assert!(expected_head_weight > 0);
        let head_flag = 1 << TIMELY_HEAD_FLAG_INDEX;

        for payload_vote in [0, 1] {
            let mut candidate = attestation.clone();
            candidate.data.index = payload_vote;
            let score = |packer: &AttestationPacker<Minimal>| {
                packer.added_weight(
                    &candidate,
                    &packer.previous_epoch_participation,
                    &packer.current_epoch_participation,
                )
            };
            let before_flags = before.participation_flags(&candidate)?;
            let full_flags = full.participation_flags(&candidate)?;
            let timely = inclusion_delay == 1;
            assert_eq!(
                before_flags ^ full_flags,
                if timely { head_flag } else { 0 }
            );
            assert_eq!(
                before_flags.get_bit(TIMELY_HEAD_FLAG_INDEX),
                timely && payload_vote == 0
            );
            assert_eq!(
                full_flags.get_bit(TIMELY_HEAD_FLAG_INDEX),
                timely && payload_vote == 1
            );
            assert_eq!(
                full_flags,
                availability_only.participation_flags(&candidate)?
            );
            assert_eq!(score(&full)?, score(&availability_only)?);
            assert_eq!(before_flags, empty.participation_flags(&candidate)?);
            assert_eq!(score(&before)?, score(&empty)?);
            if !timely {
                assert_eq!(score(&before)?, score(&full)?);
            } else if payload_vote == 0 {
                assert_eq!(
                    score(&before)?,
                    score(&full)?
                        .checked_add(expected_head_weight)
                        .expect("fixture score fits u64")
                );
            } else {
                assert_eq!(
                    score(&full)?,
                    score(&before)?
                        .checked_add(expected_head_weight)
                        .expect("fixture score fits u64")
                );
            }
            assert_eq!(candidate.data.index, payload_vote);
        }

        Ok(())
    }
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
        pack_outcome: &PackOutcome<PoolAttestation<P>>,
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
