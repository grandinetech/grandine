use core::marker::PhantomData;
use std::{
    cmp::min,
    collections::{btree_map::BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};

use anyhow::{anyhow, bail, Context, Result};
use bit_field::BitField as _;
use clock::Tick;
use good_lp::{
    default_solver, solvers::highs::highs, solvers::highs::HighsParallelType, variable, variables,
    Expression, Solution, SolverModel,
};
use helper_functions::{
    accessors::{self, get_base_reward, get_base_reward_per_increment},
    misc,
};
use itertools::{izip, Itertools as _};
use log::info;
use rayon::prelude::*;
use ssz::ContiguousList;
use tap::Pipe as _;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
// use types::nonstandard::RelativeEpoch
use types::{
    altair::{consts::PARTICIPATION_FLAG_WEIGHTS, primitives::ParticipationFlags},
    combined::BeaconState,
    config::Config,
    nonstandard::{AttestationEpoch, RelativeEpoch},
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        containers::{Attestation, PendingAttestation},
        primitives::{ValidatorIndex, H256},
    },
    preset::Preset,
    traits::BeaconState as _,
};

// TODO(Grandine Team): Consider rewriting the algorithm to take validators' effective balances into
//                      account. They are currently ignored. This has a negligible effect in typical
//                      networks because most validators have over 32 ETH.

pub struct PackOutcome<P: Preset> {
    pub attestations: ContiguousList<Attestation<P>, P::MaxAttestations>,
    pub deadline_reached: bool,
}

// The phantom type parameter is needed to prevent the impl below from causing `E0207`.
// `S` could theoretically implement both `BeaconState<Minimal>` and `BeaconState<Mainnet>`,
// making the impl overlap with itself.
pub struct AttestationPacker<P: Preset> {
    config: Arc<Config>,
    head_block_root: H256,
    state: Arc<BeaconState<P>>,
    previous_epoch_participation: Vec<ParticipationFlags>,
    current_epoch_participation: Vec<ParticipationFlags>,
    ignore_deadline: bool,
    phantom: PhantomData<P>,
}

impl<P: Preset> AttestationPacker<P> {
    pub fn new(
        config: Arc<Config>,
        head_block_root: H256,
        state: Arc<BeaconState<P>>,
        ignore_deadline: bool,
    ) -> Result<Self> {
        let previous_epoch_participation =
            compute_epoch_participation(&state, AttestationEpoch::Previous)?;

        let current_epoch_participation =
            compute_epoch_participation(&state, AttestationEpoch::Current)?;

        Ok(Self {
            config,
            head_block_root,
            state,
            previous_epoch_participation,
            current_epoch_participation,
            ignore_deadline,
            phantom: PhantomData,
        })
    }

    pub fn pack_proposable_attestations_greedily<'a>(
        &self,
        previous_epoch_aggregates: impl IntoIterator<Item = &'a Attestation<P>>,
        current_epoch_aggregates: impl IntoIterator<Item = &'a Attestation<P>>,
    ) -> PackOutcome<P> {
        let start_time = Instant::now();

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
        .pipe(ContiguousList::try_from_iter)
        .expect(
            "the call to Iterator::take limits the number \
             of attestations to P::MaxAttestations::USIZE",
        );

        // Picking the best attestations is a variation of the set packing problem, which is
        // NP-complete. See:
        // - <https://en.wikipedia.org/wiki/Set_packing>
        // - <https://cstheory.stackexchange.com/questions/21448/set-packing-with-maximum-coverage-objective>
        // We use a greedy algorithm.
        // let attestations = core::iter::from_fn(move || {
        //     // If time runs out, pack attestations as is,
        //     // without trying to find the best ones anymore.
        //     if !self.deadline_reached() {
        //         candidates.sort_by_cached_key(|attestation| {
        //             self.added_weight(
        //                 attestation,
        //                 &previous_epoch_participation,
        //                 &current_epoch_participation,
        //             )
        //             .ok()
        //         });
        //     }

        //     let attestation = candidates.pop()?;

        //     self.add_attestation(
        //         &attestation,
        //         &mut previous_epoch_participation,
        //         &mut current_epoch_participation,
        //     )
        //     .unwrap_or_default()
        //     .then_some(attestation)
        // })
        // .take(P::MaxAttestations::USIZE)
        // .pipe(ContiguousList::try_from_iter)
        // .expect(
        //     "the call to Iterator::take limits the number \
        //      of attestations to P::MaxAttestations::USIZE",
        // );

        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        //println!(
        //    "Greedy packing took: {}.{:03} seconds and deadline_reached() value is: {}",
        //    elapsed_time.as_secs(),
        //    elapsed_time.subsec_millis(),
        //    self.deadline_reached()
        //);
        info!(
            "Greedy packing took: {}.{:03} seconds and deadline_reached() value is: {}",
            elapsed_time.as_secs(),
            elapsed_time.subsec_millis(),
            self.deadline_reached()
        );

        PackOutcome {
            attestations,
            deadline_reached: self.deadline_reached(),
        }
    }

    pub fn pack_proposable_attestations_dynamically<'a>(
        &self,
        previous_epoch_aggregates: impl IntoIterator<Item = &'a Attestation<P>>,
        current_epoch_aggregates: impl IntoIterator<Item = &'a Attestation<P>>,
    ) -> PackOutcome<P> {
        let start_time = Instant::now();

        let mut previous_epoch_participation = self.previous_epoch_participation.clone();
        let mut current_epoch_participation = self.current_epoch_participation.clone();

        let mut candidates: Vec<_> = current_epoch_aggregates
            .into_iter()
            .chain(previous_epoch_aggregates)
            .filter(|aggregate| self.is_valid_for_inclusion(aggregate))
            .map(|aggregate| {
                let added_weight = self
                    .better_added_weight(
                        aggregate,
                        &previous_epoch_participation,
                        &current_epoch_participation,
                    )
                    .unwrap_or_default();
                (aggregate, added_weight)
            })
            .filter(|(_, added_weight)| *added_weight > 0)
            .collect();

        candidates.sort_by_cached_key(|(aggregate, _)| aggregate.data);

        // let mut result: Vec<Vec<_>> = Vec::<Vec<_>>::new();

        let mut candidate_data_aggregate: Vec<_> = candidates
            .into_iter()
            .map(|(aggregate, _)| (aggregate.data, aggregate.clone()))
            .collect();

        let mut grouped_aggregates: Vec<Vec<Attestation<P>>> = Vec::new();

        // it seems that this sort helps with speed (somehow it increases performance by 30%), So I am not going to delete it
        // as it might have something to do with integer programming solver, I am going to leave it for the future
        let mut ind = 0;
        for (key, group) in &candidate_data_aggregate
            .into_iter()
            .group_by(|(data, _)| data.clone())
        {
            grouped_aggregates.push(group.map(|(data, aggregate)| aggregate).collect::<Vec<_>>());
        }

        let different_data_count = grouped_aggregates.len();

        let (choices, choice_values): (Vec<_>, Vec<_>) = (0..different_data_count)
            .into_par_iter()
            .map(|index| {
                let mut vec_choices = Vec::new();
                let mut vec_values = Vec::new();
                vec_choices.push(Vec::new()); // for zero attestations only choice is nothing
                vec_values.push(0);
                let mut best_weight = 0;
                match self.select_one_attestation_greedily(&grouped_aggregates[index]) {
                    Ok((one_vec, one_weight)) => {
                        best_weight = one_weight;
                        vec_choices.push(one_vec);
                        vec_values.push(one_weight);
                    }
                    _ => assert!(false),
                }
                for sz in 2..=grouped_aggregates[index].len() {
                    if self.deadline_reached() {
                        break;
                    }
                    let mut improved = false;
                    match self.select_max_cover_attestation_integer_programming(
                        &grouped_aggregates[index],
                        sz,
                    ) {
                        Err(e) => {} // should only happen when there is an time-out
                        Ok((choices, weight)) => {
                            if weight > best_weight {
                                assert!(choices.len() == sz);
                                vec_choices.push(choices);
                                vec_values.push(weight);
                                best_weight = weight;
                                improved = true;
                            }
                        }
                    }
                    if !improved {
                        break;
                    }
                }
                assert!(vec_choices.len() == vec_values.len());
                (vec_choices, vec_values)
            })
            .unzip();

        let mut dp = vec![vec![0; P::MaxAttestations::USIZE + 1]; different_data_count + 1];
        let mut prev = vec![vec![0; P::MaxAttestations::USIZE + 1]; different_data_count + 1];
        let mut reached =
            vec![vec![false; P::MaxAttestations::USIZE + 1]; different_data_count + 1];

        reached[0][0] = true;

        for groups_analyzed in 0..different_data_count {
            for att_selected in 0..=P::MaxAttestations::USIZE {
                for new_att_selected in 0..min(choices[groups_analyzed].len(), att_selected + 1) {
                    let value_of_new_att = choice_values[groups_analyzed][new_att_selected];
                    let previously_had_attestations = att_selected - new_att_selected;
                    if reached[groups_analyzed][previously_had_attestations]
                        && (dp[groups_analyzed + 1][att_selected]
                            <= dp[groups_analyzed][previously_had_attestations] + value_of_new_att)
                    {
                        dp[groups_analyzed + 1][att_selected] =
                            dp[groups_analyzed][previously_had_attestations] + value_of_new_att;
                        prev[groups_analyzed + 1][att_selected] = previously_had_attestations;
                        reached[groups_analyzed + 1][att_selected] = true;
                    }
                }
            }
        }

        let mut att_selected = 0;
        for i in 0..=P::MaxAttestations::USIZE {
            if dp[different_data_count][i] > dp[different_data_count][att_selected] {
                att_selected = i;
            }
        }

        let mut attestations = Vec::new();
        for groups_analyzed in (1..=different_data_count).rev() {
            let new_att_selected = att_selected - prev[groups_analyzed][att_selected];
            for choice in &choices[groups_analyzed - 1][new_att_selected] {
                attestations.push(choice.clone());
            }
            att_selected = prev[groups_analyzed][att_selected];
        }
        assert!(att_selected == 0 || self.deadline_reached());

        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        //println!(
        //    "Dynamic algorithm packing took: {}.{:03} seconds and deadline_reached() value is: {}",
        //    elapsed_time.as_secs(),
        //    elapsed_time.subsec_millis(),
        //    self.deadline_reached()
        //);
        info!(
            "Dynamic algorithm packing took: {}.{:03} seconds and deadline_reached() value is: {}",
            elapsed_time.as_secs(),
            elapsed_time.subsec_millis(),
            self.deadline_reached()
        );

        PackOutcome {
            attestations: attestations
                .into_iter()
                .pipe(ContiguousList::try_from_iter)
                .expect(
                    "the call to Iterator::take limits the number \
                 of attestations to P::MaxAttestations::USIZE",
                ),
            deadline_reached: self.deadline_reached(),
        }
    }

    fn select_max_cover_attestation_integer_programming(
        &self,
        attestations: &Vec<Attestation<P>>,
        max_count: usize,
    ) -> Result<(Vec<Attestation<P>>, u64)> {
        variables! {
            vars:
        }

        let attestation_count = attestations.len();
        let useless_var = vars.add(variable().integer().min(0).max(0));

        let x: Vec<_> = (0..attestation_count)
            .map(|_| vars.add(variable().binary()))
            .collect();

        let mut x_sum = useless_var - useless_var;
        for i in 0..attestation_count {
            x_sum = x_sum + x[i];
        }

        let mut y = Vec::new();
        let mut weights = Vec::new();

        let mut val_ind_and_epoch_to_y_ind = HashMap::new();
        let mut attestations_containing_validator = Vec::new();
        let mut validator_epochs = Vec::new();

        let (mut attestations_in_previous_epoch, mut attestations_in_current_epoch) = (0, 0);

        for (i, attestation) in attestations.iter().enumerate() {
            let attestation_epoch = self.attestation_epoch(attestation)?;
            match &attestation_epoch {
                AttestationEpoch::Previous => attestations_in_previous_epoch += 1,
                AttestationEpoch::Current => attestations_in_current_epoch += 1,
            }
            let participation_flags = self.participation_flags(attestation)?;
            let base_reward_per_increment = get_base_reward_per_increment(&self.state);
            for validator_index in self.attesting_indices(&attestation)?.into_iter() {
                let index = usize::try_from(validator_index)?;

                let epoch_participation = match attestation_epoch {
                    AttestationEpoch::Previous => self.previous_epoch_participation[index],
                    AttestationEpoch::Current => self.current_epoch_participation[index],
                };

                let mut useless_validator = false;
                if !val_ind_and_epoch_to_y_ind.contains_key(&(attestation_epoch, validator_index)) {
                    let combined_weight_for_validator = PARTICIPATION_FLAG_WEIGHTS
                        .iter()
                        .filter(|(flag_index, _)| {
                            participation_flags.get_bit(*flag_index)
                                && !epoch_participation.get_bit(*flag_index)
                        })
                        .map(|(_, weight)| {
                            weight
                                * get_base_reward(
                                    &self.state,
                                    validator_index,
                                    base_reward_per_increment,
                                )
                                .unwrap_or(0)
                        })
                        .sum::<u64>();

                    if combined_weight_for_validator > 0 {
                        val_ind_and_epoch_to_y_ind
                            .insert((attestation_epoch, validator_index), y.len());
                        y.push(vars.add(variable().binary()));
                        attestations_containing_validator.push(Vec::new());
                        validator_epochs.push(attestation_epoch);
                        weights.push(combined_weight_for_validator);
                    } else {
                        useless_validator = true;
                    }
                }
                if !useless_validator {
                    attestations_containing_validator[*val_ind_and_epoch_to_y_ind
                        .get(&(attestation_epoch, validator_index))
                        .unwrap()]
                    .push(i);
                }
            }
        }
        let mut validator_in_every_attestation = Vec::new();
        for i in 0..y.len() {
            let in_all = match validator_epochs[i] {
                AttestationEpoch::Previous => {
                    attestations_containing_validator[i].len() == attestations_in_previous_epoch
                }
                AttestationEpoch::Current => {
                    attestations_containing_validator[i].len() == attestations_in_current_epoch
                }
            };
            validator_in_every_attestation.push(in_all);
        }

        assert!(weights.len() == y.len());

        let mut objective = useless_var - useless_var;

        let mut answer_value = 0;
        for i in 0..y.len() {
            if !validator_in_every_attestation[i] {
                objective += y[i] * (weights[i] as i32);
            } else {
                answer_value += weights[i];
            }
        }

        let mut problem = vars.maximise(objective).using(highs);
        problem = problem.with(x_sum.eq(max_count as i32));

        for (i, yi) in y.iter().enumerate() {
            if !validator_in_every_attestation[i] {
                let mut validator_expression = useless_var - useless_var;
                for ind in &attestations_containing_validator[i] {
                    validator_expression = validator_expression + x[*ind];
                }
                validator_expression = validator_expression - yi;
                problem = problem.with(validator_expression.geq(0 as i32));
            }
        }

        let mut selected_attestations = Vec::new();

        problem = problem.set_parallel(HighsParallelType::Off);
        problem = problem.set_time_limit(1.0); // currently set to 1 second, later on it should be dynamical based on remaining time
        let solution = problem.solve()?;

        let mut previous_epoch_participation = self.previous_epoch_participation.clone();
        let mut current_epoch_participation = self.current_epoch_participation.clone();
        for i in 0..attestation_count {
            if solution.value(x[i]).abs() > 0.5 {
                selected_attestations.push(attestations[i].clone());
            }
        }

        for i in 0..y.len() {
            if !validator_in_every_attestation[i] && solution.value(y[i]).abs() > 0.5 {
                answer_value += weights[i];
            }
        }
        if selected_attestations.len() != max_count {
            bail!("Can not pack attestations in require time");
        }
        assert!(selected_attestations.len() == max_count);

        Ok((selected_attestations, answer_value))
    }

    fn select_one_attestation_greedily(
        &self,
        attestations: &Vec<Attestation<P>>,
    ) -> Result<(Vec<Attestation<P>>, u64)> {
        let mut weights = Vec::new();
        for i in 0..attestations.len() {
            let weight = self.better_added_weight(
                &attestations[i],
                &self.previous_epoch_participation,
                &self.current_epoch_participation,
            )?;
            weights.push(weight);
        }
        let mut best_id = 0;
        let mut best_weight = 0;
        for i in 0..attestations.len() {
            if weights[i] > best_weight {
                best_weight = weights[i];
                best_id = i;
            }
        }

        Ok((vec![attestations[best_id].clone()], best_weight))
    }

    fn select_max_cover_attestations(
        &self,
        mut attestations: Vec<Attestation<P>>,
        max_count: usize,
    ) -> Result<(Vec<Attestation<P>>, u64)> {
        let mut value = 0;
        let mut selected_attestations = Vec::new();

        let mut previous_epoch_participation = self.previous_epoch_participation.clone();
        let mut current_epoch_participation = self.current_epoch_participation.clone();

        for _ in 0..max_count {
            attestations.sort_by_cached_key(|attestation| {
                self.added_weight(
                    attestation,
                    &previous_epoch_participation,
                    &current_epoch_participation,
                )
                .ok()
            });

            let attestation = match attestations.pop() {
                None => bail!("I don't know what to do"),
                Some(att) => att,
            };

            let added_value = self.added_weight(
                &attestation,
                &previous_epoch_participation,
                &current_epoch_participation,
            )?;

            if added_value == 0 {
                return Err(anyhow!("Failed to increase cover"))
                    .context("Can not add more attestations without duplication");
            }

            let _unused = self.add_attestation(
                &attestation,
                &mut previous_epoch_participation,
                &mut current_epoch_participation,
            );

            selected_attestations.push(attestation);
            value += added_value;
        }

        Ok((selected_attestations, value))
    }

    #[must_use]
    pub fn should_update_current_participation(&self, head_block_root: H256) -> bool {
        head_block_root != self.head_block_root && !self.deadline_reached()
    }

    pub fn update_current_participation(
        &mut self,
        head_block_root: H256,
        state: Arc<BeaconState<P>>,
    ) -> Result<()> {
        self.head_block_root = head_block_root;
        self.state = state;
        self.previous_epoch_participation =
            compute_epoch_participation(&self.state, AttestationEpoch::Previous)?;
        self.current_epoch_participation =
            compute_epoch_participation(&self.state, AttestationEpoch::Current)?;
        Ok(())
    }

    fn is_valid_for_inclusion(&self, attestation: &Attestation<P>) -> bool {
        let low_slot = attestation.data.slot + P::MIN_ATTESTATION_INCLUSION_DELAY.get();
        let high_slot = attestation.data.slot + P::SlotsPerEpoch::U64;

        if !(low_slot..=high_slot).contains(&self.state.slot()) {
            return false;
        }

        let expected_justified_checkpoint = match self.attestation_epoch(attestation) {
            Ok(AttestationEpoch::Previous) => self.state.previous_justified_checkpoint(),
            Ok(AttestationEpoch::Current) => self.state.current_justified_checkpoint(),
            Err(_) => return false,
        };

        attestation.data.source.root == expected_justified_checkpoint.root
    }

    // this seems to cause 30 % increase in runtime, so it is not used in greedy and may be removed from optimal solution (depending on comparison)
    fn better_added_weight(
        &self,
        attestation: &Attestation<P>,
        previous_epoch_participation: &[ParticipationFlags],
        current_epoch_participation: &[ParticipationFlags],
    ) -> Result<u64> {
        let attestation_epoch = self.attestation_epoch(attestation)?;
        let participation_flags = self.participation_flags(attestation)?;

        let base_reward_per_increment = get_base_reward_per_increment(&self.state);

        let mut proposer_reward_numerator = 0;
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
                        weight
                            * get_base_reward(
                                &self.state,
                                validator_index,
                                base_reward_per_increment,
                            )
                            .unwrap_or(0)
                    })
                    .sum::<u64>();

                Ok(combined_weight_for_validator)
            })
            .sum()
    }

    fn added_weight(
        &self,
        attestation: &Attestation<P>,
        previous_epoch_participation: &[ParticipationFlags],
        current_epoch_participation: &[ParticipationFlags],
    ) -> Result<u64> {
        let attestation_epoch = self.attestation_epoch(attestation)?;
        let participation_flags = self.participation_flags(attestation)?;

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
                    .map(|(_, weight)| weight)
                    .sum::<u64>();

                Ok(combined_weight_for_validator)
            })
            .sum()
    }

    fn add_attestation(
        &self,
        attestation: &Attestation<P>,
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

    fn attestation_epoch(&self, attestation: &Attestation<P>) -> Result<AttestationEpoch> {
        accessors::attestation_epoch(&self.state, attestation.data.target.epoch)
    }

    fn deadline_reached(&self) -> bool {
        if self.ignore_deadline {
            return false;
        }

        let result = Tick::current(&self.config, self.state.genesis_time());

        let Ok(tick) = result else {
            return true;
        };

        tick.is_start_of_slot()
    }

    fn participation_flags(&self, attestation: &Attestation<P>) -> Result<ParticipationFlags> {
        accessors::get_attestation_participation_flags(
            &self.state,
            attestation.data,
            self.state.slot() - attestation.data.slot,
        )
    }

    fn attesting_indices<'a>(
        &'a self,
        attestation: &'a Attestation<P>,
    ) -> Result<impl Iterator<Item = ValidatorIndex> + 'a> {
        accessors::get_attesting_indices(
            &self.state,
            attestation.data,
            &attestation.aggregation_bits,
        )
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

        let attesting_indices =
            accessors::get_attesting_indices(state, data, aggregation_bits)?.collect_vec();

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
mod tests {
    use std::collections::hash_map::{Entry as HashMapEntry, HashMap};

    use eth2_cache_utils::{goerli, holesky};
    use ssz::BitList;
    use std_ext::ArcExt as _;
    use transition_functions::unphased;
    use types::{config::Config, phase0::containers::AttestationData, preset::Mainnet};

    use super::*;

    type BitListMap<P> =
        HashMap<AttestationData, BitList<<P as Preset>::MaxValidatorsPerCommittee>>;

    fn compute_total_reward<P: Preset>(
        packer: &AttestationPacker<P>,
        pack_outcome: &PackOutcome<P>,
    ) -> Result<u64> {
        let mut previous_epoch_participation =
            compute_epoch_participation(&packer.state, AttestationEpoch::Previous)?;
        let mut current_epoch_participation =
            compute_epoch_participation(&packer.state, AttestationEpoch::Current)?;

        let mut ans = 0;

        for attestation in pack_outcome.attestations.clone().into_iter() {
            let weight = packer.better_added_weight(
                &attestation,
                &previous_epoch_participation,
                &current_epoch_participation,
            )?;
            ans += weight;
            let _unused = packer.add_attestation(
                &attestation,
                &mut previous_epoch_participation,
                &mut current_epoch_participation,
            );
        }
        Ok(ans)
    }

    fn print_out_attestations<P: Preset>(
        packer: &AttestationPacker<P>,
        pack_outcome: &PackOutcome<P>,
    ) -> Result<()> {
        let mut previous_epoch_participation =
            compute_epoch_participation(&packer.state, AttestationEpoch::Previous)?;
        let mut current_epoch_participation =
            compute_epoch_participation(&packer.state, AttestationEpoch::Current)?;

        let mut attestation_vec = Vec::new();
        for attestation in &pack_outcome.attestations {
            attestation_vec.push(attestation.clone());
        }

        attestation_vec.sort_by_cached_key(|attestation| attestation.data);

        for attestation in attestation_vec {
            let weight = packer.added_weight(
                &attestation,
                &previous_epoch_participation,
                &current_epoch_participation,
            )?;
            //println!("{:?} with weight {}", attestation.data, weight);
        }
        Ok(())
    }

    #[test]
    fn test_goerli_aggregate_attestation_packing() -> Result<()> {
        let config = Arc::new(Config::goerli());
        let slot = 547_813;
        let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
        let state = goerli::beacon_state(slot, 6);
        let latest_block_root = accessors::latest_block_root(&state);

        let previous_epoch_aggregates = goerli::attestations("aggregate_attestations", epoch - 1);
        let current_epoch_aggregates = goerli::attestations("aggregate_attestations", epoch);

        let _unused = accessors::initialize_shuffled_indices(&state, &previous_epoch_aggregates);
        let _unused = accessors::initialize_shuffled_indices(&state, &current_epoch_aggregates);

        let packer = AttestationPacker::new(
            config.clone_arc(),
            latest_block_root,
            state.clone_arc(),
            true,
        )?;
        let pack_outcome = packer.pack_proposable_attestations_greedily(
            &previous_epoch_aggregates,
            &current_epoch_aggregates,
        );
        //println!(
        //    "Greedy algorithm goerli reward: {}",
        //    compute_total_reward(&packer, &pack_outcome)?
        //);

        let proposable_attestations = pack_outcome.attestations;

        assert_eq!(
            proposable_attestations
                .iter()
                .filter(|attestation| attestation.aggregation_bits.count_ones() > 1)
                .count(),
            60,
            "the packer should include as many attestations that add new votes as possible",
        );

        assert_attestations_are_valid_and_add_new_bits(&config, &state, &proposable_attestations)
    }

    #[test]
    fn test_goerli_aggregate_attestation_packing_dynamically() -> Result<()> {
        let config = Arc::new(Config::goerli());
        let slot = 547_813;
        let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
        let state = goerli::beacon_state(slot, 6);
        let latest_block_root = accessors::latest_block_root(&state);

        let previous_epoch_aggregates = goerli::attestations("aggregate_attestations", epoch - 1);
        let current_epoch_aggregates = goerli::attestations("aggregate_attestations", epoch);

        let _unused = accessors::initialize_shuffled_indices(&state, &previous_epoch_aggregates);
        let _unused = accessors::initialize_shuffled_indices(&state, &current_epoch_aggregates);

        let packer = AttestationPacker::new(
            config.clone_arc(),
            latest_block_root,
            state.clone_arc(),
            true,
        )?;
        let pack_outcome = packer.pack_proposable_attestations_dynamically(
            &previous_epoch_aggregates,
            &current_epoch_aggregates,
        );
        //println!(
        //    "Dynamic algorithm goerli reward: {}",
        //    compute_total_reward(&packer, &pack_outcome)?
        //);

        let proposable_attestations = pack_outcome.attestations;
        assert_eq!(
            proposable_attestations
                .iter()
                .filter(|attestation| attestation.aggregation_bits.count_ones() > 1)
                .count(),
            66,
            "the packer should include as many attestations that add new votes as possible",
        );

        assert_attestations_are_valid_and_add_new_bits(&config, &state, &proposable_attestations)
    }

    #[test]
    fn test_holesky_aggregate_attestation_packing() -> Result<()> {
        let config = Arc::new(Config::holesky());
        let slot = 50_015;
        let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
        let state = holesky::beacon_state(slot, 8);
        let latest_block_root = accessors::latest_block_root(&state);

        let previous_epoch_aggregates = holesky::aggregate_attestations_by_epoch(epoch - 1);
        let current_epoch_aggregates = holesky::aggregate_attestations_by_epoch(epoch);

        let _unused = accessors::initialize_shuffled_indices(&state, &previous_epoch_aggregates);
        let _unused = accessors::initialize_shuffled_indices(&state, &current_epoch_aggregates);

        let start_time = Instant::now();
        let packer = AttestationPacker::new(
            config.clone_arc(),
            latest_block_root,
            state.clone_arc(),
            true,
        )?;

        let pack_outcome = packer.pack_proposable_attestations_greedily(
            &previous_epoch_aggregates,
            &current_epoch_aggregates,
        );
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        //println!(
        //    "Greedy algorithm holesky runtime: {}.{:03} seconds",
        //    elapsed_time.as_secs(),
        //    elapsed_time.subsec_millis()
        //);
        // print_out_attestations(&packer, &pack_outcome);
        //println!(
        //    "Greedy algorithm holesky reward: {}",
        //    compute_total_reward(&packer, &pack_outcome)?
        //);

        let proposable_attestations = pack_outcome.attestations;
        assert_eq!(
            proposable_attestations
                .iter()
                .filter(|attestation| attestation.aggregation_bits.count_ones() > 1)
                .count(),
            128,
            "the packer should include as many attestations that add new votes as possible",
        );

        assert_attestations_are_valid_and_add_new_bits(&config, &state, &proposable_attestations)
    }

    #[test]
    fn test_holesky_dynamic_aggregate_attestation_packing() -> Result<()> {
        let config = Arc::new(Config::holesky());
        let slot = 50_015;
        let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
        let state = holesky::beacon_state(slot, 8);
        let latest_block_root = accessors::latest_block_root(&state);

        let previous_epoch_aggregates = holesky::aggregate_attestations_by_epoch(epoch - 1);
        let current_epoch_aggregates = holesky::aggregate_attestations_by_epoch(epoch);

        let _unused = accessors::initialize_shuffled_indices(&state, &previous_epoch_aggregates);
        let _unused = accessors::initialize_shuffled_indices(&state, &current_epoch_aggregates);

        let start_time = Instant::now();
        let packer = AttestationPacker::new(
            config.clone_arc(),
            latest_block_root,
            state.clone_arc(),
            true,
        )?;

        let pack_outcome = packer.pack_proposable_attestations_dynamically(
            &previous_epoch_aggregates,
            &current_epoch_aggregates,
        );
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        //println!(
        //    "Dynamic algorithm holesky runtime: {}.{:03} seconds",
        //    elapsed_time.as_secs(),
        //    elapsed_time.subsec_millis()
        //);
        // print_out_attestations(&packer, &pack_outcome);
        //println!(
        //    "Dynamic algorithm holesky reward: {}",
        //    compute_total_reward(&packer, &pack_outcome)?
        //);

        let proposable_attestations = pack_outcome.attestations;
        assert_eq!(
            proposable_attestations
                .iter()
                .filter(|attestation| attestation.aggregation_bits.count_ones() > 1)
                .count(),
            128,
            "the packer should include as many attestations that add new votes as possible",
        );

        assert_attestations_are_valid_and_add_new_bits(&config, &state, &proposable_attestations)
    }

    fn assert_attestations_are_valid_and_add_new_bits<'attestations, P: Preset>(
        config: &Config,
        state: &BeaconState<P>,
        attestations: impl IntoIterator<Item = &'attestations Attestation<P>>,
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

            unphased::validate_attestation(config, state, attestation)?;
        }

        Ok(())
    }
}
