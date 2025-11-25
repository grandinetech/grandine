use core::{cmp::min, marker::PhantomData};
use std::{
    collections::{HashMap, HashSet, btree_map::BTreeMap},
    sync::Arc,
};

use anyhow::{Result, bail};
use bit_field::BitField as _;
use clock::Tick;
use good_lp::{
    Expression, Solution, SolverModel, solvers::highs::HighsParallelType, solvers::highs::highs,
    variable, variables,
};
use helper_functions::{
    accessors::{self, get_base_reward, get_base_reward_per_increment},
    misc, phase0,
};
use itertools::Itertools as _;
use rayon::iter::{
    IndexedParallelIterator as _, IntoParallelIterator as _, IntoParallelRefIterator as _,
    ParallelIterator as _,
};
use ssz::ContiguousList;
use tap::Pipe as _;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    altair::{consts::PARTICIPATION_FLAG_WEIGHTS, primitives::ParticipationFlags},
    combined::BeaconState,
    config::Config,
    nonstandard::AttestationEpoch,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        containers::{Attestation, PendingAttestation},
        primitives::{H256, ValidatorIndex},
    },
    preset::Preset,
    traits::BeaconState as _,
};

/// Constant used to limit number of calls to `select_max_cover_attestation_integer_programming`
/// It is used when we need a lot of aggregates (more than `MAXIMUM_ATTESTATIONS_WITH_SAME_DATA`)
/// to include all validators that signed same attestation data. In that case it could improve performance,
/// while it is unlikely to drastically decrease score.
const MAXIMUM_ATTESTATIONS_WITH_SAME_DATA: usize = 6;

/// Constant used to compute time that integer programming solver can use.
/// Since `good_lp` calls external solvers, there is no way to stop execution if it takes too long.
/// However, one can set time limit for solver. Here it is some fraction of remaining time until deadline.
const TIME_FRACTION_FOR_SUBPROBLEM: f64 = 0.25;

pub struct PackOutcome<P: Preset> {
    pub attestations: ContiguousList<Attestation<P>, P::MaxAttestations>,
    pub deadline_reached: bool,
}

#[derive(Default)]
struct AttestationWeights {
    compressed_validator_indices: Vec<usize>,
    validator_weights: Vec<u64>,
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
        .pipe(ContiguousList::try_from_iter)
        .expect(
            "the call to Iterator::take limits the number \
             of attestations to P::MaxAttestations::USIZE",
        );

        PackOutcome {
            attestations,
            deadline_reached: self.deadline_reached(),
        }
    }

    fn aggregates_grouped_by_data<'a>(
        &self,
        previous_epoch_aggregates: impl IntoIterator<Item = &'a Attestation<P>>,
        current_epoch_aggregates: impl IntoIterator<Item = &'a Attestation<P>>,
    ) -> Vec<Vec<Attestation<P>>> {
        previous_epoch_aggregates
            .into_iter()
            .chain(current_epoch_aggregates)
            .take_while(|_| !self.deadline_reached())
            .filter(|aggregate| self.is_valid_for_inclusion(aggregate))
            .map(|aggregate| (aggregate.data, aggregate))
            .chunk_by(|&(data, _)| data)
            .into_iter()
            .map(|(_, group)| group.map(|(_, y)| y.clone()).collect())
            .collect_vec()
    }

    // this function assumes that every aggregate have same AttestationData
    fn find_attestation_weights(
        &self,
        aggregates: &Vec<Attestation<P>>,
    ) -> Result<Vec<AttestationWeights>> {
        let mut attestation_weights = Vec::new();
        let base_reward_per_increment = get_base_reward_per_increment(&self.state);

        for attestation in aggregates {
            let attestation_epoch = self.attestation_epoch(attestation)?;
            let participation_flags = self.participation_flags(attestation)?;

            let mut compressed_validator_indices = Vec::new();
            let mut validator_weights = Vec::new();
            for validator_index in self.attesting_indices(attestation)? {
                let index = usize::try_from(validator_index)?;
                let epoch_participation = match attestation_epoch {
                    AttestationEpoch::Previous => self.previous_epoch_participation[index],
                    AttestationEpoch::Current => self.current_epoch_participation[index],
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
                compressed_validator_indices.push(index);
                validator_weights.push(combined_weight_for_validator);
            }
            attestation_weights.push(AttestationWeights {
                compressed_validator_indices,
                validator_weights,
            });
        }
        Ok(attestation_weights)
    }

    fn find_optimal_selections(
        &self,
        aggregates: &[Attestation<P>],
        group_weights: &[AttestationWeights],
    ) -> (Vec<Vec<usize>>, Vec<u64>) {
        let mut choices = vec![vec![]];
        let mut values = vec![0];

        let mut best_weight;

        if self.deadline_reached() {
            return (choices, values);
        }

        let maximum_possible_weight = Self::maximum_added_weight(group_weights);

        if self.deadline_reached() {
            return (choices, values);
        }

        let (one_vec, one_weight) =
            Self::select_one_attestation_greedily(aggregates, group_weights);
        best_weight = one_weight;
        choices.push(one_vec);
        values.push(one_weight);

        for number_of_aggregates_to_select in
            2..=min(aggregates.len(), MAXIMUM_ATTESTATIONS_WITH_SAME_DATA)
        {
            if self.deadline_reached() || best_weight == maximum_possible_weight {
                break;
            }

            match self.select_max_cover_attestation_integer_programming(
                aggregates,
                group_weights,
                number_of_aggregates_to_select,
            ) {
                Err(_) => break,
                Ok((attestation_choice, weight)) => {
                    if weight > best_weight {
                        choices.push(attestation_choice);
                        values.push(weight);
                        best_weight = weight;
                    } else {
                        break;
                    }
                }
            }
        }

        (choices, values)
    }

    pub fn pack_proposable_attestations_optimally<'a>(
        &self,
        previous_epoch_aggregates: impl IntoIterator<Item = &'a Attestation<P>>,
        current_epoch_aggregates: impl IntoIterator<Item = &'a Attestation<P>>,
    ) -> PackOutcome<P> {
        let grouped_aggregates =
            self.aggregates_grouped_by_data(previous_epoch_aggregates, current_epoch_aggregates);

        let grouped_aggregates_weights = grouped_aggregates
            .par_iter()
            .map(|aggregates| {
                self.find_attestation_weights(aggregates)
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();

        let different_data_count = grouped_aggregates.len();

        let (choices, choice_values): (Vec<_>, Vec<_>) = grouped_aggregates
            .par_iter()
            .zip(grouped_aggregates_weights.into_par_iter())
            .map(|(agg_group, group_weights)| {
                self.find_optimal_selections(agg_group, &group_weights)
            })
            .unzip();

        let mut best_weight =
            vec![vec![0; P::MaxAttestations::USIZE + 1]; different_data_count + 1];
        let mut prev = vec![vec![0; P::MaxAttestations::USIZE + 1]; different_data_count + 1];
        let mut reachable =
            vec![vec![false; P::MaxAttestations::USIZE + 1]; different_data_count + 1];

        reachable[0][0] = true;

        for groups_analyzed in 0..different_data_count {
            for att_selected in 0..=P::MaxAttestations::USIZE {
                for new_att_selected in 0..min(choices[groups_analyzed].len(), att_selected + 1) {
                    let value_of_new_att = choice_values[groups_analyzed][new_att_selected];
                    let previously_had_attestations = att_selected - new_att_selected;
                    if reachable[groups_analyzed][previously_had_attestations]
                        && (best_weight[groups_analyzed + 1][att_selected]
                            <= best_weight[groups_analyzed][previously_had_attestations]
                                + value_of_new_att)
                    {
                        best_weight[groups_analyzed + 1][att_selected] = best_weight
                            [groups_analyzed][previously_had_attestations]
                            + value_of_new_att;
                        prev[groups_analyzed + 1][att_selected] = previously_had_attestations;
                        reachable[groups_analyzed + 1][att_selected] = true;
                    }
                }
            }
        }

        // att_selected is the minimal number of attestations that reach best weight
        // minimal number is chosen so there wouldn't be attestations that don't add weight
        let mut att_selected = 0;
        for i in 0..=P::MaxAttestations::USIZE {
            if best_weight[different_data_count][i]
                > best_weight[different_data_count][att_selected]
            {
                att_selected = i;
            }
        }

        let mut attestations = Vec::new();
        for groups_analyzed in (1..=different_data_count).rev() {
            let new_att_selected = att_selected - prev[groups_analyzed][att_selected];
            for choice in &choices[groups_analyzed - 1][new_att_selected] {
                attestations.push(grouped_aggregates[groups_analyzed - 1][*choice].clone());
            }
            att_selected = prev[groups_analyzed][att_selected];
        }

        attestations.truncate(P::MaxAttestations::USIZE);

        PackOutcome {
            attestations: attestations.try_into().expect(
                "the call to Vec::truncate limits the number \
                 of attestations to P::MaxAttestations::USIZE",
            ),
            deadline_reached: self.deadline_reached(),
        }
    }

    #[expect(clippy::float_arithmetic)]
    fn f64_values_are_approximately_equal(a: f64, b: f64) -> bool {
        (a - b).abs() < f64::EPSILON
    }

    // This function solves maximum coverage problem by using integer linear programming (https://en.wikipedia.org/wiki/Maximum_coverage_problem)
    // It uses the assumption that all aggregates have the same AttestationData
    #[expect(clippy::too_many_lines)]
    #[expect(clippy::float_arithmetic)]
    fn select_max_cover_attestation_integer_programming(
        &self,
        aggregates: &[Attestation<P>],
        group_weights: &[AttestationWeights],
        selected_aggregates_count: usize,
    ) -> Result<(Vec<usize>, u64)> {
        variables! {
            vars:
        }

        let attestation_count = aggregates.len();

        let mut number_of_aggregates_selected = Expression::with_capacity(attestation_count);
        let is_aggregate_selected: Vec<_> = (0..attestation_count)
            .map(|_| {
                let aggregate_selected = vars.add(variable().binary());
                number_of_aggregates_selected += aggregate_selected;
                aggregate_selected
            })
            .collect();

        let mut is_validator_included_variables = Vec::new();
        let mut validator_weights = Vec::new();

        let mut validator_index_to_validator_included_variable_index = HashMap::new();
        let mut aggregates_containing_validator = Vec::new();

        for (i, group_weight) in group_weights.iter().enumerate() {
            for (validator_index, combined_weight_for_validator) in group_weight
                .compressed_validator_indices
                .iter()
                .zip(group_weight.validator_weights.iter())
            {
                let mut useless_validator = false;
                if let std::collections::hash_map::Entry::Vacant(_) =
                    validator_index_to_validator_included_variable_index.entry(validator_index)
                {
                    if *combined_weight_for_validator > 0 {
                        validator_index_to_validator_included_variable_index
                            .insert(validator_index, is_validator_included_variables.len());
                        is_validator_included_variables.push(vars.add(variable().binary()));
                        aggregates_containing_validator.push(Vec::new());
                        validator_weights.push(combined_weight_for_validator);
                    } else {
                        useless_validator = true;
                    }
                }
                if !useless_validator {
                    aggregates_containing_validator
                        [validator_index_to_validator_included_variable_index[&validator_index]]
                        .push(i);
                }
            }
        }

        // Validators that are in every attestation will be included anyway,
        // thus, some expression for solver can be simplified (it speeds up solver).
        let validator_in_every_aggregate = aggregates_containing_validator
            .iter()
            .map(|agg_containing_val| agg_containing_val.len() == aggregates.len())
            .collect_vec();

        let mut objective = Expression::with_capacity(0);

        let mut answer_value = 0;
        for i in 0..is_validator_included_variables.len() {
            if validator_in_every_aggregate[i] {
                answer_value += validator_weights[i];
            } else {
                // here conversion to i32 is needed, since `good_lp` only support i32 integers
                objective +=
                    is_validator_included_variables[i] * i32::try_from(*validator_weights[i])?;
            }
        }

        let mut problem = vars.maximise(objective).using(highs);
        problem = problem
            .with(number_of_aggregates_selected.eq(i32::try_from(selected_aggregates_count)?));

        for (i, is_validator_included) in is_validator_included_variables.iter().enumerate() {
            if !validator_in_every_aggregate[i] {
                let mut validator_expression = Expression::with_capacity(0);
                for ind in &aggregates_containing_validator[i] {
                    validator_expression += is_aggregate_selected[*ind];
                }
                validator_expression -= is_validator_included;
                problem = problem.with(validator_expression.geq(0));
            }
        }

        let mut selected_aggregates = Vec::new();

        // Here parallelization is unnecessary, since integer programming is called for each different attestation data
        problem = problem.set_parallel(HighsParallelType::Off).set_threads(1);

        problem = problem
            .set_time_limit(self.time_until_deadline_in_seconds()? * TIME_FRACTION_FOR_SUBPROBLEM);

        let solution = problem.solve()?;

        for (i, is_selected) in is_aggregate_selected.iter().enumerate() {
            // Crate `good_lp` represents all variables with floating point, so this checks if binary value is 1.
            if Self::f64_values_are_approximately_equal(solution.value(*is_selected), 1.0) {
                selected_aggregates.push(i);
            }
        }

        if selected_aggregates.len() != selected_aggregates_count {
            bail!("Integer programming returned incomplete solution for attestation packing");
        }

        for i in 0..is_validator_included_variables.len() {
            if !validator_in_every_aggregate[i]
                && Self::f64_values_are_approximately_equal(
                    solution.value(is_validator_included_variables[i]),
                    1.0,
                )
            {
                // In case of incomplete solution, this tests whether validator would actually be included.
                let attestation_was_included =
                    aggregates_containing_validator[i].iter().any(|id| {
                        Self::f64_values_are_approximately_equal(
                            solution.value(is_aggregate_selected[*id]),
                            1.0,
                        )
                    });
                if attestation_was_included {
                    answer_value += validator_weights[i];
                }
            }
        }

        Ok((selected_aggregates, answer_value))
    }

    fn select_one_attestation_greedily(
        attestations: &[Attestation<P>],
        group_weights: &[AttestationWeights],
    ) -> (Vec<usize>, u64) {
        let mut best_id = 0;
        let mut best_weight = 0;
        for (i, group_weight) in group_weights.iter().enumerate().take(attestations.len()) {
            let sum_weight = group_weight.validator_weights.iter().sum::<u64>();
            if sum_weight > best_weight {
                best_weight = sum_weight;
                best_id = i;
            }
        }

        (vec![best_id], best_weight)
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
        attestation: &Attestation<P>,
        previous_epoch_participation: &[ParticipationFlags],
        current_epoch_participation: &[ParticipationFlags],
    ) -> Result<u64> {
        let attestation_epoch = self.attestation_epoch(attestation)?;
        let participation_flags = self.participation_flags(attestation)?;

        let base_reward_per_increment = get_base_reward_per_increment(&self.state);

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

    fn maximum_added_weight(group_weights: &[AttestationWeights]) -> u64 {
        let mut ans = 0;
        let mut counted_validator_indices = HashSet::new();
        for attestation_weight in group_weights {
            for (id, weight) in attestation_weight
                .compressed_validator_indices
                .iter()
                .zip(attestation_weight.validator_weights.iter())
            {
                if counted_validator_indices.insert(id) {
                    ans += weight;
                }
            }
        }

        ans
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

    fn time_until_deadline_in_seconds(&self) -> Result<f64> {
        let (_, remaining_time) =
            clock::next_interval_with_remaining_time(&self.config, self.state.genesis_time())?;
        if self.ignore_deadline {
            Ok(self.config.slot_duration_ms.as_secs_f64())
        } else if self.deadline_reached() {
            Ok(0.0)
        } else {
            Ok(remaining_time.as_secs_f64())
        }
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
        // TODO(feature/electra): use electra::get_attesting_indices for electra attestations
        phase0::get_attesting_indices(&self.state, attestation.data, &attestation.aggregation_bits)
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

        let mut total = 0;

        for attestation in pack_outcome.attestations.clone() {
            let weight = packer.added_weight(
                &attestation,
                &previous_epoch_participation,
                &current_epoch_participation,
            )?;
            total += weight;
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
        let latest_block_root = accessors::latest_block_root(&state);

        // Optimal packing uses the assumption that attestations are sorted by their data (this assumption is fulfilled when values are taken from BTree)
        let previous_epoch_aggregates =
            goerli::attestations_sorted_by_data("aggregate_attestations", epoch - 1);
        let current_epoch_aggregates =
            goerli::attestations_sorted_by_data("aggregate_attestations", epoch);

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
    fn test_goerli_optimal_aggregate_attestation_packing() -> Result<()> {
        let config = Arc::new(Config::goerli());
        let pubkey_cache = PubkeyCache::default();
        let slot = 547_813;
        let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
        let state = goerli::beacon_state(slot, 6);
        let latest_block_root = accessors::latest_block_root(&state);

        // Optimal packing uses the assumption that attestations are sorted by their data (this assumption is fulfilled when values are taken from BTree)
        let previous_epoch_aggregates =
            goerli::attestations_sorted_by_data("aggregate_attestations", epoch - 1);
        let current_epoch_aggregates =
            goerli::attestations_sorted_by_data("aggregate_attestations", epoch);

        let _unused = accessors::initialize_shuffled_indices(&state, &previous_epoch_aggregates);
        let _unused = accessors::initialize_shuffled_indices(&state, &current_epoch_aggregates);

        let packer = AttestationPacker::new(
            config.clone_arc(),
            latest_block_root,
            state.clone_arc(),
            true,
        )?;
        let pack_outcome = packer.pack_proposable_attestations_optimally(
            &previous_epoch_aggregates,
            &current_epoch_aggregates,
        );

        // value computed without optimizations
        assert_eq!(compute_total_reward(&packer, &pack_outcome)?, 8_323_509_056);

        let proposable_attestations = pack_outcome.attestations;
        assert_eq!(
            proposable_attestations
                .iter()
                .filter(|attestation| attestation.aggregation_bits.count_ones() > 1)
                .count(),
            66,
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
        let latest_block_root = accessors::latest_block_root(&state);

        // Optimal packing uses the assumption that attestations are sorted by their data (this assumption is fulfilled when values are taken from BTree)
        let previous_epoch_aggregates =
            holesky::aggregate_attestations_by_epoch_sorted_by_data(epoch - 1);
        let current_epoch_aggregates =
            holesky::aggregate_attestations_by_epoch_sorted_by_data(epoch);

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

    #[test]
    #[cfg(feature = "eth2-cache")]
    fn test_holesky_optimal_aggregate_attestation_packing() -> Result<()> {
        let config = Arc::new(Config::holesky());
        let pubkey_cache = PubkeyCache::default();
        let slot = 50_015;
        let epoch = misc::compute_epoch_at_slot::<Mainnet>(slot);
        let state = holesky::beacon_state(slot, 8);
        let latest_block_root = accessors::latest_block_root(&state);

        // Optimal packing uses the assumption that attestations are sorted by their data (this assumption is fulfilled when values are taken from BTree)
        let previous_epoch_aggregates =
            holesky::aggregate_attestations_by_epoch_sorted_by_data(epoch - 1);
        let current_epoch_aggregates =
            holesky::aggregate_attestations_by_epoch_sorted_by_data(epoch);

        let _unused = accessors::initialize_shuffled_indices(&state, &previous_epoch_aggregates);
        let _unused = accessors::initialize_shuffled_indices(&state, &current_epoch_aggregates);

        let packer = AttestationPacker::new(
            config.clone_arc(),
            latest_block_root,
            state.clone_arc(),
            true,
        )?;

        let pack_outcome = packer.pack_proposable_attestations_optimally(
            &previous_epoch_aggregates,
            &current_epoch_aggregates,
        );

        // value computed without optimizations
        assert_eq!(compute_total_reward(&packer, &pack_outcome)?, 5_260_609_920);

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

            unphased::validate_attestation(config, pubkey_cache, state, attestation)?;
        }

        Ok(())
    }
}
