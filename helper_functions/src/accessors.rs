use core::{
    fmt::Debug,
    num::NonZeroU64,
    ops::{Div as _, Mul as _},
};
use std::sync::Arc;

use anyhow::{bail, ensure, Result};
use bit_field::BitField as _;
use bls::{AggregatePublicKey, CachedPublicKey, PublicKeyBytes};
use im::HashMap;
use itertools::{EitherOrBoth, Itertools as _};
use num_integer::Roots as _;
use prometheus_metrics::METRICS;
use rc_box::ArcBox;
use ssz::{BitList, ContiguousList, ContiguousVector, FitsInU64, Hc, SszHash as _};
use std_ext::CopyExt as _;
use tap::{Pipe as _, TryConv as _};
use try_from_iterator::TryFromIterator as _;
use typenum::{IsGreaterOrEqual, Sub1, True, Unsigned as _};
use types::{
    altair::{
        consts::{
            DOMAIN_SYNC_COMMITTEE, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
            TIMELY_TARGET_FLAG_INDEX,
        },
        containers::SyncCommittee,
        primitives::{ParticipationFlags, SubcommitteeIndex},
    },
    cache::{IndexSlice, PackedIndices},
    config::Config,
    nonstandard::{AttestationEpoch, Participation, RelativeEpoch},
    phase0::{
        consts::{DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, GENESIS_EPOCH},
        containers::{Attestation, AttestationData, AttesterSlashing, IndexedAttestation},
        primitives::{
            CommitteeIndex, DomainType, Epoch, Gwei, Slot, SubnetId, ValidatorIndex, H256,
        },
    },
    preset::{Preset, SlotsPerHistoricalRoot, SyncSubcommitteeSize},
    traits::{BeaconState, PostAltairBeaconState},
};

use crate::{error::Error, misc, predicates};

#[must_use]
pub fn get_previous_epoch<P: Preset>(state: &impl BeaconState<P>) -> Epoch {
    get_current_epoch(state)
        .saturating_sub(1)
        .max(GENESIS_EPOCH)
}

#[must_use]
pub fn get_current_epoch<P: Preset>(state: &(impl BeaconState<P> + ?Sized)) -> Epoch {
    misc::compute_epoch_at_slot::<P>(state.slot())
}

#[must_use]
pub fn get_next_epoch<P: Preset>(state: &(impl BeaconState<P> + ?Sized)) -> Epoch {
    get_current_epoch(state) + 1
}

#[must_use]
pub fn absolute_epoch<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
) -> Epoch {
    match relative_epoch {
        RelativeEpoch::Previous => get_previous_epoch(state),
        RelativeEpoch::Current => get_current_epoch(state),
        RelativeEpoch::Next => get_next_epoch(state),
    }
}

pub fn attestation_epoch<P: Preset>(
    state: &impl BeaconState<P>,
    epoch: Epoch,
) -> Result<AttestationEpoch> {
    match get_current_epoch(state).checked_sub(epoch) {
        None => bail!(Error::EpochInTheFuture),
        Some(0) => Ok(AttestationEpoch::Current),
        Some(1) => Ok(AttestationEpoch::Previous),
        Some(_) => bail!(Error::EpochBeforePrevious),
    }
}

pub fn relative_epoch<P: Preset>(
    state: &impl BeaconState<P>,
    epoch: Epoch,
) -> Result<RelativeEpoch> {
    match get_next_epoch(state).checked_sub(epoch) {
        None => bail!(Error::EpochAfterNext),
        Some(0) => Ok(RelativeEpoch::Next),
        Some(1) => Ok(RelativeEpoch::Current),
        Some(2) => Ok(RelativeEpoch::Previous),
        Some(_) => bail!(Error::EpochBeforePrevious),
    }
}

/// <https://github.com/ethereum/consensus-specs/blob/f7da1a38347155589f5e0403ad3290ffb77f4da6/specs/phase0/beacon-chain.md#helpers>
pub fn get_finality_delay<P: Preset>(state: &impl BeaconState<P>) -> u64 {
    get_previous_epoch(state) - state.finalized_checkpoint().epoch
}

pub fn get_block_root<P: Preset>(
    state: &impl BeaconState<P>,
    attestation_epoch: AttestationEpoch,
) -> Result<H256> {
    // Cause a compilation error if a new variant is added to `AttestationEpoch`.
    // Block roots are not available for epochs in the future or distant past.
    match attestation_epoch {
        AttestationEpoch::Previous | AttestationEpoch::Current => {}
    }

    let epoch = absolute_epoch(state, attestation_epoch.into());
    let slot = misc::compute_start_slot_at_epoch::<P>(epoch);
    get_block_root_at_slot(state, slot)
}

pub fn get_block_root_at_slot<P: Preset>(state: &impl BeaconState<P>, slot: Slot) -> Result<H256> {
    ensure!(slot < state.slot(), Error::SlotOutOfRange);

    ensure!(
        state.slot() <= slot + SlotsPerHistoricalRoot::<P>::U64,
        Error::SlotOutOfRange,
    );

    Ok(state.block_roots().mod_index(slot).copy())
}

/// <https://github.com/ethereum/consensus-specs/blob/2ef55744df782eb153fc0a3b1c7875b8c2e11730/specs/phase0/validator.md#ffg-vote>
///
/// This returns the root of the block that started the epoch (i.e., the block satisfying `slot` =
/// `epoch` × `SlotsPerEpoch`), or, if there was no block in that slot, the root of the last block
/// preceding it.
#[must_use]
pub fn epoch_boundary_block_root<P: Preset>(
    head_state: &impl BeaconState<P>,
    head_block_root: H256,
) -> H256
where
    SlotsPerHistoricalRoot<P>: IsGreaterOrEqual<Sub1<P::SlotsPerEpoch>, Output = True>,
{
    let epoch = get_current_epoch(head_state);
    let start_slot = misc::compute_start_slot_at_epoch::<P>(epoch);

    if start_slot == head_state.slot() {
        head_block_root
    } else {
        get_block_root_at_slot(head_state, start_slot).expect(
            "the check above combined with the bound on \
             P::SlotsPerHistoricalRoot ensures that the slot is in range",
        )
    }
}

#[must_use]
pub fn latest_block_root<P: Preset>(state: &(impl BeaconState<P> + ?Sized)) -> H256 {
    let mut header = state.latest_block_header();

    if header.state_root.is_zero() {
        header.state_root = state.hash_tree_root();
    }

    header.hash_tree_root()
}

#[must_use]
pub fn get_randao_mix<P: Preset>(state: &(impl BeaconState<P> + ?Sized), epoch: Epoch) -> H256 {
    *state.randao_mixes().mod_index(epoch)
}

pub fn public_key<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
    validator_index: ValidatorIndex,
) -> Result<&CachedPublicKey> {
    Ok(&state.validators().get(validator_index)?.pubkey)
}

#[must_use]
pub fn index_of_public_key<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
    public_key: PublicKeyBytes,
) -> Option<ValidatorIndex> {
    get_or_init_validator_indices(state, true)
        .get(&public_key)
        .copied()
}

pub fn get_or_init_validator_indices<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
    report_cache_miss: bool,
) -> &HashMap<PublicKeyBytes, ValidatorIndex> {
    state.cache().validator_indices.get_or_init(|| {
        if report_cache_miss {
            if let Some(metrics) = METRICS.get() {
                metrics.validator_indices_init_count.inc();
            }
        }

        state
            .validators()
            .into_iter()
            .map(|validator| validator.pubkey.to_bytes())
            .zip(0..)
            .collect()
    })
}

pub fn get_active_validator_indices<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
) -> impl Iterator<Item = ValidatorIndex> + '_ {
    let epoch = absolute_epoch(state, relative_epoch);
    get_active_validator_indices_by_epoch(state, epoch)
}

fn get_active_validator_indices_by_epoch<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
    epoch: Epoch,
) -> impl Iterator<Item = ValidatorIndex> + '_ {
    (0..)
        .zip(state.validators())
        .filter(move |(_, validator)| predicates::is_active_validator(validator, epoch))
        .map(|(index, _)| index)
}

// Only proposer selection needs the list of validators to be in order. Removing this function in
// favor of `get_active_validator_indices` would save some memory at the cost of having to traverse
// `BeaconState.validators` every time the proposer is computed.
pub fn active_validator_indices_ordered<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
) -> &PackedIndices {
    get_or_init_active_validator_indices_ordered(state, relative_epoch, true)
}

pub fn get_or_init_active_validator_indices_ordered<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
    report_cache_miss: bool,
) -> &PackedIndices {
    fn pack<T>(indices: Vec<ValidatorIndex>) -> Arc<[T]>
    where
        ValidatorIndex: TryInto<T>,
        <ValidatorIndex as TryInto<T>>::Error: Debug,
    {
        // This relies on `std::vec::IntoIter` implementing `TrustedLen`.
        // See the documentation for the `FromIterator` impl for `Arc`.
        //
        // `try_into` combined with `expect` appears to be just as fast as casting.
        indices
            .into_iter()
            .map(|validator_index| {
                validator_index
                    .try_into()
                    .expect("the match below ensures that validator_index fits in T")
            })
            .collect()
    }

    state.cache().active_validator_indices_ordered[relative_epoch].get_or_init(|| {
        if report_cache_miss {
            if let Some(metrics) = METRICS.get() {
                metrics.active_validator_indices_ordered_init_count.inc();
            }
        }

        // Possible optimization: cache the number of active validators and index of the last one.
        // That would make it possible to avoid temporary allocations.
        // The cached values would have to be kept up to date as the validator registry changes.
        let mut indices = Vec::with_capacity(state.validators().len_usize());

        indices.extend(get_active_validator_indices(state, relative_epoch));

        match indices.last().copied().unwrap_or_default() {
            0..=0xff => PackedIndices::U8(pack(indices)),
            0x100..=0xffff => PackedIndices::U16(pack(indices)),
            0x1_0000..=0xffff_ffff => PackedIndices::U32(pack(indices)),
            0x1_0000_0000..=u64::MAX => PackedIndices::U64(indices.into()),
        }
    })
}

pub fn active_validator_indices_shuffled<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
) -> &PackedIndices
where
    P::ValidatorRegistryLimit: FitsInU64,
{
    get_or_init_active_validator_indices_shuffled(state, relative_epoch, true)
}

pub fn get_or_init_active_validator_indices_shuffled<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
    report_cache_miss: bool,
) -> &PackedIndices
where
    P::ValidatorRegistryLimit: FitsInU64,
{
    fn shuffle<P: Preset, T: Copy>(ordered: &[T], seed: H256) -> Arc<[T]> {
        let mut shuffled = ArcBox::from(ordered);

        shuffling::shuffle_slice::<P, _>(&mut shuffled, seed).expect(
            "the bound on P::ValidatorRegistryLimit ensures \
             that the number of active validators fits in u64",
        );

        shuffled.into()
    }

    state.cache().active_validator_indices_shuffled[relative_epoch].get_or_init(|| {
        if report_cache_miss {
            if let Some(metrics) = METRICS.get() {
                metrics.active_validator_indices_shuffled_init_count.inc();
            }
        }

        let seed = get_seed(state, relative_epoch, DOMAIN_BEACON_ATTESTER);

        match get_or_init_active_validator_indices_ordered(state, relative_epoch, report_cache_miss)
        {
            PackedIndices::U8(ordered) => PackedIndices::U8(shuffle::<P, _>(ordered, seed)),
            PackedIndices::U16(ordered) => PackedIndices::U16(shuffle::<P, _>(ordered, seed)),
            PackedIndices::U32(ordered) => PackedIndices::U32(shuffle::<P, _>(ordered, seed)),
            PackedIndices::U64(ordered) => PackedIndices::U64(shuffle::<P, _>(ordered, seed)),
        }
    })
}

#[must_use]
pub fn active_validator_count_usize<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
) -> usize {
    active_validator_indices_ordered(state, relative_epoch).len()
}

fn active_validator_count_u64<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
) -> u64
where
    P::ValidatorRegistryLimit: FitsInU64,
{
    active_validator_count_usize(state, relative_epoch)
        .try_into()
        .expect("the bound on P::ValidatorRegistryLimit ensures that the count fits in u64")
}

#[must_use]
pub fn get_validator_churn_limit<P: Preset>(config: &Config, state: &impl BeaconState<P>) -> u64 {
    active_validator_count_u64(state, RelativeEpoch::Current)
        .div(config.churn_limit_quotient)
        .max(config.min_per_epoch_churn_limit)
}

#[must_use]
pub fn get_validator_activation_churn_limit<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
) -> u64 {
    get_validator_churn_limit(config, state).min(config.max_per_epoch_activation_churn_limit)
}

fn get_seed<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
    domain_type: DomainType,
) -> H256 {
    let epoch = absolute_epoch(state, relative_epoch);
    get_seed_by_epoch(state, epoch, domain_type)
}

fn get_seed_by_epoch<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
    epoch: Epoch,
    domain_type: DomainType,
) -> H256 {
    let mix = get_randao_mix(
        state,
        epoch + P::EpochsPerHistoricalVector::U64 - P::MIN_SEED_LOOKAHEAD - 1,
    );

    hashing::hash_32_64_256(domain_type.to_fixed_bytes(), epoch, mix)
}

pub fn get_subnet_for_attestation<P: Preset>(
    state: &impl BeaconState<P>,
    slot: Slot,
    committee_index: CommitteeIndex,
) -> Result<SubnetId> {
    let committees_per_slot = get_committee_count_per_slot(state, RelativeEpoch::Current);

    misc::compute_subnet_for_attestation::<P>(committees_per_slot, slot, committee_index)
}

pub fn get_committee_count_per_slot<P: Preset>(
    state: &impl BeaconState<P>,
    relative_epoch: RelativeEpoch,
) -> u64 {
    let active_validator_count = active_validator_count_u64(state, relative_epoch);
    misc::committee_count_from_active_validator_count::<P>(active_validator_count)
}

pub fn beacon_committee<P: Preset>(
    state: &impl BeaconState<P>,
    slot: Slot,
    committee_index: CommitteeIndex,
) -> Result<IndexSlice> {
    let epoch = misc::compute_epoch_at_slot::<P>(slot);
    let relative_epoch = relative_epoch(state, epoch)?;
    let committees_per_slot = get_committee_count_per_slot(state, relative_epoch);

    ensure!(
        committee_index < committees_per_slot,
        Error::CommitteeIndexOutOfBounds,
    );

    let indices = active_validator_indices_shuffled(state, relative_epoch);
    let validator_count = ValidatorIndex::try_from(indices.len())?;
    let committees_in_epoch = committees_per_slot * P::SlotsPerEpoch::U64;
    let slots_since_epoch_start = misc::slots_since_epoch_start::<P>(slot);
    let index_in_epoch = slots_since_epoch_start * committees_per_slot + committee_index;
    let start = (validator_count * index_in_epoch / committees_in_epoch).try_into()?;
    let end = (validator_count * (index_in_epoch + 1) / committees_in_epoch).try_into()?;

    Ok(indices.slice(start..end))
}

pub fn beacon_committees<P: Preset>(
    state: &impl BeaconState<P>,
    slot: Slot,
) -> Result<impl Iterator<Item = IndexSlice>> {
    let epoch = misc::compute_epoch_at_slot::<P>(slot);
    let relative_epoch = relative_epoch(state, epoch)?;
    let committees_per_slot = get_committee_count_per_slot(state, relative_epoch);

    Ok((0..committees_per_slot).map(move |committee_index| {
        beacon_committee(state, slot, committee_index)
            .expect("committee index was obtained from get_committee_count_per_slot")
    }))
}

pub fn get_beacon_proposer_index<P: Preset>(state: &impl BeaconState<P>) -> Result<ValidatorIndex> {
    get_or_try_init_beacon_proposer_index(state, true)
}

pub fn get_or_try_init_beacon_proposer_index<P: Preset>(
    state: &impl BeaconState<P>,
    report_cache_miss: bool,
) -> Result<ValidatorIndex> {
    // `accessors::relative_epoch` never fails when called with the current epoch,
    // but `misc::compute_proposer_index` fails when the state has no active validators.
    state
        .cache()
        .proposer_index
        .get_or_try_init(|| {
            if report_cache_miss {
                if let Some(metrics) = METRICS.get() {
                    metrics.beacon_proposer_index_init_count.inc();
                }
            }

            get_beacon_proposer_index_at_slot(state, state.slot())
        })
        .copied()
}

pub fn get_beacon_proposer_index_at_slot<P: Preset>(
    state: &impl BeaconState<P>,
    slot: Slot,
) -> Result<ValidatorIndex> {
    let epoch = misc::compute_epoch_at_slot::<P>(slot);
    let relative_epoch = relative_epoch(state, epoch)?;
    let seed = get_seed(state, relative_epoch, DOMAIN_BEACON_PROPOSER);

    // Cause a compilation error if a new variant is added to `RelativeEpoch`.
    // Proposer selection is not reliable for epochs after the next one or in the distant past.
    match relative_epoch {
        RelativeEpoch::Previous | RelativeEpoch::Current | RelativeEpoch::Next => {}
    }

    let indices = active_validator_indices_ordered(state, relative_epoch);
    let seed = hashing::hash_256_64(seed, slot);

    misc::compute_proposer_index(state, indices, seed)
}

pub fn get_domain<P: Preset>(
    config: &Config,
    state: &(impl BeaconState<P> + ?Sized),
    domain_type: DomainType,
    epoch: Option<Epoch>,
) -> H256 {
    let epoch = epoch.unwrap_or_else(|| get_current_epoch(state));
    let fork = state.fork();

    let fork_version = if epoch < fork.epoch {
        fork.previous_version
    } else {
        fork.current_version
    };

    misc::compute_domain(
        config,
        domain_type,
        Some(fork_version),
        Some(state.genesis_validators_root()),
    )
}

pub fn get_indexed_attestation<P: Preset>(
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<IndexedAttestation<P>> {
    let attesting_indices_iter =
        get_attesting_indices(state, attestation.data, &attestation.aggregation_bits)?;

    let mut attesting_indices = ContiguousList::try_from_iter(attesting_indices_iter).expect(
        "Attestation.aggregation_bits and IndexedAttestation.attesting_indices \
         have the same maximum length",
    );

    // Sorting a slice is faster than building a `BTreeMap`.
    attesting_indices.sort_unstable();

    Ok(IndexedAttestation {
        attesting_indices,
        data: attestation.data,
        signature: attestation.signature,
    })
}

pub fn get_attesting_indices<'all, P: Preset>(
    state: &'all impl BeaconState<P>,
    attestation_data: AttestationData,
    aggregation_bits: &'all BitList<P::MaxValidatorsPerCommittee>,
) -> Result<impl Iterator<Item = ValidatorIndex> + 'all> {
    let committee = beacon_committee(state, attestation_data.slot, attestation_data.index)?;

    ensure!(
        committee.len() == aggregation_bits.len(),
        Error::CommitteeLengthMismatch,
    );

    // `Itertools::zip_eq` is slower than `Iterator::zip` when iterating over packed indices.
    // That may be due to the internal traits `core::iter::Zip` implements.
    // `bitvec::slice::BitSlice::iter_ones` with `Iterator::filter_map` is even slower.
    aggregation_bits
        .iter()
        .by_vals()
        .zip(committee)
        .filter_map(|(present, validator_index)| present.then_some(validator_index))
        .pipe(Ok)
}

pub fn total_active_balance<P: Preset>(state: &impl BeaconState<P>) -> Gwei {
    get_or_init_total_active_balance(state, true)
}

pub fn get_or_init_total_active_balance<P: Preset>(
    state: &impl BeaconState<P>,
    report_cache_miss: bool,
) -> Gwei {
    state.cache().total_active_balance[RelativeEpoch::Current]
        .get_or_init(|| {
            if report_cache_miss {
                if let Some(metrics) = METRICS.get() {
                    metrics.total_active_balance_init_count.inc();
                }
            }

            let current_epoch = get_current_epoch(state);
            state
                .validators()
                .into_iter()
                .filter(|validator| predicates::is_active_validator(validator, current_epoch))
                .map(|validator| validator.effective_balance)
                .sum::<Gwei>()
                .max(P::EFFECTIVE_BALANCE_INCREMENT.get())
                .try_into()
                .expect("the value is at least P::EFFECTIVE_BALANCE_INCREMENT, which is nonzero")
        })
        .get()
}

fn get_next_sync_committee_indices<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
) -> Result<ContiguousVector<ValidatorIndex, P::SyncCommitteeSize>> {
    let next_epoch = get_next_epoch(state);
    let indices = get_active_validator_indices_by_epoch(state, next_epoch).collect_vec();

    let total = indices
        .len()
        .try_conv::<u64>()?
        .pipe(NonZeroU64::new)
        .ok_or(Error::NoActiveValidators)?;

    let seed = get_seed_by_epoch(state, next_epoch, DOMAIN_SYNC_COMMITTEE);
    let max_random_byte = u64::from(u8::MAX);

    (0..u64::MAX / H256::len_bytes() as u64)
        .flat_map(move |quotient| {
            hashing::hash_256_64(seed, quotient)
                .to_fixed_bytes()
                .into_iter()
                .map(u64::from)
        })
        .zip(0..)
        .filter_map(move |(random_byte, attempt)| {
            let shuffled_index_of_index = misc::compute_shuffled_index::<P>(
                attempt % total,
                total,
                seed,
            )
            .try_conv::<usize>()
            .expect("shuffled_index_of_index fits in usize because it is less than indices.len()");

            let candidate_index = indices[shuffled_index_of_index];

            let effective_balance = state
                .validators()
                .get(candidate_index)
                .expect("candidate_index was produced by enumerating active validators")
                .effective_balance;

            (effective_balance * max_random_byte >= P::MAX_EFFECTIVE_BALANCE * random_byte)
                .then_some(candidate_index)
        })
        .take(P::SyncCommitteeSize::USIZE)
        .pipe(ContiguousVector::try_from_iter)
        .map_err(Into::into)
}

pub fn get_next_sync_committee<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
) -> Result<Arc<Hc<SyncCommittee<P>>>> {
    let indices = get_next_sync_committee_indices(state)?;

    let mut pubkeys = Box::<ContiguousVector<CachedPublicKey, _>>::default();

    for (pubkey, validator_index) in pubkeys.iter_mut().zip(indices) {
        let validator = state.validators().get(validator_index)?;
        pubkey.clone_from(&validator.pubkey);
    }

    let aggregate_pubkey = itertools::process_results(
        pubkeys.iter().map(CachedPublicKey::decompress),
        |public_keys| AggregatePublicKey::aggregate_nonempty(public_keys.copied()),
    )??
    .into();

    Ok(Arc::new(Hc::from(SyncCommittee {
        pubkeys,
        aggregate_pubkey,
    })))
}

pub fn get_base_reward<P: Preset>(
    state: &impl BeaconState<P>,
    validator_index: ValidatorIndex,
    base_reward_per_increment: Gwei,
) -> Result<Gwei> {
    let effective_balance = state.validators().get(validator_index)?.effective_balance;

    Ok(compute_base_reward::<P>(
        effective_balance,
        base_reward_per_increment,
    ))
}

#[must_use]
pub fn compute_base_reward<P: Preset>(
    effective_balance: Gwei,
    base_reward_per_increment: Gwei,
) -> Gwei {
    let increments = effective_balance / P::EFFECTIVE_BALANCE_INCREMENT;
    increments * base_reward_per_increment
}

pub fn get_base_reward_per_increment<P: Preset>(state: &impl BeaconState<P>) -> Gwei {
    P::EFFECTIVE_BALANCE_INCREMENT
        .get()
        .mul(P::BASE_REWARD_FACTOR)
        .div(total_active_balance(state).sqrt())
}

pub fn get_attestation_participation_flags<P: Preset>(
    state: &impl BeaconState<P>,
    data: AttestationData,
    inclusion_delay: u64,
) -> Result<ParticipationFlags> {
    let attestation_epoch = attestation_epoch(state, data.target.epoch)?;

    let justified_checkpoint = match attestation_epoch {
        AttestationEpoch::Previous => state.previous_justified_checkpoint(),
        AttestationEpoch::Current => state.current_justified_checkpoint(),
    };

    let expected_target = get_block_root(state, attestation_epoch)?;
    let expected_head = get_block_root_at_slot(state, data.slot)?;

    // > Matching roots
    let is_matching_source = data.source == justified_checkpoint;
    let is_matching_target = is_matching_source && data.target.root == expected_target;
    let is_matching_head = is_matching_target && data.beacon_block_root == expected_head;

    ensure!(is_matching_source, Error::AttestationSourceMismatch);

    let mut participation_flags = 0;

    if is_matching_source && inclusion_delay <= P::SlotsPerEpoch::U64.sqrt() {
        participation_flags.set_bit(TIMELY_SOURCE_FLAG_INDEX, true);
    }

    // TODO(feature/deneb): Consider duplicating `get_attestation_participation_flags` for Deneb
    //                      instead of checking the the phase of the state.
    if is_matching_target && (state.is_post_deneb() || inclusion_delay <= P::SlotsPerEpoch::U64) {
        participation_flags.set_bit(TIMELY_TARGET_FLAG_INDEX, true);
    }

    if is_matching_head && inclusion_delay <= P::MIN_ATTESTATION_INCLUSION_DELAY.get() {
        participation_flags.set_bit(TIMELY_HEAD_FLAG_INDEX, true);
    }

    Ok(participation_flags)
}

pub fn get_sync_subcommittee_pubkeys<P: Preset>(
    state: &(impl PostAltairBeaconState<P> + ?Sized),
    subcommittee_index: SubcommitteeIndex,
) -> Result<&[CachedPublicKey]> {
    let current_epoch = get_current_epoch(state);
    let next_slot_epoch = misc::compute_epoch_at_slot::<P>(state.slot() + 1);

    let sync_committee = if misc::sync_committee_period::<P>(current_epoch)
        == misc::sync_committee_period::<P>(next_slot_epoch)
    {
        state.current_sync_committee()
    } else {
        state.next_sync_committee()
    };

    let index = usize::try_from(subcommittee_index)?;
    let size = SyncSubcommitteeSize::<P>::USIZE;
    let offset = index * size;

    Ok(&sync_committee.pubkeys[offset..offset + size])
}

pub fn slashable_indices(
    attester_slashing: &AttesterSlashing<impl Preset>,
) -> impl Iterator<Item = ValidatorIndex> + '_ {
    let attesting_indices_1 = attester_slashing
        .attestation_1
        .attesting_indices
        .iter()
        .copied();

    let attesting_indices_2 = attester_slashing
        .attestation_2
        .attesting_indices
        .iter()
        .copied();

    attesting_indices_1
        .merge_join_by(attesting_indices_2, Ord::cmp)
        .filter_map(|either_or_both| match either_or_both {
            EitherOrBoth::Both(validator_index, _) => Some(validator_index),
            _ => None,
        })
}

#[must_use]
pub fn combined_participation<P: Preset>(
    state: &(impl PostAltairBeaconState<P> + ?Sized),
) -> Vec<Participation> {
    itertools::zip_eq(
        state.previous_epoch_participation().into_iter().copied(),
        state.current_epoch_participation().into_iter().copied(),
    )
    .map(|(previous, current)| Participation { previous, current })
    .collect()
}

/// Initialize shufflings required to compute attestation committees.
///
/// This should be called before validating attestations in parallel.
///
/// Shuffled validator indices are stored in a `once_cell::sync::OnceCell`. If multiple attestations
/// require a shuffling that has not yet been computed, all threads processing them will attempt to
/// initialize the `OnceCell` with the shuffling. `OnceCell` works roughly the same way as a mutex,
/// which means that all but one of the threads will block until the shuffling is computed, leaving
/// them unable to do any other work.
pub fn initialize_shuffled_indices<'attestations, P: Preset>(
    state: &impl BeaconState<P>,
    attestations: impl IntoIterator<Item = &'attestations Attestation<P>>,
) -> Result<()> {
    let shuffled = &state.cache().active_validator_indices_shuffled;
    let have_previous = shuffled[RelativeEpoch::Previous].get().is_some();
    let have_current = shuffled[RelativeEpoch::Current].get().is_some();

    if have_previous && have_current {
        return Ok(());
    }

    let mut need_previous = false;
    let mut need_current = false;

    for attestation in attestations {
        match attestation_epoch(state, attestation.data.target.epoch)? {
            AttestationEpoch::Previous => need_previous = true,
            AttestationEpoch::Current => need_current = true,
        }
    }

    let initialize_previous = || active_validator_indices_shuffled(state, RelativeEpoch::Previous);
    let initialize_current = || active_validator_indices_shuffled(state, RelativeEpoch::Current);

    match (
        need_previous && !have_previous,
        need_current && !have_current,
    ) {
        (true, true) => {
            rayon::join(initialize_previous, initialize_current);
        }
        (true, false) => {
            initialize_previous();
        }
        (false, true) => {
            initialize_current();
        }
        (false, false) => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use types::{
        phase0::{beacon_state::BeaconState as Phase0BeaconState, containers::Validator},
        preset::Minimal,
    };

    use super::*;

    #[test]
    fn test_get_current_epoch_genesis() {
        let state = Phase0BeaconState::<Minimal>::default();

        assert_eq!(get_current_epoch(&state), GENESIS_EPOCH);
    }

    #[test]
    fn test_get_current_epoch() {
        let state = Phase0BeaconState::<Minimal> {
            slot: 35,
            ..Phase0BeaconState::default()
        };

        assert_eq!(get_current_epoch(&state), 4);
    }

    #[test]
    fn test_get_previous_epoch_genesis() {
        let state = Phase0BeaconState::<Minimal>::default();

        assert_eq!(get_previous_epoch(&state), GENESIS_EPOCH);
    }

    #[test]
    fn test_get_previous_epoch() {
        let state = Phase0BeaconState::<Minimal> {
            slot: 35,
            ..Phase0BeaconState::default()
        };

        assert_eq!(get_previous_epoch(&state), 3);
    }

    #[test]
    fn test_get_block_root() {
        let mut state = Phase0BeaconState::<Minimal> {
            slot: 20,
            ..Phase0BeaconState::default()
        };

        for byte in 0..19 {
            *state.block_roots.mod_index_mut(byte.into()) = H256::repeat_byte(byte);
        }

        assert_eq!(
            get_block_root(&state, AttestationEpoch::Previous)
                .expect("slot is within allowed range"),
            H256::repeat_byte(<Minimal as Preset>::SlotsPerEpoch::U8),
        );
    }

    #[test]
    fn test_get_block_root_at_slot() {
        let mut state = Phase0BeaconState::<Minimal> {
            slot: 2,
            ..Phase0BeaconState::default()
        };

        *state.block_roots.mod_index_mut(1) = H256::repeat_byte(1);

        assert_eq!(
            get_block_root_at_slot(&state, 1).expect("slot is within allowed range"),
            H256::repeat_byte(1),
        );
    }

    #[test]
    fn test_get_randao_mix() {
        let mut state = Phase0BeaconState::<Minimal>::default();

        *state.randao_mixes.mod_index_mut(0) = H256::repeat_byte(1);

        assert_eq!(get_randao_mix(&state, 0), H256::repeat_byte(1));
    }

    #[test]
    fn test_get_validator_churn_limit() {
        let config = Config::minimal();

        let state = Phase0BeaconState::<Minimal>::default();

        assert_eq!(
            get_validator_churn_limit(&config, &state),
            config.min_per_epoch_churn_limit,
        );
    }

    #[test]
    fn test_get_active_validator_indices() {
        let state = Phase0BeaconState::<Minimal> {
            slot: 28,
            validators: [
                Validator {
                    exit_epoch: 10,
                    ..Validator::default()
                },
                Validator {
                    exit_epoch: 1,
                    ..Validator::default()
                },
                Validator {
                    exit_epoch: 10,
                    ..Validator::default()
                },
            ]
            .try_into()
            .expect("length is under maximum"),
            ..Phase0BeaconState::default()
        };

        let indices = get_active_validator_indices(&state, RelativeEpoch::Current);

        itertools::assert_equal(indices, [0, 2]);
    }
}
