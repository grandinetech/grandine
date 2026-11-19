use anyhow::Result;
use arithmetic::U64Ext as _;
use helper_functions::{
    accessors::{get_current_epoch, get_pending_balance_to_withdraw, index_of_public_key},
    electra::initiate_validator_exit,
    gloas::{add_builder_to_registry, initiate_builder_exit},
    misc::get_max_effective_balance,
    mutators::{balance, increase_balance},
    pq as pq_helpers,
    pq::{compute_deposit_pubkey, compute_deposit_vrf_root, is_legacy_pubkey},
    predicates::{is_active_validator, is_builder_withdrawal_credential},
};
use ssz::{PersistentProgressiveList, SszList as _, SszListMut as _};
use try_from_iterator::TryFromIterator as _;
use types::{
    config::Config,
    electra::containers::{
        ConsolidationRequest, DepositRequest, PendingDeposit, WithdrawalRequest,
    },
    gloas::{
        consts::PAYLOAD_BUILDER_VERSION,
        containers::{BuilderDepositRequest, BuilderExitRequest},
    },
    nonstandard::PartialValidator,
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        primitives::{ExecutionAddress, Gwei, H256},
    },
    pq::{
        beacon_state::BeaconState,
        containers::{
            BuilderPreregistration, BuilderPreregistrationRequest, ExecutionRequests, Validator,
            ValidatorPreregistration, ValidatorPreregistrationRequest, VoluntaryExitRequest,
        },
        validator_list::padded_pubkey,
    },
    preset::Preset,
    traits::{PostGloasBeaconState as _, SszValidatorList as _},
};
use xmss::XmssPublicKey;

use crate::{electra, gloas};

pub fn process_execution_requests<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    execution_requests: &ExecutionRequests<P>,
) -> Result<()> {
    for deposit_request in &execution_requests.deposits {
        process_deposit_request(state, *deposit_request)?;
    }

    for withdrawal_request in &execution_requests.withdrawals {
        process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    for consolidation_request in &execution_requests.consolidations {
        process_consolidation_request(config, state, *consolidation_request)?;
    }

    for deposit_request in &execution_requests.builder_deposits {
        process_builder_deposit_request(config, state, *deposit_request)?;
    }

    for exit_request in &execution_requests.builder_exits {
        process_builder_exit_request(config, state, *exit_request)?;
    }

    for request in &execution_requests.validator_preregistrations {
        process_validator_preregistration_request::<P>(state, *request)?;
    }

    for request in &execution_requests.builder_preregistrations {
        process_builder_preregistration_request::<P>(state, *request)?;
    }

    for request in &execution_requests.voluntary_exits {
        process_voluntary_exit_request(config, state, *request)?;
    }

    Ok(())
}

// Validators and builders keep their public keys padded with `XMSS_DEPOSIT_PREFIX` in memory.
// For a request that is not legacy, that is the request's own `pubkey`.
fn padded_deposit_pubkey(pubkey: &bls::PublicKeyBytes) -> bls::PublicKeyBytes {
    padded_pubkey(compute_deposit_pubkey(pubkey))
}

/// [`process_deposit_request`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_deposit_request)
pub(super) fn process_deposit_request<P: Preset>(
    state: &mut BeaconState<P>,
    deposit_request: DepositRequest,
) -> Result<()> {
    let DepositRequest {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        ..
    } = deposit_request;

    let deposit_pubkey = compute_deposit_pubkey(&pubkey);

    if let Some(preregistration) = get_active_validator_preregistration(state, deposit_pubkey) {
        if withdrawal_credentials != preregistration.withdrawal_credentials {
            return Ok(());
        }

        if pq_helpers::vrf_root_from_signature_field(signature.as_bytes())
            != preregistration.vrf_root
        {
            return Ok(());
        }

        remove_validator_preregistration(state, deposit_pubkey)?;
    }

    let slot = state.slot;

    state.pending_deposits.push(PendingDeposit {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        slot,
    })?;

    Ok(())
}

/// [`process_withdrawal_request`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_withdrawal_request)
pub(super) fn process_withdrawal_request<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    withdrawal_request: WithdrawalRequest,
) -> Result<()> {
    // > Ignore requests that name a BLS public key
    if is_legacy_pubkey(&withdrawal_request.validator_pubkey) {
        return Ok(());
    }

    electra::process_withdrawal_request(config, state, withdrawal_request)
}

/// [`process_consolidation_request`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_consolidation_request)
pub(super) fn process_consolidation_request<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    consolidation_request: ConsolidationRequest,
) -> Result<()> {
    // > Ignore requests that name a BLS public key
    if is_legacy_pubkey(&consolidation_request.source_pubkey)
        || is_legacy_pubkey(&consolidation_request.target_pubkey)
    {
        return Ok(());
    }

    electra::process_consolidation_request(config, state, consolidation_request)
}

/// [`process_builder_deposit_request`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_builder_deposit_request)
pub(super) fn process_builder_deposit_request<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    request: BuilderDepositRequest,
) -> Result<()> {
    let BuilderDepositRequest {
        pubkey: request_pubkey,
        withdrawal_credentials,
        amount,
        ..
    } = request;

    // > Ignore deposits with unexpected withdrawal credential prefixes
    if !is_builder_withdrawal_credential(withdrawal_credentials) {
        return Ok(());
    }

    let deposit_pubkey = compute_deposit_pubkey(&request_pubkey);

    if let Some(preregistration) = get_active_builder_preregistration(state, deposit_pubkey) {
        if withdrawal_credentials != preregistration.withdrawal_credentials {
            return Ok(());
        }

        remove_builder_preregistration(state, deposit_pubkey)?;
    }

    let pubkey = padded_pubkey(deposit_pubkey);

    if let Some(builder_index) = state
        .builders()
        .into_iter()
        .position(|builder| builder.pubkey == pubkey)
    {
        let current_epoch = get_current_epoch(state);
        let builder = state.builders_mut().get_mut(builder_index.try_into()?)?;

        // > If exited and swept, reset the withdrawable epoch
        if builder.withdrawable_epoch != FAR_FUTURE_EPOCH && builder.balance == 0 {
            builder.withdrawable_epoch =
                current_epoch.try_add(config.min_builder_withdrawability_delay)?;
        }

        // > Increase balance by deposit amount
        builder.balance = builder.balance.try_add(amount)?;
    } else {
        let mut address = ExecutionAddress::zero();
        address.assign_from_slice(&withdrawal_credentials[12..]);

        let slot = state.slot;
        let builder_index = add_builder_to_registry(
            state,
            pubkey,
            PAYLOAD_BUILDER_VERSION,
            address,
            amount,
            slot,
        )?;

        // > [New in PQ]
        if is_legacy_pubkey(&request_pubkey) {
            initiate_builder_exit(config, state, builder_index)?;
        }
    }

    Ok(())
}

/// [`process_builder_exit_request`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-process_builder_exit_request)
pub(super) fn process_builder_exit_request<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    exit_request: BuilderExitRequest,
) -> Result<()> {
    // > `XMSSPubkey(request.pubkey[16:])`, which is how builders are keyed in memory once padded.
    let pubkey = padded_pubkey(types::pq::validator_list::unpadded_pubkey(
        &exit_request.pubkey,
    ));

    gloas::process_builder_exit_request(
        config,
        state,
        BuilderExitRequest {
            pubkey,
            ..exit_request
        },
    )
}

/// [`process_validator_preregistration_request`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-process_validator_preregistration_request)
pub(super) fn process_validator_preregistration_request<P: Preset>(
    state: &mut BeaconState<P>,
    request: ValidatorPreregistrationRequest,
) -> Result<()> {
    let ValidatorPreregistrationRequest {
        pubkey,
        withdrawal_credentials,
        vrf_root,
    } = request;

    // > An active binding for this pubkey makes the new request a no-op
    if get_active_validator_preregistration(state, pubkey).is_some() {
        return Ok(());
    }

    // > A pubkey with an existing validator cannot be preregistered
    if index_of_public_key(state, &padded_pubkey(pubkey)).is_some() {
        return Ok(());
    }

    // > A pubkey with a pending deposit cannot be preregistered
    if is_pending_validator(state, pubkey) {
        return Ok(());
    }

    let active_count = state
        .validator_preregistrations
        .into_iter()
        .filter(|preregistration| is_active_preregistration(state, preregistration.expiry_slot))
        .count();

    if u64::try_from(active_count)? >= P::PREREGISTRATIONS_LIMIT {
        return Ok(());
    }

    let preregistration = ValidatorPreregistration {
        pubkey,
        withdrawal_credentials,
        vrf_root,
        expiry_slot: state.slot.try_add(P::PREREGISTRATION_EXPIRY_SLOTS)?,
    };

    match validator_preregistration_index(state, pubkey) {
        // > Replace the expired record in place
        Some(index) => *state.validator_preregistrations.get_mut(index)? = preregistration,
        None => state.validator_preregistrations.push(preregistration)?,
    }

    Ok(())
}

/// [`process_builder_preregistration_request`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-process_builder_preregistration_request)
pub(super) fn process_builder_preregistration_request<P: Preset>(
    state: &mut BeaconState<P>,
    request: BuilderPreregistrationRequest,
) -> Result<()> {
    let BuilderPreregistrationRequest {
        pubkey,
        withdrawal_credentials,
    } = request;

    // > An active binding for this pubkey makes the new request a no-op
    if get_active_builder_preregistration(state, pubkey).is_some() {
        return Ok(());
    }

    // > A pubkey with an existing builder cannot be preregistered
    let padded = padded_pubkey(pubkey);

    if state
        .builders()
        .into_iter()
        .any(|builder| builder.pubkey == padded)
    {
        return Ok(());
    }

    let active_count = state
        .builder_preregistrations
        .into_iter()
        .filter(|preregistration| is_active_preregistration(state, preregistration.expiry_slot))
        .count();

    if u64::try_from(active_count)? >= P::PREREGISTRATIONS_LIMIT {
        return Ok(());
    }

    let preregistration = BuilderPreregistration {
        pubkey,
        withdrawal_credentials,
        expiry_slot: state.slot.try_add(P::PREREGISTRATION_EXPIRY_SLOTS)?,
    };

    match builder_preregistration_index(state, pubkey) {
        // > Replace the expired record in place
        Some(index) => *state.builder_preregistrations.get_mut(index)? = preregistration,
        None => state.builder_preregistrations.push(preregistration)?,
    }

    Ok(())
}

/// [`process_voluntary_exit_request`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-process_voluntary_exit_request)
pub(super) fn process_voluntary_exit_request<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    request: VoluntaryExitRequest,
) -> Result<()> {
    let Some(index) = index_of_public_key(state, &padded_pubkey(request.pubkey)) else {
        return Ok(());
    };

    let validator = state.validators.partial_validator(index)?;
    let current_epoch = get_current_epoch(state);

    if !is_active_validator(validator, current_epoch) {
        return Ok(());
    }

    if validator.exit_epoch != FAR_FUTURE_EPOCH {
        return Ok(());
    }

    if current_epoch
        < validator
            .activation_epoch
            .try_add(config.shard_committee_period)?
    {
        return Ok(());
    }

    if get_pending_balance_to_withdraw(state, index) != 0 {
        return Ok(());
    }

    initiate_validator_exit(config, state, index)
}

/// [`is_active_validator_preregistration`] and [`is_active_builder_preregistration`].
///
/// [`is_active_validator_preregistration`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-is_active_validator_preregistration
/// [`is_active_builder_preregistration`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-is_active_builder_preregistration
pub const fn is_active_preregistration<P: Preset>(
    state: &BeaconState<P>,
    expiry_slot: u64,
) -> bool {
    // > Activity is evaluated against the slot of the outstanding parent payload
    state.latest_execution_payload_bid.slot < expiry_slot
}

fn validator_preregistration_index<P: Preset>(
    state: &BeaconState<P>,
    pubkey: XmssPublicKey,
) -> Option<u64> {
    state
        .validator_preregistrations
        .into_iter()
        .position(|preregistration| preregistration.pubkey == pubkey)
        .and_then(|index| index.try_into().ok())
}

fn builder_preregistration_index<P: Preset>(
    state: &BeaconState<P>,
    pubkey: XmssPublicKey,
) -> Option<u64> {
    state
        .builder_preregistrations
        .into_iter()
        .position(|preregistration| preregistration.pubkey == pubkey)
        .and_then(|index| index.try_into().ok())
}

fn get_active_validator_preregistration<P: Preset>(
    state: &BeaconState<P>,
    pubkey: XmssPublicKey,
) -> Option<ValidatorPreregistration> {
    let index = validator_preregistration_index(state, pubkey)?;
    let preregistration = *state.validator_preregistrations.get(index).ok()?;
    is_active_preregistration(state, preregistration.expiry_slot).then_some(preregistration)
}

fn get_active_builder_preregistration<P: Preset>(
    state: &BeaconState<P>,
    pubkey: XmssPublicKey,
) -> Option<BuilderPreregistration> {
    let index = builder_preregistration_index(state, pubkey)?;
    let preregistration = *state.builder_preregistrations.get(index).ok()?;
    is_active_preregistration(state, preregistration.expiry_slot).then_some(preregistration)
}

// > Removal preserves the order of the remaining records, which the state root commits to.
fn remove_validator_preregistration<P: Preset>(
    state: &mut BeaconState<P>,
    pubkey: XmssPublicKey,
) -> Result<()> {
    state.validator_preregistrations = PersistentProgressiveList::try_from_iter(
        state
            .validator_preregistrations
            .into_iter()
            .copied()
            .filter(|preregistration| preregistration.pubkey != pubkey),
    )?;

    Ok(())
}

fn remove_builder_preregistration<P: Preset>(
    state: &mut BeaconState<P>,
    pubkey: XmssPublicKey,
) -> Result<()> {
    state.builder_preregistrations = PersistentProgressiveList::try_from_iter(
        state
            .builder_preregistrations
            .into_iter()
            .copied()
            .filter(|preregistration| preregistration.pubkey != pubkey),
    )?;

    Ok(())
}

/// [`process_preregistration_expiry`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-process_preregistration_expiry)
pub fn process_preregistration_expiry<P: Preset>(state: &mut BeaconState<P>) -> Result<()> {
    let validator_preregistrations = state
        .validator_preregistrations
        .into_iter()
        .copied()
        .filter(|preregistration| is_active_preregistration(state, preregistration.expiry_slot))
        .collect::<Vec<_>>();

    let builder_preregistrations = state
        .builder_preregistrations
        .into_iter()
        .copied()
        .filter(|preregistration| is_active_preregistration(state, preregistration.expiry_slot))
        .collect::<Vec<_>>();

    state.validator_preregistrations =
        PersistentProgressiveList::try_from_iter(validator_preregistrations)?;
    state.builder_preregistrations =
        PersistentProgressiveList::try_from_iter(builder_preregistrations)?;

    Ok(())
}

/// [`is_pending_validator`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-is_pending_validator)
fn is_pending_validator<P: Preset>(state: &BeaconState<P>, pubkey: XmssPublicKey) -> bool {
    state
        .pending_deposits
        .into_iter()
        .any(|deposit| compute_deposit_pubkey(&deposit.pubkey) == pubkey)
}

/// [`apply_pending_deposit`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-apply_pending_deposit)
pub fn apply_pending_deposit<P: Preset>(
    config: &Config,
    state: &mut BeaconState<P>,
    deposit: &PendingDeposit,
) -> Result<()> {
    let pubkey = padded_deposit_pubkey(&deposit.pubkey);

    if let Some(validator_index) = index_of_public_key(state, &pubkey) {
        return increase_balance(balance(state, validator_index)?, deposit.amount);
    }

    add_validator_to_registry(
        state,
        pubkey,
        compute_deposit_vrf_root(deposit),
        deposit.withdrawal_credentials,
        deposit.amount,
    )?;

    // > [New in PQ] The validator of a legacy deposit is exited at once
    if is_legacy_pubkey(&deposit.pubkey) {
        let epoch = get_current_epoch(state);
        let index = state.validators.len_u64().try_sub(1)?;
        let validator = state.validators.partial_validator_mut(index)?;

        validator.exit_epoch = epoch;
        validator.withdrawable_epoch = epoch.try_add(config.min_validator_withdrawability_delay)?;
    }

    Ok(())
}

/// [`add_validator_to_registry`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-add_validator_to_registry)
fn add_validator_to_registry<P: Preset>(
    state: &mut BeaconState<P>,
    pubkey: bls::PublicKeyBytes,
    vrf_root: H256,
    withdrawal_credentials: H256,
    amount: Gwei,
) -> Result<()> {
    let partial = PartialValidator {
        withdrawal_credentials,
        slashed: false,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };

    let effective_balance = amount
        .prev_multiple_of(P::EFFECTIVE_BALANCE_INCREMENT)
        .min(get_max_effective_balance::<P>(&partial));

    state.validators.push_pq(Validator {
        pubkey: types::pq::validator_list::unpadded_pubkey(&pubkey),
        vrf_root,
        withdrawal_credentials,
        effective_balance,
        slashed: false,
        activation_eligibility_epoch: FAR_FUTURE_EPOCH,
        activation_epoch: FAR_FUTURE_EPOCH,
        exit_epoch: FAR_FUTURE_EPOCH,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    })?;

    state.balances.push(amount)?;
    state.previous_epoch_participation.push(0)?;
    state.current_epoch_participation.push(0)?;
    state.inactivity_scores.push(0)?;

    Ok(())
}
