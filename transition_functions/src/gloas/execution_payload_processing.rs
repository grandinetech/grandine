use anyhow::Result;
use helper_functions::{
    accessors::{get_current_epoch, get_pending_balance_to_withdraw_for_builder},
    gloas::{add_builder_to_registry, initiate_builder_exit},
    predicates::{
        is_active_builder, is_builder_withdrawal_credential, is_valid_builder_deposit_signature,
    },
};
use pubkey_cache::PubkeyCache;
use types::{
    config::Config,
    gloas::{
        consts::PAYLOAD_BUILDER_VERSION,
        containers::{BuilderDepositRequest, BuilderExitRequest, ExecutionRequests},
    },
    phase0::{consts::FAR_FUTURE_EPOCH, primitives::ExecutionAddress},
    preset::Preset,
    traits::PostGloasBeaconState,
};

use crate::{electra, fulu};

pub fn process_execution_requests<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    execution_requests: &ExecutionRequests<P>,
) -> Result<()> {
    for deposit_request in &execution_requests.deposits {
        fulu::process_deposit_request(state, *deposit_request)?;
    }

    for withdrawal_request in &execution_requests.withdrawals {
        electra::process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    for consolidation_request in &execution_requests.consolidations {
        electra::process_consolidation_request(config, state, *consolidation_request)?;
    }

    for deposit_request in &execution_requests.builder_deposits {
        process_builder_deposit_request(config, pubkey_cache, state, *deposit_request)?;
    }

    for exit_request in &execution_requests.builder_exits {
        process_builder_exit_request(config, state, *exit_request)?;
    }

    Ok(())
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub fn process_builder_deposit_request<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    deposit_request: BuilderDepositRequest,
) -> Result<()> {
    let BuilderDepositRequest {
        pubkey,
        withdrawal_credentials,
        amount,
        ..
    } = deposit_request;

    if !is_builder_withdrawal_credential(withdrawal_credentials) {
        return Ok(());
    }

    if let Some(builder_index) = state
        .builders()
        .into_iter()
        .position(|builder| builder.pubkey == pubkey)
    {
        let current_epoch = get_current_epoch(state);
        let builder_index = builder_index.try_into()?;
        let builder = state
            .builders_mut()
            .get_mut(builder_index)
            .expect("builder index is valid since its pubkey found in builder registry");

        // > If exited, reset the withdrawable epoch
        if builder.withdrawable_epoch != FAR_FUTURE_EPOCH && builder.balance == 0 {
            builder.withdrawable_epoch =
                current_epoch.checked_add(config.min_builder_withdrawability_delay).ok_or_else(|| {
                    anyhow::anyhow!(
                        "epoch overflow when resetting withdrawable epoch for builder at index {builder_index}",
                    )
                })?;
        }

        builder.balance = builder.balance.checked_add(amount).ok_or_else(|| {
            anyhow::anyhow!(
                "balance overflow when applying deposit for builder at index {builder_index}",
            )
        })?;
    } else if is_valid_builder_deposit_signature(config, pubkey_cache, &deposit_request) {
        let mut address = ExecutionAddress::zero();
        address.assign_from_slice(&withdrawal_credentials[12..]);

        add_builder_to_registry(
            state,
            pubkey,
            PAYLOAD_BUILDER_VERSION,
            address,
            amount,
            state.slot(),
        )?;
    }

    Ok(())
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub fn process_builder_exit_request<P: Preset>(
    config: &Config,
    state: &mut impl PostGloasBeaconState<P>,
    exit_request: BuilderExitRequest,
) -> Result<()> {
    let BuilderExitRequest {
        source_address,
        pubkey,
    } = exit_request;

    if let Some(builder_index) = state
        .builders()
        .into_iter()
        .position(|builder| builder.pubkey == pubkey)
    {
        let builder_index = builder_index.try_into()?;
        let builder = state
            .builders()
            .get(builder_index)
            .expect("builder index is valid since its pubkey found in builder registry");

        if is_active_builder(builder, state.finalized_checkpoint().epoch)
            && builder.execution_address == source_address
            && get_pending_balance_to_withdraw_for_builder(state, builder_index)? == 0
        {
            initiate_builder_exit(config, state, builder_index)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::{BlsSetting, Case};
    use ssz::SszReadDefault;
    use test_generator::test_resources;
    use types::{
        gloas::beacon_state::BeaconState,
        preset::{Mainnet, Minimal},
    };

    use super::*;

    macro_rules! processing_tests {
        (
            $module_name: ident,
            $processing_function: expr,
            $operation_name: literal,
            $mainnet_glob: literal,
            $minimal_glob: literal,
        ) => {
            mod $module_name {
                use super::*;

                #[test_resources($mainnet_glob)]
                fn mainnet(case: Case) {
                    run_processing_case_specialized::<Mainnet>(case);
                }

                #[test_resources($minimal_glob)]
                fn minimal(case: Case) {
                    run_processing_case_specialized::<Minimal>(case);
                }

                fn run_processing_case_specialized<P: Preset>(case: Case) {
                    run_processing_case::<P, _>(case, $operation_name, $processing_function);
                }
            }
        };
    }

    processing_tests! {
        process_deposit_request,
        |_, _, state, deposit_request, _| fulu::process_deposit_request(state, deposit_request),
        "deposit_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/deposit_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/deposit_request/*/*",
    }

    processing_tests! {
        process_withdrawal_request,
        |config, _, state, withdrawal_request, _| electra::process_withdrawal_request(config, state, withdrawal_request),
        "withdrawal_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/withdrawal_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/withdrawal_request/*/*",
    }

    processing_tests! {
        process_consolidation_request,
        |config, _, state, consolidation_request, _| electra::process_consolidation_request(config, state, consolidation_request),
        "consolidation_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/consolidation_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/consolidation_request/*/*",
    }

    processing_tests! {
        process_builder_deposit_request,
        |config, pubkey_cache, state, builder_deposit_request, _| process_builder_deposit_request(config, pubkey_cache, state, builder_deposit_request),
        "builder_deposit_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/builder_deposit_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/builder_deposit_request/*/*",
    }

    processing_tests! {
        process_builder_exit_request,
        |config, _, state, builder_exit_request, _| process_builder_exit_request(config, state, builder_exit_request),
        "builder_exit_request",
        "consensus-spec-tests/tests/mainnet/gloas/operations/builder_exit_request/*/*",
        "consensus-spec-tests/tests/minimal/gloas/operations/builder_exit_request/*/*",
    }

    fn run_processing_case<P: Preset, O: SszReadDefault>(
        case: Case,
        operation_name: &str,
        processing_function: impl FnOnce(
            &Config,
            &PubkeyCache,
            &mut BeaconState<P>,
            O,
            BlsSetting,
        ) -> Result<()>,
    ) {
        let pubkey_cache = PubkeyCache::default();
        let mut state = case.ssz_default("pre");
        let operation = case.ssz_default(operation_name);
        let post_option = case.try_ssz_default("post");
        let bls_setting = case.meta().bls_setting;

        let result = processing_function(
            &P::default_config(),
            &pubkey_cache,
            &mut state,
            operation,
            bls_setting,
        )
        .map(|()| state);

        if let Some(expected_post) = post_option {
            let actual_post = result.expect("operation processing should succeed");
            assert_eq!(actual_post, expected_post);
        } else {
            result.expect_err("operation processing should fail");
        }
    }
}
