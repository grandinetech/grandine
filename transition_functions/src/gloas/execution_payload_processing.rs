use std::collections::HashMap;

use anyhow::Result;
use bls::{PublicKeyBytes, SignatureBytes};
use helper_functions::{
    gloas::apply_deposit_for_builder, predicates::is_builder_withdrawal_credential,
};
use pubkey_cache::PubkeyCache;
use types::{
    config::Config,
    electra::containers::{DepositRequest, ExecutionRequests, PendingDeposit},
    phase0::containers::DepositMessage,
    preset::Preset,
    traits::PostGloasBeaconState,
};

use crate::electra;

type DepositSignatureCache = HashMap<(DepositMessage, SignatureBytes), bool>;

pub fn process_execution_requests<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    execution_requests: &ExecutionRequests<P>,
) -> Result<()> {
    let mut signature_cache = DepositSignatureCache::new();

    for deposit_request in &execution_requests.deposits {
        process_deposit_request(
            config,
            pubkey_cache,
            state,
            *deposit_request,
            &mut signature_cache,
        )?;
    }

    for withdrawal_request in &execution_requests.withdrawals {
        electra::process_withdrawal_request(config, state, *withdrawal_request)?;
    }

    for consolidation_request in &execution_requests.consolidations {
        electra::process_consolidation_request(config, state, *consolidation_request)?;
    }

    Ok(())
}

#[cfg_attr(feature = "tracing", tracing::instrument(level = "debug", skip_all))]
pub fn process_deposit_request<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    deposit_request: DepositRequest,
    signature_cache: &mut DepositSignatureCache,
) -> Result<()> {
    let DepositRequest {
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        ..
    } = deposit_request;

    // > Regardless of the withdrawal credentials prefix, if a builder/validator
    //   already exists with this pubkey, apply the deposit to their balance
    if state
        .builders()
        .into_iter()
        .any(|builder| builder.pubkey == pubkey)
        || (is_builder_withdrawal_credential(withdrawal_credentials)
            && !state
                .validators()
                .into_iter()
                .any(|validator| validator.pubkey == pubkey)
            && !is_pending_validator(config, pubkey_cache, state, pubkey, signature_cache))
    {
        apply_deposit_for_builder(
            config,
            pubkey_cache,
            state,
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            state.slot(),
        )?;
    } else {
        let slot = state.slot();

        state.pending_deposits_mut().push(PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            slot,
        })?;
    }

    Ok(())
}

fn is_pending_validator<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    signature_cache: &mut DepositSignatureCache,
) -> bool {
    for deposit in state.pending_deposits() {
        if deposit.pubkey != pubkey {
            continue;
        }

        let PendingDeposit {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            ..
        } = *deposit;

        let deposit_message = DepositMessage {
            pubkey,
            withdrawal_credentials,
            amount,
        };

        if *signature_cache
            .entry((deposit_message, signature))
            .or_insert_with(|| electra::is_valid_deposit_signature(config, pubkey_cache, deposit))
        {
            return true;
        }
    }

    false
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
        |config, pubkey_cache, state, deposit_request, _| process_deposit_request(config, pubkey_cache, state, deposit_request, &mut HashMap::new()),
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
