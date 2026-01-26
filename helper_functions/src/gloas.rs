use anyhow::Result;
use bls::{PublicKeyBytes, SignatureBytes};
use pubkey_cache::PubkeyCache;
use ssz::H256;
use types::{
    config::Config,
    gloas::{containers::Builder, primitives::BuilderIndex},
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        containers::DepositMessage,
        primitives::{ExecutionAddress, Gwei},
    },
    preset::Preset,
    traits::PostGloasBeaconState,
};

use crate::{
    accessors::get_current_epoch,
    mutators::{builder_balance, increase_balance},
    signing::SignForAllForks as _,
};

pub fn apply_deposit_for_builder<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &mut impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    withdrawal_credentials: H256,
    amount: Gwei,
    signature: SignatureBytes,
) -> Result<()> {
    if let Some(builder_index) = state
        .builders()
        .into_iter()
        .position(|builder| builder.pubkey == pubkey)
    {
        let builder_index = builder_index.try_into()?;

        increase_balance(builder_balance(state, builder_index)?, amount);
    } else {
        // > Verify the deposit signature (proof of possession)
        // > which is not checked by the deposit contract
        let deposit_message = DepositMessage {
            pubkey,
            withdrawal_credentials,
            amount,
        };

        // > Fork-agnostic domain since deposits are valid across forks
        if let Ok(decompressed) = pubkey_cache.get_or_insert(pubkey)
            && deposit_message
                .verify(config, signature, decompressed)
                .is_ok()
        {
            add_builder_to_registry(state, pubkey, withdrawal_credentials, amount)?;
        }
    }

    Ok(())
}

fn add_builder_to_registry<P: Preset>(
    state: &mut impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    withdrawal_credentials: H256,
    amount: Gwei,
) -> Result<()> {
    let builder_index = get_index_for_new_builder(state);
    let builder = get_builder_from_deposit(state, pubkey, withdrawal_credentials, amount);

    if builder_index == state.builders().len_u64() {
        state.builders_mut().push(builder)?;
    } else {
        *state.builders_mut().get_mut(builder_index)? = builder;
    }

    // TODO(gloas): Should builder indices be cached like validators?
    // if so, it need to pruned since builder index is reusable. remove this TODO if not
    Ok(())
}

fn get_index_for_new_builder<P: Preset>(state: &impl PostGloasBeaconState<P>) -> BuilderIndex {
    let current_epoch = get_current_epoch(state);

    state
        .builders()
        .into_iter()
        .zip(0..)
        .find_map(|(builder, index)| {
            (builder.withdrawable_epoch <= current_epoch && builder.balance == 0).then_some(index)
        })
        .unwrap_or_else(|| state.builders().len_u64())
}

fn get_builder_from_deposit<P: Preset>(
    state: &impl PostGloasBeaconState<P>,
    pubkey: PublicKeyBytes,
    withdrawal_credentials: H256,
    amount: Gwei,
) -> Builder {
    let version = withdrawal_credentials[0];
    let mut address = ExecutionAddress::zero();
    address.assign_from_slice(&withdrawal_credentials[12..]);

    Builder {
        pubkey,
        version,
        execution_address: address,
        balance: amount,
        deposit_epoch: get_current_epoch(state),
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}
