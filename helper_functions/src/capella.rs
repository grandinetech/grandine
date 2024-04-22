use types::{
    phase0::{
        containers::Validator,
        primitives::{Epoch, Gwei},
    },
    preset::Preset,
};

use crate::predicates;

/// [`is_fully_withdrawable_validator`](https://github.com/ethereum/consensus-specs/blob/dc17b1e2b6a4ec3a2104c277a33abae75a43b0fa/specs/capella/beacon-chain.md#is_fully_withdrawable_validator)
///
/// > Check if ``validator`` is fully withdrawable.
pub fn is_fully_withdrawable_validator(validator: &Validator, balance: Gwei, epoch: Epoch) -> bool {
    predicates::has_eth1_withdrawal_credential(validator)
        && validator.withdrawable_epoch <= epoch
        && balance > 0
}

/// [`is_partially_withdrawable_validator`](https://github.com/ethereum/consensus-specs/blob/dc17b1e2b6a4ec3a2104c277a33abae75a43b0fa/specs/capella/beacon-chain.md#is_partially_withdrawable_validator)
///
/// > Check if ``validator`` is partially withdrawable.
pub fn is_partially_withdrawable_validator<P: Preset>(
    validator: &Validator,
    balance: Gwei,
) -> bool {
    let has_max_effective_balance = validator.effective_balance == P::MAX_EFFECTIVE_BALANCE;
    let has_excess_balance = balance > P::MAX_EFFECTIVE_BALANCE;

    predicates::has_eth1_withdrawal_credential(validator)
        && has_max_effective_balance
        && has_excess_balance
}
