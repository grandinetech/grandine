use bls::PublicKeyBytes;
use ssz::{Compressed, ContiguousList, ReadError, Ssz};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned;

use crate::{
    gloas::validator_list::ProgressiveValidatorList,
    nonstandard::{PartialValidator, PubkeyList, RawValidatorList},
    phase0::{primitives::Gwei, validator_list::ValidatorList},
};

#[derive(Ssz)]
#[ssz(derive_hash = false, derive_cursor = true)]
pub struct StoredValidators<N: Unsigned> {
    effective_balances: Compressed<ContiguousList<Gwei, N>>,
    partial_validators: Compressed<ContiguousList<PartialValidator, N>>,
    new_pubkeys: ContiguousList<PublicKeyBytes, N>,
}

impl<N: Unsigned> StoredValidators<N> {
    #[must_use]
    pub fn new(validators: &RawValidatorList, finalized: usize, level: i32) -> Self {
        Self {
            effective_balances: Compressed::with_level(
                ContiguousList::try_from_iter(validators.effective_balances().copied())
                    .expect("the registry fits in its limit"),
                level,
            ),
            partial_validators: Compressed::with_level(
                ContiguousList::try_from_iter(validators.partial_validators().copied())
                    .expect("the registry fits in its limit"),
                level,
            ),
            new_pubkeys: ContiguousList::try_from_iter(
                validators.pubkeys().iter().skip(finalized).copied(),
            )
            .expect("the registry fits in its limit"),
        }
    }

    pub fn into_list(self, finalized_pubkeys: &PubkeyList) -> Result<ValidatorList<N>, ReadError> {
        self.into_raw(finalized_pubkeys)
            .map(ValidatorList::from_raw)
    }

    pub fn into_progressive_list(
        self,
        finalized_pubkeys: &PubkeyList,
    ) -> Result<ProgressiveValidatorList, ReadError> {
        self.into_raw(finalized_pubkeys)
            .map(ProgressiveValidatorList::from_raw)
    }

    fn into_raw(self, finalized_pubkeys: &PubkeyList) -> Result<RawValidatorList, ReadError> {
        let Self {
            effective_balances,
            partial_validators,
            new_pubkeys,
        } = self;

        let effective_balances = effective_balances.into_inner();
        let partial_validators = partial_validators.into_inner();

        let length = partial_validators.len();
        let finalized = length.saturating_sub(new_pubkeys.len());

        if finalized_pubkeys.len() < finalized
            || effective_balances.len() != length
            || new_pubkeys.len() > length
        {
            return Err(ReadError::Custom {
                message: "a stored registry does not fit the finalized one",
            });
        }

        let mut pubkeys = finalized_pubkeys.prefix(finalized);

        pubkeys.extend(new_pubkeys);

        Ok(RawValidatorList::from_columns(
            pubkeys,
            effective_balances.into_iter().collect(),
            partial_validators.into_iter().collect(),
        ))
    }
}
