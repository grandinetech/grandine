use core::ops::Range;
#[cfg(target_os = "zkvm")]
use std::slice::Iter as VectorIter;
#[cfg(target_os = "zkvm")]
use std::vec::Vec as Vector;

use anyhow::Result;
use bls::PublicKeyBytes;
#[cfg(not(target_os = "zkvm"))]
use im::{Vector, vector::Iter as VectorIter};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{
    H256, IndexError, PushError, ReadError, Size, SszHash, SszRead, SszSize, SszWrite, U1,
    WriteError, read_list, write_list,
};
use xmss::XmssPublicKey;

use crate::{
    gloas::validator_list::ProgressiveValidatorList,
    nonstandard::{EffectiveBalanceList, PartialValidator, PartialValidatorList, PubkeyList},
    phase0::{containers::Validator as Phase0Validator, primitives::Gwei},
    pq::{consts::XMSS_DEPOSIT_PREFIX, containers::Validator},
    traits::SszValidatorList,
};

/// The spec's `Bytes48` encoding of an XMSS public key: `XMSS_DEPOSIT_PREFIX ‖ pubkey`.
///
/// PQ states keep validator and builder public keys in this form in memory, so that code keyed by
/// `PublicKeyBytes` works across forks.
#[must_use]
pub fn padded_pubkey(pubkey: XmssPublicKey) -> PublicKeyBytes {
    let mut bytes = [0; 48];
    bytes[..XMSS_DEPOSIT_PREFIX.len()].copy_from_slice(&XMSS_DEPOSIT_PREFIX);
    bytes[XMSS_DEPOSIT_PREFIX.len()..].copy_from_slice(pubkey.as_array());
    PublicKeyBytes(bytes)
}

/// The last 32 bytes of `pubkey`, the spec's `XMSSPubkey(pubkey[16:])`.
#[must_use]
pub fn unpadded_pubkey(pubkey: &PublicKeyBytes) -> XmssPublicKey {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(&pubkey.as_bytes()[XMSS_DEPOSIT_PREFIX.len()..]);
    XmssPublicKey::from_array(bytes)
}

impl Validator {
    #[must_use]
    pub fn from_parts(validator: &Phase0Validator, vrf_root: H256) -> Self {
        Self {
            pubkey: unpadded_pubkey(&validator.pubkey),
            vrf_root,
            withdrawal_credentials: validator.withdrawal_credentials,
            effective_balance: validator.effective_balance,
            slashed: validator.slashed,
            activation_eligibility_epoch: validator.activation_eligibility_epoch,
            activation_epoch: validator.activation_epoch,
            exit_epoch: validator.exit_epoch,
            withdrawable_epoch: validator.withdrawable_epoch,
        }
    }

    #[must_use]
    pub fn into_parts(self) -> (Phase0Validator, H256) {
        let validator = Phase0Validator {
            pubkey: padded_pubkey(self.pubkey),
            withdrawal_credentials: self.withdrawal_credentials,
            effective_balance: self.effective_balance,
            slashed: self.slashed,
            activation_eligibility_epoch: self.activation_eligibility_epoch,
            activation_epoch: self.activation_epoch,
            exit_epoch: self.exit_epoch,
            withdrawable_epoch: self.withdrawable_epoch,
        };

        (validator, self.vrf_root)
    }
}

/// The PQ `validators` list.
///
/// The fork-agnostic parts live in a [`ProgressiveValidatorList`] with padded public keys.
/// VRF roots are kept alongside, and the list is serialized and hashed as PQ `Validator`s.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct PqValidatorList {
    pub(crate) list: ProgressiveValidatorList,
    pub(crate) vrf_roots: Vector<H256>,
}

impl PqValidatorList {
    pub fn vrf_root(&self, index: u64) -> Result<H256, IndexError> {
        let index = usize::try_from(index).map_err(|_| IndexError::DoesNotFitInUsize { index })?;

        self.vrf_roots
            .get(index)
            .copied()
            .ok_or(IndexError::OutOfBounds {
                index,
                length: self.vrf_roots.len(),
            })
    }

    pub fn get_pq(&self, index: u64) -> Result<Validator, IndexError> {
        Ok(Validator::from_parts(
            &self.list.get(index)?,
            self.vrf_root(index)?,
        ))
    }

    pub fn push_pq(&mut self, validator: Validator) -> Result<(), PushError> {
        let (validator, vrf_root) = validator.into_parts();
        self.list.push(validator)?;
        push_back(&mut self.vrf_roots, vrf_root);
        Ok(())
    }

    /// Sets the VRF roots of the validators from index `start` on, which must have been pushed
    /// since the list was last hashed. Existing VRF roots never change.
    #[cfg(not(target_os = "zkvm"))]
    pub(crate) fn set_appended_vrf_roots(
        &mut self,
        start: usize,
        vrf_roots: impl IntoIterator<Item = H256>,
    ) -> Result<(), IndexError> {
        for (index, vrf_root) in (start..).zip(vrf_roots) {
            let length = self.vrf_roots.len();

            *self
                .vrf_roots
                .get_mut(index)
                .ok_or(IndexError::OutOfBounds { index, length })? = vrf_root;
        }

        Ok(())
    }

    pub fn iter_pq(&self) -> impl ExactSizeIterator<Item = Validator> + '_ {
        self.list
            .iter()
            .zip(self.vrf_roots.iter())
            .map(|(validator, vrf_root)| Validator::from_parts(&validator, *vrf_root))
    }
}

#[cfg(not(target_os = "zkvm"))]
fn push_back(vector: &mut Vector<H256>, value: H256) {
    vector.push_back(value);
}

#[cfg(target_os = "zkvm")]
fn push_back(vector: &mut Vector<H256>, value: H256) {
    vector.push(value);
}

impl SszValidatorList for PqValidatorList {
    fn get(&self, index: u64) -> Result<Phase0Validator, IndexError> {
        self.list.get(index)
    }

    fn pubkey(&self, index: u64) -> Result<&PublicKeyBytes, IndexError> {
        self.list.pubkey(index)
    }

    fn effective_balance(&self, index: u64) -> Result<u64, IndexError> {
        self.list.effective_balance(index)
    }

    fn partial_validator(&self, index: u64) -> Result<&PartialValidator, IndexError> {
        self.list.partial_validator(index)
    }

    fn pubkeys(&self) -> &PubkeyList {
        self.list.pubkeys()
    }

    fn partial_validators(&self) -> VectorIter<'_, PartialValidator> {
        self.list.partial_validators()
    }

    fn effective_balances(&self) -> VectorIter<'_, Gwei> {
        self.list.effective_balances()
    }

    fn effective_balance_mut(&mut self, index: u64) -> Result<&mut u64, IndexError> {
        self.list.effective_balance_mut(index)
    }

    fn partial_validator_mut(&mut self, index: u64) -> Result<&mut PartialValidator, IndexError> {
        self.list.partial_validator_mut(index)
    }

    fn restore_pubkeys(&mut self, pubkeys: &PubkeyList) -> Result<()> {
        self.list.restore_pubkeys(pubkeys)
    }

    fn restore_pubkeys_in(&mut self, pubkeys: &PubkeyList, range: Range<usize>) -> Result<()> {
        self.list.restore_pubkeys_in(pubkeys, range)
    }

    fn clear_pubkeys(&mut self, count: usize) {
        self.list.clear_pubkeys(count);
    }

    fn columns(&self) -> (&PubkeyList, &EffectiveBalanceList, &PartialValidatorList) {
        self.list.columns()
    }

    fn update_effective_balances(
        &mut self,
        updater: &mut dyn FnMut(&PartialValidator, Gwei) -> Result<Gwei, anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        self.list.update_effective_balances(updater)
    }

    /// Fork-agnostic callers have no VRF root to give. PQ code adds validators with
    /// [`PqValidatorList::push_pq`].
    fn push(&mut self, validator: Phase0Validator) -> Result<(), PushError> {
        self.list.push(validator)?;
        push_back(&mut self.vrf_roots, H256::zero());
        Ok(())
    }

    fn len_usize(&self) -> usize {
        self.list.len_usize()
    }

    fn len_u64(&self) -> u64 {
        self.list.len_u64()
    }

    fn iter<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = Phase0Validator> + 'a> {
        self.list.iter()
    }

    fn clone_boxed(&self) -> Box<dyn SszValidatorList> {
        Box::new(self.clone())
    }
}

impl FromIterator<Validator> for PqValidatorList {
    fn from_iter<T: IntoIterator<Item = Validator>>(iter: T) -> Self {
        let (validators, vrf_roots): (Vec<_>, Vec<_>) =
            iter.into_iter().map(Validator::into_parts).unzip();

        Self {
            list: validators.into_iter().collect(),
            vrf_roots: vrf_roots.into_iter().collect(),
        }
    }
}

impl Serialize for PqValidatorList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.iter_pq())
    }
}

impl<'de> Deserialize<'de> for PqValidatorList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<Validator>::deserialize(deserializer)
            .map(|validators| validators.into_iter().collect())
    }
}

impl SszSize for PqValidatorList {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl SszWrite for PqValidatorList {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        write_list(bytes, self.iter_pq())
    }
}

impl<C> SszRead<C> for PqValidatorList {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let validators: Vec<Validator> = read_list(usize::MAX, context, bytes)?;
        Ok(validators.into_iter().collect())
    }
}

impl SszHash for PqValidatorList {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        self.list.hash_tree_root_with(&|index| {
            let index = u64::try_from(index).expect("index fits in u64");

            self.get_pq(index)
                .expect("validator list invariant violated: VRF roots out of sync")
                .hash_tree_root()
        })
    }
}

#[cfg(test)]
mod tests {
    use ssz::SszReadDefault as _;
    use try_from_iterator::TryFromIterator as _;

    use super::*;

    fn validator(byte: u8) -> Validator {
        Validator {
            pubkey: XmssPublicKey::from_array([byte; 32]),
            vrf_root: H256::repeat_byte(byte.wrapping_add(1)),
            effective_balance: u64::from(byte),
            ..Validator::default()
        }
    }

    #[test]
    fn hashes_and_serializes_as_pq_validators() -> Result<(), Box<dyn core::error::Error>> {
        let validators = (0..7).map(validator).collect::<Vec<_>>();
        let mut list = validators.iter().copied().collect::<PqValidatorList>();
        let expected =
            ssz::ProgressiveList::<Validator>::try_from_iter(validators.iter().copied())?;

        assert_eq!(list.hash_tree_root(), expected.hash_tree_root());
        assert_eq!(list.to_ssz()?, expected.to_ssz()?);
        assert_eq!(PqValidatorList::from_ssz_default(list.to_ssz()?)?, list);

        list.push_pq(validator(9))?;
        *list.effective_balance_mut(3)? = 1234;

        let mut validators = validators;
        validators.push(validator(9));
        validators[3].effective_balance = 1234;
        let expected = ssz::ProgressiveList::<Validator>::try_from_iter(validators)?;

        assert_eq!(list.hash_tree_root(), expected.hash_tree_root());
        assert_eq!(
            list.pubkey(3)?,
            &padded_pubkey(XmssPublicKey::from_array([3; 32]))
        );

        Ok(())
    }
}
