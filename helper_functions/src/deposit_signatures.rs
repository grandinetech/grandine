//! Pre-verification of `pending_deposits` signatures ahead of the Gloas fork.
//!
//! The queue is unbounded. `onboard_builders` in [`crate::fork::upgrade_to_gloas`] checks
//! every entry in it. Doing that at the fork could stall the node. So the results are computed
//! ahead of time and cached in `PubkeyCache::deposit_signatures`.

use std::{collections::HashSet, sync::Arc};

use bls::{PublicKey, PublicKeyBytes, SignatureBytes};
use pubkey_cache::{DepositSignatureKey, PubkeyCache};
use std_ext::ArcExt as _;
use typenum::Unsigned as _;
use types::{
    combined::BeaconState as CombinedBeaconState,
    config::Config,
    electra::containers::PendingDeposit,
    phase0::{consts::GENESIS_SLOT, containers::DepositMessage, primitives::H256},
    preset::Preset,
    traits::BeaconState as _,
};

#[cfg(feature = "metrics")]
use prometheus_metrics::METRICS;

use crate::{
    error::SignatureKind,
    signing::SignForAllForks as _,
    verifier::{MultiVerifier, SingleVerifier, Triple, Verifier as _},
};

/// The number of signatures verified together.
/// Small, because one invalid signature forces the whole batch to be verified again.
const BATCH_SIZE: usize = 8;

struct Entry {
    key: DepositSignatureKey,
    pubkey: PublicKeyBytes,
}

#[must_use]
pub fn deposit_signature_key(config: &Config, deposit: &PendingDeposit) -> DepositSignatureKey {
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

    (deposit_message.signing_root(config), signature)
}

/// Like [`crate::predicates::is_valid_deposit_signature`], but cached.
/// Looks the result up in [`PubkeyCache::deposit_signatures`] and stores it on a miss.
#[must_use]
pub fn is_valid_deposit_signature_cached(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    deposit: &PendingDeposit,
) -> bool {
    let cache = pubkey_cache.deposit_signatures();
    let key = deposit_signature_key(config, deposit);

    if let Some(is_valid) = cache.get(&key) {
        #[cfg(feature = "metrics")]
        if let Some(metrics) = METRICS.get() {
            metrics.deposit_signature_cache_hit_count.inc();
        }

        return is_valid;
    }

    #[cfg(feature = "metrics")]
    if let Some(metrics) = METRICS.get() {
        metrics.deposit_signature_cache_miss_count.inc();
    }

    // The signature is verified without holding the cache lock.
    let (signing_root, signature) = key;
    let is_valid = verify_singular(pubkey_cache, signing_root, signature, deposit.pubkey);

    cache.insert(key, is_valid);

    is_valid
}

/// Verifies and caches the signatures of every `pending_deposit` in `state`.
/// For the anchor state during startup.
pub fn cache_pending_deposit_signatures<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &CombinedBeaconState<P>,
) -> usize {
    let Some(state) = state.post_electra() else {
        return 0;
    };

    cache_deposit_signatures(config, pubkey_cache, state.pending_deposits().iter())
}

/// Verifies and caches the signatures of the deposits appended by the latest block.
/// Earlier deposits were cached when they were appended.
pub fn cache_new_pending_deposit_signatures<P: Preset>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    state: &CombinedBeaconState<P>,
) -> usize {
    let slot = state.slot();

    let Some(state) = state.post_electra() else {
        return 0;
    };

    let pending_deposits = state.pending_deposits();

    let max_new_deposits = P::MaxDeposits::USIZE
        .saturating_add(P::MaxDepositRequestsPerPayload::USIZE)
        .saturating_add(P::MaxConsolidationRequestsPerPayload::USIZE);

    let new_deposits = (0..pending_deposits.len_u64())
        .rev()
        .take(max_new_deposits)
        .map_while(|index| pending_deposits.get(index).ok())
        // Blocks append `GENESIS_SLOT` entries too, after the deposit requests:
        // Eth1 deposits and excess balances from switches to compounding.
        // Stopping at the first one would hide every deposit in the block.
        .take_while(|deposit| deposit.slot == slot || deposit.slot == GENESIS_SLOT)
        // `onboard_builders` never checks `GENESIS_SLOT` signatures,
        // because those pubkeys are already in `validators`.
        .filter(|deposit| deposit.slot == slot);

    cache_deposit_signatures(config, pubkey_cache, new_deposits)
}

/// Verifies and caches the signatures of the `deposits` that are not cached yet.
/// Returns the number of signatures verified.
pub fn cache_deposit_signatures<'deposit>(
    config: &Config,
    pubkey_cache: &PubkeyCache,
    deposits: impl IntoIterator<Item = &'deposit PendingDeposit>,
) -> usize {
    let cache = pubkey_cache.deposit_signatures();

    let mut entries = deposits
        .into_iter()
        .map(|deposit| Entry {
            key: deposit_signature_key(config, deposit),
            pubkey: deposit.pubkey,
        })
        .collect::<Vec<_>>();

    if entries.is_empty() {
        return 0;
    }

    let missing = cache
        .missing(entries.iter().map(|entry| entry.key))
        .into_iter()
        .collect::<HashSet<_>>();

    let mut seen = HashSet::new();

    entries.retain(|entry| missing.contains(&entry.key) && seen.insert(entry.key));

    if entries.is_empty() {
        return 0;
    }

    let results = verify_batches(pubkey_cache, &entries);
    let verified = results.len();

    cache.insert_all(results);

    verified
}

#[cfg(not(target_os = "zkvm"))]
fn verify_batches(
    pubkey_cache: &PubkeyCache,
    entries: &[Entry],
) -> Vec<(DepositSignatureKey, bool)> {
    use rayon::{iter::ParallelIterator as _, slice::ParallelSlice as _};

    entries
        .par_chunks(BATCH_SIZE)
        .flat_map_iter(|batch| verify_batch(pubkey_cache, batch))
        .collect()
}

#[cfg(target_os = "zkvm")]
fn verify_batches(
    pubkey_cache: &PubkeyCache,
    entries: &[Entry],
) -> Vec<(DepositSignatureKey, bool)> {
    entries
        .chunks(BATCH_SIZE)
        .flat_map(|batch| verify_batch(pubkey_cache, batch))
        .collect()
}

fn verify_batch(pubkey_cache: &PubkeyCache, batch: &[Entry]) -> Vec<(DepositSignatureKey, bool)> {
    let mut results = Vec::with_capacity(batch.len());
    let mut decompressed = Vec::with_capacity(batch.len());

    for Entry { key, pubkey } in batch {
        match pubkey_cache.get_or_insert(*pubkey) {
            Ok(public_key) => decompressed.push((*key, public_key)),
            // A deposit whose pubkey cannot be decompressed can never have a valid signature.
            Err(_) => results.push((*key, false)),
        }
    }

    if decompressed.is_empty() {
        return results;
    }

    let triples = decompressed
        .iter()
        .map(|((signing_root, signature), public_key)| {
            Triple::new(*signing_root, *signature, public_key.clone_arc())
        })
        .collect::<Vec<_>>();

    if MultiVerifier::from(triples).finish().is_ok() {
        results.extend(decompressed.iter().map(|(key, _)| (*key, true)));

        return results;
    }

    // At least one signature in the batch is invalid.
    // Verify them one by one to find out which.
    results.extend(decompressed.into_iter().map(|(key, public_key)| {
        let (signing_root, signature) = key;
        let is_valid = verify_decompressed(signing_root, signature, public_key);

        (key, is_valid)
    }));

    results
}

fn verify_singular(
    pubkey_cache: &PubkeyCache,
    signing_root: H256,
    signature: SignatureBytes,
    pubkey: PublicKeyBytes,
) -> bool {
    pubkey_cache
        .get_or_insert(pubkey)
        .is_ok_and(|public_key| verify_decompressed(signing_root, signature, public_key))
}

fn verify_decompressed(
    signing_root: H256,
    signature: SignatureBytes,
    public_key: Arc<PublicKey>,
) -> bool {
    SingleVerifier
        .verify_singular(signing_root, signature, public_key, SignatureKind::Deposit)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use bls::{SecretKey, SecretKeyBytes, traits::SecretKey as _};
    use ssz::Hc;
    use try_from_iterator::TryFromIterator as _;
    use types::{
        PendingDeposits, electra::beacon_state::BeaconState as ElectraBeaconState,
        phase0::primitives::Slot, preset::Minimal,
    };

    use crate::predicates;

    use super::*;

    fn secret_key(index: u8) -> SecretKey {
        let mut bytes = SecretKeyBytes::default();

        // Any nonzero value below the curve order is a valid secret key.
        bytes.as_mut()[31] = index.saturating_add(1);

        bytes
            .try_into()
            .expect("small nonzero numbers are valid secret keys")
    }

    fn valid_deposit(config: &Config, index: u8, slot: Slot) -> PendingDeposit {
        let secret_key = secret_key(index);
        let pubkey = secret_key.to_public_key().into();

        let deposit_message = DepositMessage {
            pubkey,
            withdrawal_credentials: H256::repeat_byte(index),
            amount: 32_000_000_000,
        };

        PendingDeposit {
            pubkey,
            withdrawal_credentials: deposit_message.withdrawal_credentials,
            amount: deposit_message.amount,
            signature: deposit_message.sign(config, &secret_key).into(),
            slot,
        }
    }

    fn invalid_deposit(config: &Config, index: u8, slot: Slot) -> PendingDeposit {
        let mut deposit = valid_deposit(config, index, slot);

        // Changing the amount leaves the signature matching a different message.
        deposit.amount = deposit.amount.saturating_add(1);

        deposit
    }

    fn state_with_pending_deposits(
        slot: Slot,
        deposits: impl IntoIterator<Item = PendingDeposit>,
    ) -> CombinedBeaconState<Minimal> {
        let state = ElectraBeaconState::<Minimal> {
            slot,
            pending_deposits: PendingDeposits::<Minimal>::try_from_iter(deposits)
                .expect("deposits should fit in the list"),
            ..ElectraBeaconState::default()
        };

        CombinedBeaconState::Electra(Hc::from(state))
    }

    #[test]
    fn keys_of_deposits_verified_over_different_domains_differ() {
        let deposit = valid_deposit(&Config::mainnet(), 0, 0);

        let mut other_config = Config::mainnet();
        other_config.genesis_fork_version = [1; 4].into();

        assert_ne!(
            deposit_signature_key(&Config::mainnet(), &deposit),
            deposit_signature_key(&other_config, &deposit),
        );
    }

    #[test]
    fn caches_the_results_of_valid_and_invalid_deposits() {
        let config = Config::mainnet();
        let pubkey_cache = PubkeyCache::default();

        let valid = valid_deposit(&config, 0, 0);
        let invalid = invalid_deposit(&config, 1, 0);
        let deposits = [valid, invalid];

        assert_eq!(
            cache_deposit_signatures(&config, &pubkey_cache, &deposits),
            2,
        );

        let cache = pubkey_cache.deposit_signatures();

        assert_eq!(
            cache.get(&deposit_signature_key(&config, &valid)),
            Some(true),
        );

        assert_eq!(
            cache.get(&deposit_signature_key(&config, &invalid)),
            Some(false),
        );
    }

    #[test]
    fn does_not_verify_cached_or_duplicate_deposits_again() {
        let config = Config::mainnet();
        let pubkey_cache = PubkeyCache::default();
        let deposit = valid_deposit(&config, 0, 0);
        let deposits = [deposit, deposit];

        assert_eq!(
            cache_deposit_signatures(&config, &pubkey_cache, &deposits),
            1,
        );

        assert_eq!(
            cache_deposit_signatures(&config, &pubkey_cache, &deposits),
            0,
        );
    }

    #[test]
    fn cached_results_match_uncached_ones() {
        let config = Config::mainnet();
        let pubkey_cache = PubkeyCache::default();

        for (index, deposit) in [valid_deposit(&config, 0, 0), invalid_deposit(&config, 1, 0)]
            .into_iter()
            .enumerate()
        {
            let expected = predicates::is_valid_deposit_signature(&config, &pubkey_cache, &deposit);

            assert_eq!(expected, index == 0);

            // Once on a cache miss and once on a cache hit.
            assert_eq!(
                is_valid_deposit_signature_cached(&config, &pubkey_cache, &deposit),
                expected,
            );

            assert_eq!(
                is_valid_deposit_signature_cached(&config, &pubkey_cache, &deposit),
                expected,
            );
        }
    }

    #[test]
    fn only_deposits_added_by_the_last_block_are_verified() {
        let config = Config::mainnet();
        let pubkey_cache = PubkeyCache::default();

        let old = valid_deposit(&config, 0, 0);
        let new = valid_deposit(&config, 1, 5);
        let newer = valid_deposit(&config, 2, 5);

        let state = state_with_pending_deposits(5, [old, new, newer]);

        assert_eq!(
            cache_new_pending_deposit_signatures(&config, &pubkey_cache, &state),
            2,
        );

        let cache = pubkey_cache.deposit_signatures();

        assert_eq!(cache.get(&deposit_signature_key(&config, &old)), None);
        assert_eq!(cache.get(&deposit_signature_key(&config, &new)), Some(true));
        assert_eq!(
            cache.get(&deposit_signature_key(&config, &newer)),
            Some(true),
        );
    }

    #[test]
    fn deposits_added_before_a_genesis_slot_entry_in_the_same_block_are_verified() {
        let config = Config::mainnet();
        let pubkey_cache = PubkeyCache::default();

        let old = valid_deposit(&config, 0, 4);
        let new = valid_deposit(&config, 1, 5);

        // Queued by a switch to compounding in the same block, after the deposits.
        let excess_balance = valid_deposit(&config, 2, GENESIS_SLOT);

        let state = state_with_pending_deposits(5, [old, new, excess_balance]);

        assert_eq!(
            cache_new_pending_deposit_signatures(&config, &pubkey_cache, &state),
            1,
        );

        let cache = pubkey_cache.deposit_signatures();

        assert_eq!(cache.get(&deposit_signature_key(&config, &old)), None);
        assert_eq!(cache.get(&deposit_signature_key(&config, &new)), Some(true));
        assert_eq!(
            cache.get(&deposit_signature_key(&config, &excess_balance)),
            None,
        );
    }

    #[test]
    fn all_pending_deposits_are_verified_when_seeding() {
        let config = Config::mainnet();
        let pubkey_cache = PubkeyCache::default();

        let old = valid_deposit(&config, 0, 0);
        let new = valid_deposit(&config, 1, 5);
        let state = state_with_pending_deposits(5, [old, new]);

        assert_eq!(
            cache_pending_deposit_signatures(&config, &pubkey_cache, &state),
            2,
        );

        let cache = pubkey_cache.deposit_signatures();

        assert_eq!(cache.get(&deposit_signature_key(&config, &old)), Some(true));
        assert_eq!(cache.get(&deposit_signature_key(&config, &new)), Some(true));
    }
}
