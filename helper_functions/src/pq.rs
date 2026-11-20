//! Helpers added or modified by the PQ upgrade (`specs/_features/pq/beacon-chain.md`).

use anyhow::{Result, ensure};
use arithmetic::U64Ext as _;
use bls::PublicKeyBytes;
use pq_prover::{ProverBackend, Statement};
use sha2::{Digest as _, Sha256};
use ssz::{H256, SszBitList as _};
use tiny_keccak::{Hasher as _, Keccak};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    cache::PackedIndices,
    config::Config,
    electra::containers::PendingDeposit,
    phase0::{
        consts::{DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_SELECTION_PROOF},
        primitives::{CommitteeIndex, Epoch, Slot, ValidatorIndex},
    },
    pq::{
        beacon_state::BeaconState as PqBeaconState,
        consts::{
            AGGREGATORS_PER_COMMITTEE, LEAF_OFFSET_AGGREGATE_AND_PROOF, LEGACY_VRF_ROOT_DOMAIN,
            LEGACY_XMSS_PUBKEY_DOMAIN, VRF_LEAF_DOMAIN, XMSS_ATTESTATION_LEAVES,
            XMSS_BUILDER_BID_LEAVES, XMSS_DEPOSIT_PREFIX, XMSS_LEAVES_PER_SLOT,
            XMSS_RESERVED_LEAVES,
        },
        containers::{Attestation, AttesterSlashing, SignedAggregateAndProof, SingleAttestation},
        primitives::{AggregationCommittee, AggregationCommittees, VrfProof},
        validator_list::unpadded_pubkey,
    },
    preset::{Preset, SlotsPerHistoricalRoot},
    traits::BeaconState,
};
use xmss::{XmssPublicKey, XmssSignature};

use crate::{
    accessors,
    error::{Error, SignatureKind},
    misc,
};

/// [`compute_xmss_attestation_leaf_index`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_xmss_attestation_leaf_index)
pub fn compute_xmss_attestation_leaf_index(epoch: Epoch) -> Result<u64> {
    XMSS_RESERVED_LEAVES.try_add(epoch).map_err(Into::into)
}

/// [`compute_xmss_leaf_index`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_xmss_leaf_index)
pub fn compute_xmss_leaf_index(slot: Slot, leaf_offset: u64) -> Result<u64> {
    XMSS_RESERVED_LEAVES
        .try_add(XMSS_ATTESTATION_LEAVES)?
        .try_add(XMSS_BUILDER_BID_LEAVES)?
        .try_add(slot.try_mul(XMSS_LEAVES_PER_SLOT)?)?
        .try_add(leaf_offset)
        .map_err(Into::into)
}

/// [`is_builder_bid_leaf_index`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-is_builder_bid_leaf_index)
#[must_use]
pub const fn is_builder_bid_leaf_index(leaf_index: u64) -> bool {
    let start = XMSS_RESERVED_LEAVES + XMSS_ATTESTATION_LEAVES;
    start <= leaf_index && leaf_index < start + XMSS_BUILDER_BID_LEAVES
}

/// [`is_legacy_pubkey`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-is_legacy_pubkey)
#[must_use]
pub fn is_legacy_pubkey(pubkey: &PublicKeyBytes) -> bool {
    pubkey.as_bytes()[..XMSS_DEPOSIT_PREFIX.len()] != XMSS_DEPOSIT_PREFIX
}

fn hash_with_domain(pubkey: &PublicKeyBytes, domain: u8) -> H256 {
    H256(
        Sha256::new()
            .chain_update(pubkey.as_bytes())
            .chain_update([domain])
            .finalize()
            .into(),
    )
}

/// [`compute_legacy_xmss_pubkey`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_legacy_xmss_pubkey)
#[must_use]
pub fn compute_legacy_xmss_pubkey(pubkey: &PublicKeyBytes) -> XmssPublicKey {
    hash_with_domain(pubkey, LEGACY_XMSS_PUBKEY_DOMAIN).into()
}

/// [`compute_legacy_vrf_root`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_legacy_vrf_root)
#[must_use]
pub fn compute_legacy_vrf_root(pubkey: &PublicKeyBytes) -> H256 {
    hash_with_domain(pubkey, LEGACY_VRF_ROOT_DOMAIN)
}

/// [`compute_deposit_pubkey`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_deposit_pubkey)
#[must_use]
pub fn compute_deposit_pubkey(pubkey: &PublicKeyBytes) -> XmssPublicKey {
    if is_legacy_pubkey(pubkey) {
        return compute_legacy_xmss_pubkey(pubkey);
    }

    unpadded_pubkey(pubkey)
}

/// [`compute_deposit_vrf_root`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_deposit_vrf_root)
#[must_use]
pub fn compute_deposit_vrf_root(deposit: &PendingDeposit) -> H256 {
    if is_legacy_pubkey(&deposit.pubkey) {
        return compute_legacy_vrf_root(&deposit.pubkey);
    }

    vrf_root_from_signature_field(deposit.signature.as_bytes())
}

/// The first 32 bytes of a deposit's 96-byte signature field, which hold the VRF root after PQ.
#[must_use]
pub fn vrf_root_from_signature_field(signature: &[u8]) -> H256 {
    H256::from_slice(&signature[..H256::len_bytes()])
}

/// [`keccak256`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-keccak256)
pub(crate) fn keccak256(parts: &[&[u8]]) -> H256 {
    let mut hasher = Keccak::v256();
    let mut output = [0; 32];

    for part in parts {
        hasher.update(part);
    }

    hasher.finalize(&mut output);

    H256(output)
}

/// [`compute_vrf_leaf`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_vrf_leaf)
#[must_use]
pub fn compute_vrf_leaf(secret: H256, index: u64) -> H256 {
    keccak256(&[VRF_LEAF_DOMAIN, secret.as_bytes(), &index.to_le_bytes()])
}

/// [`is_valid_vrf_proof`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-is_valid_vrf_proof)
#[must_use]
pub fn is_valid_vrf_proof(vrf_root: H256, slot: Slot, proof: &VrfProof) -> bool {
    let (secret, branch) = proof
        .split_first()
        .expect("a VRF proof always has VRF_TREE_DEPTH + 1 entries");

    vrf_root_from_branch(*secret, slot, branch) == vrf_root
}

/// The root of a VRF tree whose leaf at `index` commits to `secret`, given the leaf's branch.
pub(crate) fn vrf_root_from_branch(secret: H256, index: u64, branch: &[H256]) -> H256 {
    branch.iter().zip(0..).fold(
        compute_vrf_leaf(secret, index),
        |value, (sibling, height)| {
            if index >> height & 1 == 1 {
                keccak256(&[sibling.as_bytes(), value.as_bytes()])
            } else {
                keccak256(&[value.as_bytes(), sibling.as_bytes()])
            }
        },
    )
}

/// `xmss.Verify` with the public key of the validator at `validator_index`.
pub fn verify_validator_signature<P: Preset>(
    state: &impl BeaconState<P>,
    validator_index: ValidatorIndex,
    leaf_index: u64,
    signing_root: H256,
    signature: &XmssSignature,
) -> Result<bool> {
    let pubkey = unpadded_pubkey(accessors::public_key(state, validator_index)?);

    Ok(xmss::verify_u64(
        &pubkey,
        leaf_index,
        signing_root.as_fixed_bytes(),
        signature,
    ))
}

/// [`get_committee_indices`] for `CommitteeBits` of `MAX_COMMITTEES_PER_SLOT_PQ` bits.
///
/// [`get_committee_indices`]: https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/electra/beacon-chain.md#new-get_committee_indices
pub fn get_committee_indices<P: Preset>(
    attestation: &Attestation<P>,
) -> impl Iterator<Item = CommitteeIndex> {
    attestation
        .committee_bits
        .into_iter()
        .zip(0..)
        .filter_map(|(present, committee_index)| present.then_some(committee_index))
}

/// The attesters of each committee of `attestation`, in committee order.
///
/// Fails like the spec's `process_attestation` if a committee is out of range, has no attesters, or
/// the aggregation bits do not cover the committees exactly.
pub fn get_attesting_indices_by_committee<P: Preset>(
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<Vec<Vec<ValidatorIndex>>> {
    let aggregation_bits = &attestation.aggregation_bits;
    let mut bits = aggregation_bits.iter_bits();
    let mut committee_offset: usize = 0;
    let mut output = vec![];

    for index in get_committee_indices(attestation) {
        let committee = accessors::beacon_committee(state, attestation.data.slot, index)?;

        let attesters = committee
            .into_iter()
            .filter(|_| bits.next().unwrap_or_default())
            .collect::<Vec<_>>();

        ensure!(!attesters.is_empty(), Error::NoCommitteeAttesters { index });

        committee_offset = committee_offset.checked_add(committee.len()).ok_or(
            Error::ParticipantsCountMismatch {
                aggregation_bitlist_length: aggregation_bits.len_usize(),
                participants_count: usize::MAX,
            },
        )?;

        output.push(attesters);
    }

    ensure!(
        committee_offset == aggregation_bits.len_usize(),
        Error::ParticipantsCountMismatch {
            aggregation_bitlist_length: aggregation_bits.len_usize(),
            participants_count: committee_offset,
        },
    );

    Ok(output)
}

/// [`get_attesting_indices`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#modified-get_attesting_indices)
///
/// Sorted and without duplicates.
pub fn get_attesting_indices<P: Preset>(
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<Vec<ValidatorIndex>> {
    let mut indices = get_attesting_indices_by_committee(state, attestation)?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    indices.sort_unstable();
    indices.dedup();

    Ok(indices)
}

/// [`get_attestation_statements`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-get_attestation_statements)
pub fn get_attestation_statements<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    attestation: &Attestation<P>,
) -> Result<Vec<Statement>> {
    let target_epoch = attestation.data.target.epoch;
    let domain = accessors::get_domain(config, state, DOMAIN_BEACON_ATTESTER, Some(target_epoch));
    let message = misc::compute_signing_root(&attestation.data, domain).to_fixed_bytes();
    let leaf_index = compute_xmss_attestation_leaf_index(target_epoch)?;

    get_attesting_indices_by_committee(state, attestation)?
        .into_iter()
        .map(|attesters| {
            let pubkeys = attesters
                .into_iter()
                .map(|index| accessors::public_key(state, index).map(unpadded_pubkey))
                .collect::<Result<_>>()?;

            Ok(Statement {
                pubkeys,
                leaf_index,
                message,
            })
        })
        .collect()
}

/// [`get_latest_block_slot`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-get_latest_block_slot)
pub fn get_latest_block_slot<P: Preset>(
    state: &impl BeaconState<P>,
    mut slot: Slot,
    parent_slot: Slot,
) -> Result<Slot> {
    if parent_slot <= slot {
        return Ok(parent_slot);
    }

    let block_root = accessors::get_block_root_at_slot(state, slot)?;

    while slot > 0
        && slot.try_add(SlotsPerHistoricalRoot::<P>::U64)? > state.slot()
        && accessors::get_block_root_at_slot(state, slot.try_sub(1)?)? == block_root
    {
        slot = slot.try_sub(1)?;
    }

    Ok(slot)
}

/// [`compute_aggregation_committee`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_aggregation_committee)
///
/// `committee` is the beacon committee at `slot` for `index`. `seed` is
/// `get_seed(state, epoch, DOMAIN_SELECTION_PROOF)` for the epoch of `slot`.
pub fn compute_aggregation_committee<P: Preset>(
    state: &impl BeaconState<P>,
    seed: H256,
    slot: Slot,
    index: CommitteeIndex,
    committee: Vec<ValidatorIndex>,
) -> Result<AggregationCommittee> {
    let seed = H256(
        Sha256::new()
            .chain_update(seed)
            .chain_update(slot.to_le_bytes())
            .chain_update(index.to_le_bytes())
            .finalize()
            .into(),
    );

    let mut candidates = committee;
    let mut aggregators = vec![];

    while aggregators.len() < usize::try_from(AGGREGATORS_PER_COMMITTEE)? && !candidates.is_empty()
    {
        let aggregator = misc::compute_balance_weighted_selection(
            state,
            &PackedIndices::U64(candidates.iter().copied().collect()),
            hashing::hash_256_64(seed, u64::try_from(aggregators.len())?),
            1,
            false,
        )?
        .into_iter()
        .next()
        .expect("compute_balance_weighted_selection returns as many indices as requested");

        aggregators.push(aggregator);
        candidates.retain(|candidate| *candidate != aggregator);
    }

    AggregationCommittee::try_from_iter(aggregators).map_err(Into::into)
}

/// [`compute_aggregation_committees`] for every slot of any `epoch`, in slot order.
///
/// [`compute_aggregation_committees`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-compute_aggregation_committees
pub fn compute_aggregation_committees_for_epoch<P: Preset>(
    state: &impl BeaconState<P>,
    epoch: Epoch,
) -> Result<Vec<AggregationCommittees>> {
    let (_, shuffled, committees_per_slot) = accessors::epoch_shuffling(state, epoch)?;
    let seed = accessors::get_seed_by_epoch(state, epoch, DOMAIN_SELECTION_PROOF)?;

    misc::slots_in_epoch::<P>(epoch)?
        .map(|slot| {
            let committees = (0..committees_per_slot)
                .map(|index| {
                    let range = accessors::committee_range::<P>(
                        shuffled.len(),
                        committees_per_slot,
                        slot,
                        index,
                    )?;

                    let committee = shuffled.slice(range).into_iter().collect();

                    compute_aggregation_committee(state, seed, slot, index, committee)
                })
                .collect::<Result<Vec<_>>>()?;

            AggregationCommittees::try_from_iter(committees).map_err(Into::into)
        })
        .collect()
}

/// [`get_aggregation_committee`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/beacon-chain.md#new-get_aggregation_committee)
pub fn get_aggregation_committee<P: Preset>(
    state: &PqBeaconState<P>,
    slot: Slot,
    index: CommitteeIndex,
) -> Result<&AggregationCommittee> {
    let epoch = misc::compute_epoch_at_slot::<P>(slot);
    let state_epoch = accessors::get_current_epoch(state);
    let slot_in_epoch = misc::slots_since_epoch_start::<P>(slot);

    let position = if epoch < state_epoch {
        ensure!(
            epoch.try_add(1)? == state_epoch,
            Error::AggregationCommitteeOutOfRange { slot },
        );

        slot_in_epoch
    } else {
        ensure!(
            epoch <= state_epoch.try_add(P::MinSeedLookahead::U64)?,
            Error::AggregationCommitteeOutOfRange { slot },
        );

        epoch
            .try_sub(state_epoch)?
            .try_add(1)?
            .try_mul(P::SlotsPerEpoch::U64)?
            .try_add(slot_in_epoch)?
    };

    let committees = state
        .aggregation_committee_window
        .get(usize::try_from(position)?)
        .ok_or(Error::AggregationCommitteeOutOfRange { slot })?;

    committees
        .get(usize::try_from(index)?)
        .ok_or_else(|| Error::CommitteeIndexOutOfBounds.into())
}

/// [`is_aggregator`](https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/validator.md#aggregation-selection)
pub fn is_aggregator<P: Preset>(
    state: &PqBeaconState<P>,
    slot: Slot,
    index: CommitteeIndex,
    validator_index: ValidatorIndex,
) -> Result<bool> {
    Ok(get_aggregation_committee(state, slot, index)?.contains(&validator_index))
}

/// The XMSS signature check of [`validate_beacon_attestation_gossip`].
///
/// [`validate_beacon_attestation_gossip`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/p2p-interface.md#modified-beacon_attestation_subnet_id
pub fn verify_single_attestation<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    attestation: &SingleAttestation,
) -> Result<()> {
    let target_epoch = attestation.data.target.epoch;
    let domain = accessors::get_domain(config, state, DOMAIN_BEACON_ATTESTER, Some(target_epoch));
    let signing_root = misc::compute_signing_root(&attestation.data, domain);

    ensure!(
        verify_validator_signature(
            state,
            attestation.attester_index,
            compute_xmss_attestation_leaf_index(target_epoch)?,
            signing_root,
            &attestation.signature,
        )?,
        Error::SignatureInvalid(SignatureKind::Attestation),
    );

    Ok(())
}

/// The aggregator signature and STARK checks of [`validate_beacon_aggregate_and_proof_gossip`].
///
/// [`validate_beacon_aggregate_and_proof_gossip`]: https://github.com/ethereum/consensus-specs/blob/pq/specs/_features/pq/p2p-interface.md#modified-beacon_aggregate_and_proof
pub fn verify_aggregate_and_proof<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    signed_aggregate_and_proof: &SignedAggregateAndProof<P>,
    backend: &dyn ProverBackend,
) -> Result<()> {
    let aggregate_and_proof = &signed_aggregate_and_proof.message;
    let aggregate = &aggregate_and_proof.aggregate;
    let target_epoch = aggregate.data.target.epoch;
    let domain = accessors::get_domain(
        config,
        state,
        DOMAIN_AGGREGATE_AND_PROOF,
        Some(target_epoch),
    );
    let signing_root = misc::compute_signing_root(aggregate_and_proof, domain);
    let leaf_index = compute_xmss_leaf_index(aggregate.data.slot, LEAF_OFFSET_AGGREGATE_AND_PROOF)?;

    ensure!(
        verify_validator_signature(
            state,
            aggregate_and_proof.aggregator_index,
            leaf_index,
            signing_root,
            &signed_aggregate_and_proof.signature,
        )?,
        Error::SignatureInvalid(SignatureKind::AggregateAndProof),
    );

    let statements = get_attestation_statements(config, state, aggregate)?;

    ensure!(
        backend.verify(&statements, aggregate_and_proof.proof.as_bytes())?,
        Error::AttestationProofInvalid,
    );

    Ok(())
}

/// The validators in both attestations of `attester_slashing`, without checking that they are
/// slashable.
pub fn slashable_indices<P: Preset>(
    attester_slashing: &AttesterSlashing<P>,
) -> impl Iterator<Item = ValidatorIndex> + '_ {
    let indices_2 = &attester_slashing.attestation_2.attesting_indices;

    attester_slashing
        .attestation_1
        .attesting_indices
        .iter()
        .copied()
        .filter(move |index| indices_2.iter().any(|other| other == index))
}
