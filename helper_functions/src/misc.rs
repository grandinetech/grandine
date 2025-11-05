use core::{
    num::NonZeroU64,
    ops::{Div as _, Range, Shr as _},
};
use std::sync::Arc;

use anyhow::{ensure, Result};
use arithmetic::{U64Ext as _, UsizeExt as _};
use bls::PublicKeyBytes;
use hashing::ZERO_HASHES;
use itertools::{izip, Itertools as _};
use sha2::{Digest as _, Sha256};
use ssz::{BitVector, ContiguousVector, MerkleTree, SszHash};
use tap::{Pipe as _, TryConv as _};
use typenum::Unsigned as _;
use types::{
    altair::{consts::SyncCommitteeSubnetCount, primitives::SyncCommitteePeriod},
    cache::PackedIndices,
    combined::{Attestation, DataColumnSidecar, SignedBeaconBlock},
    config::Config,
    deneb::{
        consts::{BlobCommitmentTreeDepth, VERSIONED_HASH_VERSION_KZG},
        containers::BlobSidecar,
        primitives::{
            Blob, BlobCommitmentInclusionProof, BlobIndex, KzgCommitment, KzgProof, VersionedHash,
        },
    },
    fulu::{
        containers::MatrixEntry,
        primitives::{BlobCommitmentsInclusionProof, ColumnIndex},
    },
    phase0::{
        consts::{
            AttestationSubnetCount, BLS_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX,
            GENESIS_EPOCH, GENESIS_SLOT,
        },
        containers::{ForkData, SignedBeaconBlockHeader, SigningData, Validator},
        primitives::{
            CommitteeIndex, Domain, DomainType, Epoch, ExecutionAddress, ForkDigest, Gwei, NodeId,
            Slot, SubnetId, Uint256, UnixSeconds, ValidatorIndex, Version, H128, H256,
        },
    },
    preset::{Preset, SyncSubcommitteeSize},
    traits::{
        BeaconState, PostAltairBeaconState, PostDenebBeaconBlockBody, PostElectraBeaconBlockBody,
        SignedBeaconBlock as _,
    },
};

use crate::{accessors, error::Error, predicates};

#[must_use]
pub fn compute_epoch_at_slot<P: Preset>(slot: Slot) -> Epoch {
    slot.div_typenum::<P::SlotsPerEpoch>()
}

#[must_use]
pub const fn compute_start_slot_at_epoch<P: Preset>(epoch: Epoch) -> Slot {
    epoch.saturating_mul(P::SlotsPerEpoch::U64)
}

#[must_use]
pub fn is_epoch_start<P: Preset>(slot: Slot) -> bool {
    slots_since_epoch_start::<P>(slot) == 0
}

#[must_use]
pub const fn builder_payment_index_for_current_epoch<P: Preset>(slot: Slot) -> u64 {
    P::SlotsPerEpoch::U64.saturating_add(slot % P::SlotsPerEpoch::U64)
}

#[must_use]
pub const fn builder_payment_index_for_previous_epoch<P: Preset>(slot: Slot) -> u64 {
    slot % P::SlotsPerEpoch::U64
}

#[expect(
    clippy::unnecessary_min_or_max,
    reason = "GENESIS_EPOCH const might be adjusted independently."
)]
#[must_use]
pub fn previous_epoch(epoch: Epoch) -> Epoch {
    epoch.saturating_sub(1).max(GENESIS_EPOCH)
}

#[expect(
    clippy::unnecessary_min_or_max,
    reason = "GENESIS_SLOT const might be adjusted independently."
)]
#[must_use]
pub fn previous_slot(slot: Slot) -> Slot {
    slot.saturating_sub(1).max(GENESIS_SLOT)
}

// `consensus-specs` uses this in at least 2 places:
// - <https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#compute_slots_since_epoch_start>
// - <https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#broadcast-attestation>
#[must_use]
pub fn slots_since_epoch_start<P: Preset>(slot: Slot) -> u64 {
    slot - compute_start_slot_at_epoch::<P>(compute_epoch_at_slot::<P>(slot))
}

#[must_use]
pub const fn slots_in_epoch<P: Preset>(epoch: Epoch) -> Range<Slot> {
    let next_epoch = epoch.saturating_add(1);
    compute_start_slot_at_epoch::<P>(epoch)..compute_start_slot_at_epoch::<P>(next_epoch)
}

/// <https://github.com/ethereum/consensus-specs/blob/5a4e568d2dc4cae6c470e0acbe4e48b01351500f/specs/altair/validator.md#sync-committee>
#[must_use]
pub fn sync_committee_period<P: Preset>(epoch: Epoch) -> SyncCommitteePeriod {
    epoch / P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

#[must_use]
pub const fn start_of_sync_committee_period<P: Preset>(period: SyncCommitteePeriod) -> Epoch {
    period * P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD.get()
}

#[must_use]
pub const fn compute_activation_exit_epoch<P: Preset>(epoch: Epoch) -> Epoch {
    epoch.saturating_add(1 + P::MAX_SEED_LOOKAHEAD)
}

// > Return the 32-byte fork data root for the ``current_version`` and ``genesis_validators_root``.
// > This is used primarily in signature domains to avoid collisions across forks/chains.
fn compute_fork_data_root(current_version: Version, genesis_validators_root: H256) -> H256 {
    ForkData {
        current_version,
        genesis_validators_root,
    }
    .hash_tree_root()
}

// > Return the 4-byte fork digest for the ``current_version`` and ``genesis_validators_root``.
// > This is a digest primarily used for domain separation on the p2p layer.
// > 4-bytes suffices for practical separation of forks/chains.
fn compute_fork_digest_pre_fulu(
    current_version: Version,
    genesis_validators_root: H256,
) -> ForkDigest {
    let root = compute_fork_data_root(current_version, genesis_validators_root);
    ForkDigest::from_slice(&root[..ForkDigest::len_bytes()])
}

// > Return the 4-byte fork digest for the ``version`` and ``genesis_validators_root``
// > XOR'd with the hash of the blob parameters for ``epoch``.
//
// > This is a digest primarily used for domain separation on the p2p layer.
// > 4-bytes suffices for practical separation of forks/chains.
fn compute_fork_digest_post_fulu(
    config: &Config,
    genesis_validators_root: H256,
    epoch: Epoch,
) -> ForkDigest {
    let fork_version = config.version_at_epoch(epoch);
    let blob_entry = config.get_blob_schedule_entry(epoch);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&blob_entry.epoch.to_le_bytes());
    bytes[8..].copy_from_slice(
        &u64::try_from(blob_entry.max_blobs_per_block)
            .expect("number of max blobs should fit in u64")
            .to_le_bytes(),
    );
    let hash = H256::from_slice(&Sha256::digest(bytes));
    let root = compute_fork_data_root(fork_version, genesis_validators_root);
    let bitmask_digest = root ^ hash;
    ForkDigest::from_slice(&bitmask_digest[..ForkDigest::len_bytes()])
}

#[must_use]
pub fn compute_fork_digest(
    config: &Config,
    genesis_validators_root: H256,
    epoch: Epoch,
) -> ForkDigest {
    if config.phase_at_epoch(epoch).is_peerdas_activated() {
        compute_fork_digest_post_fulu(config, genesis_validators_root, epoch)
    } else {
        let fork_version = config.version_at_epoch(epoch);
        compute_fork_digest_pre_fulu(fork_version, genesis_validators_root)
    }
}

#[must_use]
pub fn compute_domain(
    config: &Config,
    domain_type: DomainType,
    fork_version: Option<Version>,
    genesis_validators_root: Option<H256>,
) -> Domain {
    let fork_version = fork_version.unwrap_or(config.genesis_fork_version);
    let genesis_validators_root = genesis_validators_root.unwrap_or_else(H256::zero);
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);

    let mut domain = Domain::zero();
    domain[..DomainType::len_bytes()].copy_from_slice(domain_type.as_bytes());
    domain[DomainType::len_bytes()..].copy_from_slice(&fork_data_root[..28]);
    domain
}

pub fn compute_signing_root(object: &(impl SszHash + ?Sized), domain: Domain) -> H256 {
    SigningData {
        object_root: object.hash_tree_root(),
        domain,
    }
    .hash_tree_root()
}

pub(crate) fn compute_shuffled_index<P: Preset>(
    index: ValidatorIndex,
    index_count: NonZeroU64,
    seed: H256,
) -> ValidatorIndex {
    shuffling::shuffle_single::<P>(index, index_count, seed)
}

fn compute_proposer_index_pre_electra<P: Preset>(
    state: &impl BeaconState<P>,
    indices: &PackedIndices,
    seed: H256,
) -> Result<ValidatorIndex> {
    let total = indices
        .len()
        .try_conv::<u64>()?
        .pipe(NonZeroU64::new)
        .ok_or(Error::NoActiveValidators)?;

    let max_random_byte = u64::from(u8::MAX);

    (0..u64::MAX / H256::len_bytes() as u64)
        .flat_map(|quotient| {
            hashing::hash_256_64(seed, quotient)
                .to_fixed_bytes()
                .into_iter()
                .map(u64::from)
        })
        .zip(0..)
        .find_map(|(random_byte, attempt)| {
            let shuffled_index_of_index = compute_shuffled_index::<P>(attempt % total, total, seed)
                .try_conv::<usize>()
                .expect(
                    "shuffled_index_of_index fits in usize because it is less than indices.len()",
                );

            let candidate_index = indices
                .get(shuffled_index_of_index)
                .expect("compute_shuffled_index returns a value less than indices.len()");

            let effective_balance = state
                .validators()
                .get(candidate_index)
                .expect("candidate_index was produced by enumerating active validators")
                .effective_balance;

            (effective_balance * max_random_byte >= P::MAX_EFFECTIVE_BALANCE * random_byte)
                .then_some(candidate_index)
        })
        .ok_or(Error::FailedToSelectProposer)
        .map_err(Into::into)
}

fn compute_proposer_index_post_electra<P: Preset>(
    state: &impl BeaconState<P>,
    indices: &PackedIndices,
    seed: H256,
) -> Result<ValidatorIndex> {
    let total = indices
        .len()
        .try_conv::<u64>()?
        .pipe(NonZeroU64::new)
        .ok_or(Error::NoActiveValidators)?;

    let max_random_value = u64::from(u16::MAX);

    (0..u64::MAX / H128::len_bytes() as u64)
        .flat_map(|quotient| {
            hashing::hash_256_64(seed, quotient)
                .to_fixed_bytes()
                .into_iter()
                .tuples()
                .map(|bytes: (u8, u8)| u64::from(u16::from_le_bytes(bytes.into())))
        })
        .zip(0..)
        .find_map(|(random_value, attempt)| {
            let shuffled_index_of_index = compute_shuffled_index::<P>(attempt % total, total, seed)
                .try_conv::<usize>()
                .expect(
                    "shuffled_index_of_index fits in usize because it is less than indices.len()",
                );

            let candidate_index = indices
                .get(shuffled_index_of_index)
                .expect("compute_shuffled_index returns a value less than indices.len()");

            let effective_balance = state
                .validators()
                .get(candidate_index)
                .expect("candidate_index was produced by enumerating active validators")
                .effective_balance;

            (effective_balance * max_random_value
                >= P::MAX_EFFECTIVE_BALANCE_ELECTRA * random_value)
                .then_some(candidate_index)
        })
        .ok_or(Error::FailedToSelectProposer)
        .map_err(Into::into)
}

pub(crate) fn compute_proposer_index<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    indices: &PackedIndices,
    seed: H256,
    epoch: Epoch,
) -> Result<ValidatorIndex> {
    if state.is_post_electra() || epoch >= config.electra_fork_epoch {
        compute_proposer_index_post_electra(state, indices, seed)
    } else {
        compute_proposer_index_pre_electra(state, indices, seed)
    }
}

/// [`compute_subnet_for_attestation`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#broadcast-attestation)
pub fn compute_subnet_for_attestation<P: Preset>(
    committees_per_slot: u64,
    slot: Slot,
    committee_index: CommitteeIndex,
) -> Result<SubnetId> {
    ensure!(
        committee_index < committees_per_slot,
        Error::CommitteeIndexOutOfBounds,
    );

    let slots_since_epoch_start = slots_since_epoch_start::<P>(slot);
    let committees_since_epoch_start = committees_per_slot * slots_since_epoch_start;

    Ok((committees_since_epoch_start + committee_index).mod_typenum::<AttestationSubnetCount>())
}

/// [`compute_subnet_for_blob_sidecar`](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/deneb/validator.md#sidecar)
pub fn compute_subnet_for_blob_sidecar<P: Preset>(
    config: &Config,
    blob_sidecar: &BlobSidecar<P>,
) -> SubnetId {
    let phase = config.phase_at_slot::<P>(blob_sidecar.signed_block_header.message.slot);

    blob_sidecar.index % config.blob_sidecar_subnet_count(phase)
}

// source: https://github.com/ethereum/consensus-specs/pull/3574/files/cebf78a83e6fc8fa237daf4264b9ca0fe61473f4#diff-96cf4db15bede3d60f04584fb25339507c35755959159cdbe19d760ca92de109R106
#[must_use]
pub const fn compute_subnet_for_data_column_sidecar(
    config: &Config,
    column_index: ColumnIndex,
) -> SubnetId {
    column_index % config.data_column_sidecar_subnet_count
}

/// <https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/altair/validator.md#broadcast-sync-committee-message>
pub fn compute_subnets_for_sync_committee<P: Preset>(
    state: &(impl PostAltairBeaconState<P> + ?Sized),
    validator_index: ValidatorIndex,
) -> Result<BitVector<SyncCommitteeSubnetCount>> {
    let next_slot_epoch = compute_epoch_at_slot::<P>(state.slot() + 1);

    let sync_committee = if sync_committee_period::<P>(accessors::get_current_epoch(state))
        == sync_committee_period::<P>(next_slot_epoch)
    {
        state.current_sync_committee()
    } else {
        state.next_sync_committee()
    };

    let target_pubkey = &state.validators().get(validator_index)?.pubkey;

    let mut subnets = BitVector::default();

    sync_committee
        .pubkeys
        .iter()
        .enumerate()
        .filter(|(_, pubkey)| *pubkey == target_pubkey)
        .map(|(position, _)| position.div_typenum::<SyncSubcommitteeSize<P>>())
        .for_each(|position| subnets.set(position, true));

    Ok(subnets)
}

/// [`compute_subscribed_subnets`](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.2/specs/phase0/p2p-interface.md#attestation-subnet-subscription)
pub fn compute_subscribed_subnets<P: Preset>(
    node_id: NodeId,
    config: &Config,
    epoch: Epoch,
) -> Result<impl Iterator<Item = SubnetId>> {
    let attestation_subnet_prefix_bits = AttestationSubnetCount::USIZE
        .ilog2_ceil()
        .checked_add(config.attestation_subnet_extra_bits)
        .ok_or(Error::SubnetPrefixBitCountOverflow)?;

    let node_id_prefix = node_id
        .shr(NodeId::BITS - u16::from(attestation_subnet_prefix_bits))
        .try_into()?;

    let node_offset = node_id % config.epochs_per_subnet_subscription;

    let permutation_seed = (node_offset + Uint256::from_u64(epoch))
        .div(config.epochs_per_subnet_subscription)
        .try_into()
        .map(hashing::hash_64)?;

    let permutated_prefix_maximum = 1_u64
        .checked_shl(attestation_subnet_prefix_bits.into())
        .ok_or(Error::PermutatedPrefixMaximumOverflow)?
        .try_into()?;

    let permutated_prefix =
        compute_shuffled_index::<P>(node_id_prefix, permutated_prefix_maximum, permutation_seed);

    let cutoff = permutated_prefix
        .checked_add(config.subnets_per_node)
        .ok_or(Error::SubnetIdOverflow)?;

    Ok((permutated_prefix..cutoff).map(|index| index % AttestationSubnetCount::U64))
}

pub fn next_subnet_subscription_epoch<P: Preset>(
    node_id: NodeId,
    config: &Config,
    current_epoch: Epoch,
) -> Result<Epoch> {
    let current_subscribed_subnets =
        compute_subscribed_subnets::<P>(node_id, config, current_epoch)?.collect_vec();

    let mut epoch = current_epoch + 1;

    while compute_subscribed_subnets::<P>(node_id, config, epoch)?.collect_vec()
        == current_subscribed_subnets
    {
        epoch += 1;
    }

    Ok(epoch)
}

/// [`compute_time_at_slot`] and [`compute_timestamp_at_slot`].
///
/// The two functions do the same thing as long as [`GENESIS_SLOT`] is 0.
/// [`compute_timestamp_at_slot`] was originally an exact duplicate of [`compute_time_at_slot`].
/// See:
/// - <https://github.com/ethereum/consensus-specs/commit/0dec828d89c522aa2048e47f681eccb41b5fa282#diff-1ca740c05fe970719353cb1588c2158b04257ed260017d6464c315eeba35e099R162-R167>
/// - <https://github.com/ethereum/consensus-specs/commit/f6f36872d82d15e6b3ee2a9afc0fd949f4e9ad13>
/// - <https://github.com/ethereum/consensus-specs/commit/878b15df6ab8d56dd4499c45e2ddec4faa570910>
/// - <https://github.com/ethereum/consensus-specs/commit/65649c0383c886b11beac6f0fb58bad19ffc2f7e>
///
/// [`compute_time_at_slot`]:      https://github.com/ethereum/consensus-specs/blob/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/specs/phase0/validator.md#get_eth1_data
/// [`compute_timestamp_at_slot`]: https://github.com/ethereum/consensus-specs/blob/9839ed49346a85f95af4f8b0cb9c4d98b2308af8/specs/bellatrix/beacon-chain.md#compute_timestamp_at_slot
#[must_use]
pub fn compute_timestamp_at_slot<P: Preset>(
    config: &Config,
    state: &(impl BeaconState<P> + ?Sized),
    slot: Slot,
) -> UnixSeconds {
    let slots_since_genesis = slot - GENESIS_SLOT;
    state.genesis_time() + slots_since_genesis * config.slot_duration_ms.as_secs()
}

#[must_use]
pub fn committee_count_from_active_validator_count<P: Preset>(active_validator_count: u64) -> u64 {
    active_validator_count
        .div_typenum::<P::SlotsPerEpoch>()
        .div(P::TARGET_COMMITTEE_SIZE)
        .clamp(1, P::MaxCommitteesPerSlot::U64)
}

// <https://github.com/ethereum/consensus-specs/blob/dc17b1e2b6a4ec3a2104c277a33abae75a43b0fa/specs/phase0/validator.md#bls_withdrawal_prefix>
#[must_use]
pub fn bls_withdrawal_credentials(public_key: PublicKeyBytes) -> H256 {
    let mut withdrawal_credentials = hashing::hash_384(public_key);
    withdrawal_credentials[..BLS_WITHDRAWAL_PREFIX.len()].copy_from_slice(BLS_WITHDRAWAL_PREFIX);
    withdrawal_credentials
}

// <https://github.com/ethereum/consensus-specs/blob/dc17b1e2b6a4ec3a2104c277a33abae75a43b0fa/specs/phase0/validator.md#eth1_address_withdrawal_prefix>
#[must_use]
pub fn eth1_address_withdrawal_credentials(address: ExecutionAddress) -> H256 {
    let mut withdrawal_credentials = H256::zero();

    withdrawal_credentials[..ETH1_ADDRESS_WITHDRAWAL_PREFIX.len()]
        .copy_from_slice(ETH1_ADDRESS_WITHDRAWAL_PREFIX);

    withdrawal_credentials[H256::len_bytes() - ExecutionAddress::len_bytes()..]
        .copy_from_slice(address.as_bytes());

    withdrawal_credentials
}

#[must_use]
pub fn vec_of_default<P: Preset, T: Clone + Default>(state: &impl BeaconState<P>) -> Vec<T> {
    vec![T::default(); state.validators().len_usize()]
}

/// [`kzg_commitment_to_versioned_hash`](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/deneb/beacon-chain.md#kzg_commitment_to_versioned_hash)
#[must_use]
pub fn kzg_commitment_to_versioned_hash(kzg_commitment: KzgCommitment) -> VersionedHash {
    // TODO(feature/deneb): Implement `AsRef` directly on `KzgCommitment` like with `PublicKeyBytes`.
    //                      See the TODO in `types::deneb::primitives`.
    struct Wrapper(KzgCommitment);

    impl AsRef<[u8; 48]> for Wrapper {
        fn as_ref(&self) -> &[u8; 48] {
            self.0.as_fixed_bytes()
        }
    }

    let mut versioned_hash = hashing::hash_384(Wrapper(kzg_commitment));
    versioned_hash[..VERSIONED_HASH_VERSION_KZG.len()].copy_from_slice(VERSIONED_HASH_VERSION_KZG);
    versioned_hash
}

pub fn deneb_kzg_commitment_inclusion_proof<P: Preset>(
    body: &(impl PostDenebBeaconBlockBody<P> + ?Sized),
    commitment_index: BlobIndex,
) -> Result<BlobCommitmentInclusionProof<P>> {
    let depth = P::KzgCommitmentInclusionProofDepth::USIZE;

    let mut proof = ContiguousVector::default();
    let mut merkle_tree = MerkleTree::<BlobCommitmentTreeDepth<P>>::default();

    let chunks = body
        .blob_kzg_commitments()
        .iter()
        .map(SszHash::hash_tree_root);

    let commitment_indices = 0..body.blob_kzg_commitments().len();
    let proof_indices = commitment_index.try_into()?..(commitment_index + 1).try_into()?;

    let subproof = merkle_tree
        .extend_and_construct_proofs(chunks, commitment_indices, proof_indices)
        .exactly_one()
        .ok()
        .expect("exactly one proof is requested");

    // The first 13 or 5 nodes are computed from other elements of `body.blob_kzg_commitments`.
    proof[..depth - 4].copy_from_slice(subproof.as_slice());

    // The last 4 nodes are computed from other fields of `body`.
    proof[depth - 4] = body.bls_to_execution_changes().hash_tree_root();

    proof[depth - 3] = hashing::hash_256_256(
        body.sync_aggregate().hash_tree_root(),
        body.execution_payload().hash_tree_root(),
    );

    proof[depth - 2] = ZERO_HASHES[2];

    proof[depth - 1] = hashing::hash_256_256(
        hashing::hash_256_256(
            hashing::hash_256_256(
                body.randao_reveal().hash_tree_root(),
                body.eth1_data().hash_tree_root(),
            ),
            hashing::hash_256_256(body.graffiti(), body.proposer_slashings().hash_tree_root()),
        ),
        hashing::hash_256_256(
            hashing::hash_256_256(body.attester_slashings_root(), body.attestations_root()),
            hashing::hash_256_256(
                body.deposits().hash_tree_root(),
                body.voluntary_exits().hash_tree_root(),
            ),
        ),
    );

    Ok(proof)
}

pub fn electra_kzg_commitment_inclusion_proof<P: Preset>(
    body: &(impl PostElectraBeaconBlockBody<P> + ?Sized),
    commitment_index: BlobIndex,
) -> Result<BlobCommitmentInclusionProof<P>> {
    let depth = P::KzgCommitmentInclusionProofDepth::USIZE;

    let mut proof = ContiguousVector::default();
    let mut merkle_tree = MerkleTree::<BlobCommitmentTreeDepth<P>>::default();

    let chunks = body
        .blob_kzg_commitments()
        .iter()
        .map(SszHash::hash_tree_root);

    let commitment_indices = 0..body.blob_kzg_commitments().len();
    let proof_indices = commitment_index.try_into()?..(commitment_index + 1).try_into()?;

    let subproof = merkle_tree
        .extend_and_construct_proofs(chunks, commitment_indices, proof_indices)
        .exactly_one()
        .ok()
        .expect("exactly one proof is requested");

    // The first 13 or 5 nodes are computed from other elements of `body.blob_kzg_commitments`.
    proof[..depth - 4].copy_from_slice(subproof.as_slice());

    // The last 4 nodes are computed from other fields of `body`.
    proof[depth - 4] = body.bls_to_execution_changes().hash_tree_root();

    proof[depth - 3] = hashing::hash_256_256(
        body.sync_aggregate().hash_tree_root(),
        body.execution_payload().hash_tree_root(),
    );

    proof[depth - 2] = hashing::hash_256_256(
        hashing::hash_256_256(body.execution_requests().hash_tree_root(), ZERO_HASHES[0]),
        ZERO_HASHES[1],
    );

    proof[depth - 1] = hashing::hash_256_256(
        hashing::hash_256_256(
            hashing::hash_256_256(
                body.randao_reveal().hash_tree_root(),
                body.eth1_data().hash_tree_root(),
            ),
            hashing::hash_256_256(body.graffiti(), body.proposer_slashings().hash_tree_root()),
        ),
        hashing::hash_256_256(
            hashing::hash_256_256(body.attester_slashings_root(), body.attestations_root()),
            hashing::hash_256_256(
                body.deposits().hash_tree_root(),
                body.voluntary_exits().hash_tree_root(),
            ),
        ),
    );

    Ok(proof)
}

pub fn kzg_commitments_inclusion_proof<P: Preset>(
    body: &(impl PostElectraBeaconBlockBody<P> + ?Sized),
) -> BlobCommitmentsInclusionProof<P> {
    let depth = P::KzgCommitmentsInclusionProofDepth::USIZE;
    let mut proof = BlobCommitmentsInclusionProof::<P>::default();

    proof[depth - 4] = body.bls_to_execution_changes().hash_tree_root();

    proof[depth - 3] = hashing::hash_256_256(
        body.sync_aggregate().hash_tree_root(),
        body.execution_payload().hash_tree_root(),
    );

    proof[depth - 2] = hashing::hash_256_256(
        hashing::hash_256_256(body.execution_requests().hash_tree_root(), ZERO_HASHES[0]),
        ZERO_HASHES[1],
    );

    proof[depth - 1] = hashing::hash_256_256(
        hashing::hash_256_256(
            hashing::hash_256_256(
                body.randao_reveal().hash_tree_root(),
                body.eth1_data().hash_tree_root(),
            ),
            hashing::hash_256_256(body.graffiti(), body.proposer_slashings().hash_tree_root()),
        ),
        hashing::hash_256_256(
            hashing::hash_256_256(body.attester_slashings_root(), body.attestations_root()),
            hashing::hash_256_256(
                body.deposits().hash_tree_root(),
                body.voluntary_exits().hash_tree_root(),
            ),
        ),
    );

    proof
}

#[must_use]
pub fn blob_serve_range_slot<P: Preset>(config: &Config, current_slot: Slot) -> Slot {
    let current_epoch = compute_epoch_at_slot::<P>(current_slot);
    let epoch = config.deneb_fork_epoch.max(
        current_epoch
            .checked_sub(config.min_epochs_for_blob_sidecars_requests)
            .unwrap_or(GENESIS_EPOCH),
    );

    compute_start_slot_at_epoch::<P>(epoch)
}

pub fn construct_blob_sidecar<P: Preset>(
    block: &SignedBeaconBlock<P>,
    signed_block_header: SignedBeaconBlockHeader,
    index: BlobIndex,
    blob: Blob<P>,
    kzg_commitment: KzgCommitment,
    kzg_proof: KzgProof,
) -> Result<BlobSidecar<P>> {
    let message = block.message();

    let Some(body) = message.body().post_deneb() else {
        return Err(Error::BlobsForPreDenebBlock {
            root: message.hash_tree_root(),
            slot: message.slot(),
        }
        .into());
    };

    let kzg_commitment_inclusion_proof = match message.body().post_electra() {
        Some(body) => electra_kzg_commitment_inclusion_proof(body, index)?,
        None => deneb_kzg_commitment_inclusion_proof(body, index)?,
    };

    Ok(BlobSidecar {
        index,
        blob,
        kzg_commitment,
        kzg_proof,
        signed_block_header,
        kzg_commitment_inclusion_proof,
    })
}

pub fn construct_blob_sidecars<P: Preset>(
    block: &SignedBeaconBlock<P>,
    blobs: impl IntoIterator<Item = Blob<P>>,
    proofs: impl IntoIterator<Item = KzgProof>,
) -> Result<Vec<BlobSidecar<P>>> {
    let Some(body) = block.message().body().post_deneb() else {
        return Ok(vec![]);
    };

    let commitments = body.blob_kzg_commitments().into_iter().copied();
    let signed_block_header = block.to_header();

    izip!(0.., blobs, proofs, commitments)
        .map(|(index, blob, kzg_proof, kzg_commitment)| {
            construct_blob_sidecar(
                block,
                signed_block_header,
                index,
                blob,
                kzg_commitment,
                kzg_proof,
            )
        })
        .collect()
}

#[must_use]
pub fn committee_index<P: Preset>(attestation: &Attestation<P>) -> CommitteeIndex {
    match attestation {
        Attestation::Phase0(attestation) => attestation.data.index,
        Attestation::Electra(attestation) => get_committee_indices::<P>(attestation.committee_bits)
            .next()
            .unwrap_or_default(),
        Attestation::Single(attestation) => attestation.committee_index,
    }
}

pub fn get_committee_indices<P: Preset>(
    committee_bits: BitVector<P::MaxCommitteesPerSlot>,
) -> impl Iterator<Item = CommitteeIndex> {
    committee_bits
        .into_iter()
        .zip(0..)
        .filter_map(|(present, committee_index)| present.then_some(committee_index))
}

// > Get max effective balance for ``validator``.
#[must_use]
pub fn get_max_effective_balance<P: Preset>(validator: &Validator) -> Gwei {
    if predicates::has_compounding_withdrawal_credential(validator) {
        P::MAX_EFFECTIVE_BALANCE_ELECTRA
    } else {
        P::MIN_ACTIVATION_BALANCE
    }
}

pub fn parse_graffiti(string: &str) -> Result<H256> {
    ensure!(string.len() <= H256::len_bytes(), Error::GraffitiTooLong);

    let mut graffiti = H256::zero();
    graffiti[..string.len()].copy_from_slice(string.as_bytes());

    Ok(graffiti)
}

#[must_use]
pub fn data_column_serve_range_slot<P: Preset>(config: &Config, current_slot: Slot) -> Slot {
    let current_epoch = compute_epoch_at_slot::<P>(current_slot);
    let epoch = config.fulu_fork_epoch.max(
        current_epoch
            .checked_sub(config.min_epochs_for_data_column_sidecars_requests)
            .unwrap_or(GENESIS_EPOCH),
    );

    compute_start_slot_at_epoch::<P>(epoch)
}

pub fn compute_matrix_for_data_column_sidecar<P: Preset>(
    data_column_sidecar: &Arc<DataColumnSidecar<P>>,
) -> Vec<MatrixEntry<P>> {
    let column = data_column_sidecar.column();
    let column_index = data_column_sidecar.index();
    let blob_count = column.len() as u64;

    izip!(0..blob_count, column, data_column_sidecar.kzg_proofs())
        .map(|(row_index, cell, kzg_proof)| MatrixEntry {
            row_index,
            column_index,
            cell: cell.clone(),
            kzg_proof: *kzg_proof,
        })
        .collect()
}

pub fn compute_proposer_indices<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    epoch: Epoch,
    seed: H256,
    indices: &PackedIndices,
) -> Result<Vec<ValidatorIndex>> {
    let start_slot = compute_start_slot_at_epoch::<P>(epoch);
    (0..P::SlotsPerEpoch::U64)
        .map(|i| {
            let seed = hashing::hash_256_64(seed, start_slot.saturating_add(i));

            if state.is_post_gloas() {
                compute_balance_weighted_selection(state, indices, seed, 1, true)
                    .map(|validators| validators[0])
            } else {
                compute_proposer_index(config, state, indices, seed, epoch)
            }
        })
        .collect::<Result<_>>()
}

pub fn compute_balance_weighted_selection<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
    indices: &PackedIndices,
    seed: H256,
    size: usize,
    shuffle_indices: bool,
) -> Result<Vec<ValidatorIndex>> {
    let total = indices
        .len()
        .try_conv::<u64>()?
        .pipe(NonZeroU64::new)
        .ok_or(Error::NoActiveValidators)?;

    let mut selected = vec![];
    let mut i = 0u64;
    while selected.len() < size {
        let mut next_index = (i % total.get())
            .try_conv::<usize>()
            .expect("next_index fits in usize because it is less than indices.len()");

        if shuffle_indices {
            next_index = compute_shuffled_index::<P>(next_index as u64, total, seed)
                .try_conv::<usize>()
                .expect("next_index fits in usize because it is less than indices.len()");
        }

        let candidate_index = indices
            .get(next_index)
            .ok_or(Error::ValidatorIndexOutOfRange)?;

        if compute_balance_weighted_acceptance(state, candidate_index, seed, i)? {
            selected.push(candidate_index);
        }

        i += 1;
    }

    Ok(selected)
}

fn compute_balance_weighted_acceptance<P: Preset>(
    state: &(impl BeaconState<P> + ?Sized),
    index: ValidatorIndex,
    seed: H256,
    i: u64,
) -> Result<bool> {
    let max_random_value = u64::from(u16::MAX);
    let seed = hashing::hash_256_64(seed, i.saturating_div(16));
    let random_bytes = seed.as_fixed_bytes();
    let offset = usize::try_from((i % 16) * 2)?;
    let random_value = u64::from(u16::from_le_bytes([
        random_bytes[offset],
        random_bytes[offset + 1],
    ]));
    let effective_balance = state
        .validators()
        .get(index)
        .map(|validator| validator.effective_balance)?;

    Ok(effective_balance * max_random_value >= P::MAX_EFFECTIVE_BALANCE_ELECTRA * random_value)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hex_literal::hex;
    use itertools::iproduct;
    use nonzero_ext::nonzero;
    use types::{
        nonstandard::RelativeEpoch,
        phase0::{
            beacon_state::BeaconState as Phase0BeaconState,
            consts::{DOMAIN_BEACON_ATTESTER, FAR_FUTURE_EPOCH, GENESIS_EPOCH},
            containers::Validator,
        },
        preset::{Mainnet, Minimal},
    };

    use super::*;

    #[test]
    fn test_epoch_at_slot() {
        assert_eq!(compute_epoch_at_slot::<Minimal>(9), 1);
        assert_eq!(compute_epoch_at_slot::<Minimal>(8), 1);
        assert_eq!(compute_epoch_at_slot::<Minimal>(7), 0);
    }

    #[test]
    fn test_start_slot_at_epoch() {
        assert_eq!(compute_start_slot_at_epoch::<Minimal>(1), 8);
    }

    #[test]
    fn test_activation_exit_epoch() {
        assert_eq!(compute_activation_exit_epoch::<Minimal>(1), 6);
    }

    #[test]
    fn test_compute_domain() {
        assert_eq!(
            compute_domain(
                &Config::minimal(),
                DOMAIN_BEACON_ATTESTER,
                Some(hex!("00000001").into()),
                None,
            ),
            hex!("0100000018ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053").into()
        );
    }

    #[test]
    fn test_compute_shuffled_index_in_range() {
        let index_count = nonzero!(25_u64);

        let shuffled_index = compute_shuffled_index::<Minimal>(2, index_count, H256::random());

        assert!(shuffled_index < index_count.get());
    }

    #[test]
    fn test_compute_proposer_index_in_range() -> Result<()> {
        let validator = Validator {
            effective_balance: Minimal::MAX_EFFECTIVE_BALANCE,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            ..Validator::default()
        };

        let state = Phase0BeaconState::<Minimal> {
            validators: [validator.clone(), validator].try_into()?,
            ..Phase0BeaconState::default()
        };

        let proposer_index = compute_proposer_index(
            &Config::minimal(),
            &state,
            accessors::active_validator_indices_ordered(&state, RelativeEpoch::Current),
            H256::random(),
            compute_epoch_at_slot::<Minimal>(state.slot()),
        )?;

        assert!(proposer_index < 2);

        Ok(())
    }

    #[test]
    fn test_compute_subscribed_subnets_does_not_panic() {
        let node_ids = [NodeId::ZERO, NodeId::MAX];

        let configs = [
            Arc::new(Config::minimal()),
            {
                let mut config = Config::minimal();
                config.attestation_subnet_extra_bits = u8::MAX - AttestationSubnetCount::U8;
                Arc::new(config)
            },
            {
                let mut config = Config::minimal();
                config.attestation_subnet_extra_bits = u8::MAX;
                Arc::new(config)
            },
            {
                let mut config = Config::minimal();
                config.epochs_per_subnet_subscription = NonZeroU64::MIN;
                Arc::new(config)
            },
            {
                let mut config = Config::minimal();
                config.epochs_per_subnet_subscription = NonZeroU64::MAX;
                Arc::new(config)
            },
            {
                let mut config = Config::minimal();
                config.subnets_per_node = u64::MIN;
                Arc::new(config)
            },
            {
                let mut config = Config::minimal();
                config.subnets_per_node = u64::MAX;
                Arc::new(config)
            },
        ];

        let epochs = [GENESIS_EPOCH, FAR_FUTURE_EPOCH];

        for (node_id, config, epoch) in iproduct!(node_ids, configs, epochs) {
            compute_subscribed_subnets::<Minimal>(node_id, &config, epoch).ok();
        }
    }

    #[test]
    fn test_next_subnet_subscription_epoch() -> Result<()> {
        let node_id = NodeId::from_u64(123_456);
        let config = Config::mainnet();

        for epoch in [100_000, 200_000, 300_000] {
            let current_subscribed_subnets =
                compute_subscribed_subnets::<Mainnet>(node_id, &config, epoch)?.collect_vec();

            let next_subscription_epoch =
                next_subnet_subscription_epoch::<Mainnet>(node_id, &config, epoch)?;

            assert_eq!(
                current_subscribed_subnets,
                compute_subscribed_subnets::<Mainnet>(
                    node_id,
                    &config,
                    next_subscription_epoch - 1
                )?
                .collect_vec(),
            );

            assert_ne!(
                current_subscribed_subnets,
                compute_subscribed_subnets::<Mainnet>(node_id, &config, next_subscription_epoch)?
                    .collect_vec(),
            );
        }

        Ok(())
    }
}
