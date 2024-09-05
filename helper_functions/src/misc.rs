use core::{
    num::NonZeroU64,
    ops::{Div as _, Range, Shr as _},
};

use anyhow::{ensure, Result};
use arithmetic::{U64Ext as _, UsizeExt as _};
use bls::PublicKeyBytes;
use hashing::ZERO_HASHES;
use itertools::{izip, Itertools as _};
use ssz::{BitVector, ContiguousVector, MerkleElements, MerkleTree, SszHash};
use tap::{Pipe as _, TryConv as _};
use typenum::Unsigned as _;
use types::{
    altair::{consts::SyncCommitteeSubnetCount, primitives::SyncCommitteePeriod},
    cache::PackedIndices,
    combined::SignedBeaconBlock,
    config::Config,
    deneb::{
        consts::{BlobSidecarSubnetCount, VERSIONED_HASH_VERSION_KZG},
        containers::BlobSidecar,
        primitives::{Blob, BlobIndex, KzgCommitment, KzgProof, VersionedHash},
    },
    phase0::{
        consts::{
            AttestationSubnetCount, BLS_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX,
            GENESIS_EPOCH, GENESIS_SLOT,
        },
        containers::{ForkData, SigningData},
        primitives::{
            CommitteeIndex, Domain, DomainType, Epoch, ExecutionAddress, ForkDigest, NodeId, Slot,
            SubnetId, Uint256, UnixSeconds, ValidatorIndex, Version, H256,
        },
    },
    preset::{Preset, SyncSubcommitteeSize},
    traits::{
        BeaconState, PostAltairBeaconState, PostDenebBeaconBlockBody, SignedBeaconBlock as _,
    },
};

use crate::{accessors, error::Error};

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

// `consensus-specs` uses this in at least 2 places:
// - <https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md#compute_slots_since_epoch_start>
// - <https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#broadcast-attestation>
#[must_use]
pub fn slots_since_epoch_start<P: Preset>(slot: Slot) -> u64 {
    slot - compute_start_slot_at_epoch::<P>(compute_epoch_at_slot::<P>(slot))
}

#[must_use]
pub const fn slots_in_epoch<P: Preset>(epoch: Epoch) -> Range<Slot> {
    compute_start_slot_at_epoch::<P>(epoch)..compute_start_slot_at_epoch::<P>(epoch + 1)
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
    epoch + 1 + P::MAX_SEED_LOOKAHEAD
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
#[must_use]
pub fn compute_fork_digest(current_version: Version, genesis_validators_root: H256) -> ForkDigest {
    let root = compute_fork_data_root(current_version, genesis_validators_root);
    ForkDigest::from_slice(&root[..ForkDigest::len_bytes()])
}

pub(crate) fn compute_domain(
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

pub(crate) fn compute_proposer_index<P: Preset>(
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
#[must_use]
pub fn compute_subnet_for_blob_sidecar(blob_index: BlobIndex) -> SubnetId {
    blob_index.mod_typenum::<BlobSidecarSubnetCount>()
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
    state.genesis_time() + slots_since_genesis * config.seconds_per_slot.get()
}

#[must_use]
pub fn committee_count_from_active_validator_count<P: Preset>(active_validator_count: u64) -> u64 {
    active_validator_count
        .div_typenum::<P::SlotsPerEpoch>()
        .div(P::TARGET_COMMITTEE_SIZE)
        .clamp(1, P::MAX_COMMITTEES_PER_SLOT.get())
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

// TODO(feature/deneb): Consider extracting a type alias for the inclusion proof.
pub fn kzg_commitment_inclusion_proof<P: Preset>(
    body: &(impl PostDenebBeaconBlockBody<P> + ?Sized),
    commitment_index: BlobIndex,
) -> Result<ContiguousVector<H256, P::KzgCommitmentInclusionProofDepth>> {
    let depth = P::KzgCommitmentInclusionProofDepth::USIZE;

    let mut proof = ContiguousVector::default();

    // TODO(feature/deneb): Try to break this up into something more readable.
    let mut merkle_tree = MerkleTree::<
        <P::MaxBlobCommitmentsPerBlock as MerkleElements<KzgCommitment>>::UnpackedMerkleTreeDepth,
    >::default();

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
            hashing::hash_256_256(
                body.attester_slashings().hash_tree_root(),
                body.attestations().hash_tree_root(),
            ),
            hashing::hash_256_256(
                body.deposits().hash_tree_root(),
                body.voluntary_exits().hash_tree_root(),
            ),
        ),
    );

    Ok(proof)
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

pub fn construct_blob_sidecars<P: Preset>(
    signed_block: &SignedBeaconBlock<P>,
    blobs: impl Iterator<Item = Blob<P>>,
    proofs: impl Iterator<Item = KzgProof>,
) -> Result<Vec<BlobSidecar<P>>> {
    if let Some(post_deneb_block_body) = signed_block.message().body().post_deneb() {
        let commitments = post_deneb_block_body.blob_kzg_commitments();
        let signed_block_header = signed_block.to_header();

        return izip!(0.., blobs, proofs, commitments)
            .map(|(index, blob, kzg_proof, kzg_commitment)| {
                Ok(BlobSidecar::<P> {
                    index,
                    blob,
                    kzg_commitment: *kzg_commitment,
                    kzg_proof,
                    signed_block_header,
                    kzg_commitment_inclusion_proof: kzg_commitment_inclusion_proof(
                        post_deneb_block_body,
                        index,
                    )?,
                })
            })
            .collect();
    }

    Ok(vec![])
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
        preset::Minimal,
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
            &state,
            accessors::active_validator_indices_ordered(&state, RelativeEpoch::Current),
            H256::random(),
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
}
