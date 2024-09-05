use core::{
    num::NonZeroU64,
    ops::{Div as _, Index as _},
};

use anyhow::{ensure, Error as AnyhowError, Result};
use arithmetic::U64Ext as _;
use bit_field::BitField as _;
use bls::SignatureBytes;
use itertools::Itertools as _;
use ssz::SszHash as _;
use tap::TryConv as _;
use typenum::Unsigned as _;
use types::{
    altair::consts::{SyncCommitteeSubnetCount, TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE},
    combined::BeaconState as CombinedBeaconState,
    config::Config,
    deneb::{containers::BlobSidecar, primitives::BlobIndex},
    phase0::{
        consts::{
            ETH1_ADDRESS_WITHDRAWAL_PREFIX, FAR_FUTURE_EPOCH, TARGET_AGGREGATORS_PER_COMMITTEE,
        },
        containers::{AttestationData, IndexedAttestation, Validator},
        primitives::{CommitteeIndex, Epoch, Gwei, Slot, H256},
    },
    preset::Preset,
    traits::{BeaconState, PostBellatrixBeaconBlockBody, PostBellatrixBeaconState},
};

use crate::{
    accessors,
    error::{Error, SignatureKind},
    signing::SignForSingleFork as _,
    verifier::Verifier,
};

// > Check if ``validator`` is active.
#[inline]
#[must_use]
pub const fn is_active_validator(validator: &Validator, epoch: Epoch) -> bool {
    validator.activation_epoch <= epoch && epoch < validator.exit_epoch
}

// > Check if ``validator`` is eligible to be placed into the activation queue.
#[must_use]
pub const fn is_eligible_for_activation_queue<P: Preset>(validator: &Validator) -> bool {
    validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH
        && validator.effective_balance == P::MAX_EFFECTIVE_BALANCE
}

// > Check if ``validator`` is eligible for activation.
#[must_use]
pub fn is_eligible_for_activation<P: Preset>(
    state: &impl BeaconState<P>,
    validator: &Validator,
) -> bool {
    // > Placement in queue is finalized
    validator.activation_eligibility_epoch <= state.finalized_checkpoint().epoch
        // > Has not yet been activated
        && validator.activation_epoch == FAR_FUTURE_EPOCH
}

#[inline]
#[must_use]
pub const fn is_eligible_for_penalties(validator: &Validator, previous_epoch: Epoch) -> bool {
    is_active_validator(validator, previous_epoch)
        || (validator.slashed && previous_epoch + 1 < validator.withdrawable_epoch)
}

// > Check if ``validator`` is slashable.
#[inline]
#[must_use]
pub const fn is_slashable_validator(validator: &Validator, epoch: Epoch) -> bool {
    !validator.slashed
        && epoch < validator.withdrawable_epoch
        && validator.activation_epoch <= epoch
}

// > Check if ``data_1`` and ``data_2`` are slashable according to Casper FFG rules.
#[inline]
#[must_use]
pub fn is_slashable_attestation_data(data_1: AttestationData, data_2: AttestationData) -> bool {
    (data_1 != data_2 && data_1.target.epoch == data_2.target.epoch)
        || (data_1.source.epoch < data_2.source.epoch && data_2.target.epoch < data_1.target.epoch)
}

// This doesn't verify the signature when called directly with `MultiVerifier`.
// When calling directly, use `SingleVerifier` or call `finalize` manually.
pub fn validate_constructed_indexed_attestation<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    indexed_attestation: &IndexedAttestation<P>,
    verifier: impl Verifier,
) -> Result<()> {
    validate_indexed_attestation(config, state, indexed_attestation, verifier, false)
}

pub fn validate_received_indexed_attestation<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    indexed_attestation: &IndexedAttestation<P>,
    verifier: impl Verifier,
) -> Result<()> {
    validate_indexed_attestation(config, state, indexed_attestation, verifier, true)
}

fn validate_indexed_attestation<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
    indexed_attestation: &IndexedAttestation<P>,
    mut verifier: impl Verifier,
    validate_indices_sorted_and_unique: bool,
) -> Result<()> {
    let indices = &indexed_attestation.attesting_indices;

    ensure!(!indices.is_empty(), Error::AttestationHasNoAttestingIndices);

    if validate_indices_sorted_and_unique {
        // > Verify indices are sorted and unique
        ensure!(
            indices.iter().tuple_windows().all(|(a, b)| a < b),
            Error::AttestingIndicesNotSortedAndUnique,
        );
    }

    // > Verify aggregate signature
    itertools::process_results(
        indices.iter().copied().map(|validator_index| {
            accessors::public_key(state, validator_index)?
                .decompress()
                .map_err(AnyhowError::new)
        }),
        |public_keys| {
            verifier.verify_aggregate(
                indexed_attestation.data.signing_root(config, state),
                indexed_attestation.signature,
                public_keys,
                SignatureKind::Attestation,
            )
        },
    )?
}

/// <https://github.com/ethereum/consensus-specs/blob/5e83e60a594c1d855d1396b8e25fbf43af913577/specs/phase0/validator.md#aggregation-selection>
pub fn is_aggregator<P: Preset>(
    state: &impl BeaconState<P>,
    slot: Slot,
    committee_index: CommitteeIndex,
    slot_signature: SignatureBytes,
) -> Result<bool> {
    let committee = accessors::beacon_committee(state, slot, committee_index)?;

    let dividend = hashing::hash_768(slot_signature)
        .index(..size_of::<u64>())
        .try_into()
        .map(u64::from_le_bytes)
        .expect("slice has the same length as u64");

    let modulo = committee
        .len()
        .try_conv::<u64>()?
        .div(TARGET_AGGREGATORS_PER_COMMITTEE)
        .try_into()
        .unwrap_or(NonZeroU64::MIN);

    Ok(dividend.is_multiple_of(modulo))
}

/// <https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/altair/validator.md#aggregation-selection>
#[must_use]
pub fn is_sync_committee_aggregator<P: Preset>(signature: SignatureBytes) -> bool {
    let dividend = hashing::hash_768(signature)
        .index(..size_of::<u64>())
        .try_into()
        .map(u64::from_le_bytes)
        .expect("slice has the same length as u64");

    let modulo = P::SyncCommitteeSize::U64
        .div_typenum::<SyncCommitteeSubnetCount>()
        .div(TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE)
        .try_into()
        .unwrap_or(NonZeroU64::MIN);

    dividend.is_multiple_of(modulo)
}

/// [`is_valid_merkle_branch`](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#is_valid_merkle_branch)
#[must_use]
pub fn is_valid_merkle_branch(
    leaf: H256,
    branch: impl IntoIterator<Item = H256>,
    index: u64,
    root: H256,
) -> bool {
    let mut hash = leaf;

    for (height, node) in branch.into_iter().enumerate() {
        if index.get_bit(height) {
            hash = hashing::hash_256_256(node, hash);
        } else {
            hash = hashing::hash_256_256(hash, node);
        }
    }

    hash == root
}

/// [`verify_blob_sidecar_inclusion_proof`](https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/deneb/p2p-interface.md#verify_blob_sidecar_inclusion_proof)
///
/// Renamed to match [`is_valid_merkle_branch`].
#[must_use]
pub fn is_valid_blob_sidecar_inclusion_proof<P: Preset>(blob_sidecar: &BlobSidecar<P>) -> bool {
    // `consensus-specs` calls this `gindex`, but that is another misleading name.
    // This is NOT a generalized index.
    let index_at_commitment_depth = index_at_commitment_depth::<P>(blob_sidecar.index);

    is_valid_merkle_branch(
        blob_sidecar.kzg_commitment.hash_tree_root(),
        blob_sidecar.kzg_commitment_inclusion_proof,
        index_at_commitment_depth,
        blob_sidecar.signed_block_header.message.body_root,
    )
}

/// <https://github.com/ethereum/consensus-specs/blob/f7da1a38347155589f5e0403ad3290ffb77f4da6/specs/phase0/beacon-chain.md#helpers>
#[must_use]
pub fn is_in_inactivity_leak<P: Preset>(state: &impl BeaconState<P>) -> bool {
    accessors::get_finality_delay(state) > P::MIN_EPOCHS_TO_INACTIVITY_PENALTY
}

/// <https://github.com/ethereum/consensus-specs/blob/8ae93b8265c66851e6140733a074916453dd2660/specs/bellatrix/beacon-chain.md#is_merge_transition_complete>
#[must_use]
pub fn is_merge_transition_complete<P: Preset>(
    state: &(impl PostBellatrixBeaconState<P> + ?Sized),
) -> bool {
    !state.latest_execution_payload_header().is_default_payload()
}

/// <https://github.com/ethereum/consensus-specs/blob/8ae93b8265c66851e6140733a074916453dd2660/specs/bellatrix/beacon-chain.md#is_merge_transition_block>
#[must_use]
pub fn is_merge_transition_block<P: Preset>(
    state: &CombinedBeaconState<P>,
    body: &(impl PostBellatrixBeaconBlockBody<P> + ?Sized),
) -> bool {
    state.post_bellatrix().is_some_and(|state| {
        !is_merge_transition_complete(state) && !body.execution_payload().is_default_payload()
    })
}

// TODO(feature/disco-states-alternative-develop): The `state` parameter appears to be unused.
//                                                 Payloads cannot be empty after the Merge.
//                                                 Wait for a response from other developers.
/// <https://github.com/ethereum/consensus-specs/blob/8ae93b8265c66851e6140733a074916453dd2660/specs/bellatrix/beacon-chain.md#is_execution_enabled>
///
/// The [`is_merge_transition_complete`] call is needed to reject default payloads after the Merge,
/// but all test cases in `consensus-spec-tests` pass if it is removed.
#[must_use]
pub fn is_execution_enabled<P: Preset>(
    state: &(impl PostBellatrixBeaconState<P> + ?Sized),
    body: &(impl PostBellatrixBeaconBlockBody<P> + ?Sized),
) -> bool {
    is_merge_transition_complete(state) || !body.execution_payload().is_default_payload()
}

/// [`has_eth1_withdrawal_credential`](https://github.com/ethereum/consensus-specs/blob/dc17b1e2b6a4ec3a2104c277a33abae75a43b0fa/specs/capella/beacon-chain.md#has_eth1_withdrawal_credential)
///
/// > Check if ``validator`` has an 0x01 prefixed "eth1" withdrawal credential.
#[must_use]
pub fn has_eth1_withdrawal_credential(validator: &Validator) -> bool {
    validator
        .withdrawal_credentials
        .as_bytes()
        .starts_with(ETH1_ADDRESS_WITHDRAWAL_PREFIX)
}

/// [`is_fully_withdrawable_validator`](https://github.com/ethereum/consensus-specs/blob/dc17b1e2b6a4ec3a2104c277a33abae75a43b0fa/specs/capella/beacon-chain.md#is_fully_withdrawable_validator)
///
/// > Check if ``validator`` is fully withdrawable.
pub fn is_fully_withdrawable_validator(validator: &Validator, balance: Gwei, epoch: Epoch) -> bool {
    has_eth1_withdrawal_credential(validator)
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
    has_eth1_withdrawal_credential(validator) && has_max_effective_balance && has_excess_balance
}

const fn index_at_commitment_depth<P: Preset>(commitment_index: BlobIndex) -> u64 {
    // When using the minimal preset, `commitment_index` should be in the range `0..16`.
    // 16 is the value of `MAX_BLOB_COMMITMENTS_PER_BLOCK`.
    //
    // The Merkle tree that makes up Deneb `BeaconBlockBody` looks like this:
    // ```text
    // 1┬─2┬─4┬─8┬16 body.randao_reveal
    //  │  │  │  └17 body.eth1_data
    //  │  │  └─9┬18 body.graffiti
    //  │  │     └19 body.proposer_slashings
    //  │  └─5┬10┬20 body.attester_slashings
    //  │     │  └21 body.attestations
    //  │     └11┬22 body.deposits
    //  │        └23 body.voluntary_exits
    //  └─3──6┬12┬24 body.sync_aggregate
    //        │  └25 body.execution_payload
    //        └13┬26 body.bls_to_execution_changes
    //           └27 body.blob_kzg_commitments
    //
    // 27┬─54┬108┬216┬432┬864 body.blob_kzg_commitments[0]
    //   │   │   │   │   └865 body.blob_kzg_commitments[1]
    //   │   │   │   └433┬866 body.blob_kzg_commitments[2]
    //   │   │   │       └867 body.blob_kzg_commitments[3]
    //   │   │   └217┬434┬868 body.blob_kzg_commitments[4]
    //   │   │       │   └869 body.blob_kzg_commitments[5]
    //   │   │       └435┬870 body.blob_kzg_commitments[6]
    //   │   │           └871 body.blob_kzg_commitments[7]
    //   │   └109┬218┬436┬872 body.blob_kzg_commitments[8]
    //   │       │   │   └873 body.blob_kzg_commitments[9]
    //   │       │   └437┬874 body.blob_kzg_commitments[10]
    //   │       │       └875 body.blob_kzg_commitments[11]
    //   │       └219┬438┬876 body.blob_kzg_commitments[12]
    //   │           │   └877 body.blob_kzg_commitments[13]
    //   │           └439┬878 body.blob_kzg_commitments[14]
    //   │               └879 body.blob_kzg_commitments[15]
    //   └─55                 body.blob_kzg_commitments.len()
    // ```
    //
    // Indices in the diagram above are generalized indices.
    // `consensus-specs` uses them to define Merkle proofs.
    // They have some useful properties, but they cannot be used to verify proofs directly.
    // `is_valid_merkle_branch` requires indices like these:
    // ```text
    // ┄┬───┬───┬───┬352 body.blob_kzg_commitments[0]
    //  │   │   │   └353 body.blob_kzg_commitments[1]
    //  │   │   └───┬354 body.blob_kzg_commitments[2]
    //  │   │       └355 body.blob_kzg_commitments[3]
    //  │   └───┬───┬356 body.blob_kzg_commitments[4]
    //  │       │   └357 body.blob_kzg_commitments[5]
    //  │       └───┬358 body.blob_kzg_commitments[6]
    //  │           └359 body.blob_kzg_commitments[7]
    //  └───┬───┬───┬360 body.blob_kzg_commitments[8]
    //      │   │   └361 body.blob_kzg_commitments[9]
    //      │   └───┬362 body.blob_kzg_commitments[10]
    //      │       └363 body.blob_kzg_commitments[11]
    //      └───┬───┬364 body.blob_kzg_commitments[12]
    //          │   └365 body.blob_kzg_commitments[13]
    //          └───┬366 body.blob_kzg_commitments[14]
    //              └367 body.blob_kzg_commitments[15]
    // ```
    // The index of commitment 0 is offset by 352 because of preceding fields in `BeaconBlockBody`.
    let fields_before_blob_kzg_commitments = 11;
    let indices_per_field_without_length = P::MaxBlobCommitmentsPerBlock::U64;
    let indices_per_field_with_length = 2 * indices_per_field_without_length;
    let index_of_commitment_0 = fields_before_blob_kzg_commitments * indices_per_field_with_length;
    index_of_commitment_0 + commitment_index
}

#[cfg(test)]
mod spec_tests {
    use duplicate::duplicate_item;
    use serde::Deserialize;
    use spec_test_utils::Case;
    use ssz::{ContiguousVector, SszHash, SszRead};
    use test_generator::test_resources;
    use try_from_iterator::TryFromIterator as _;
    use types::{
        capella::containers::BeaconBlockBody as CapellaBeaconBlockBody,
        deneb::containers::BeaconBlockBody as DenebBeaconBlockBody,
        nonstandard::Phase,
        phase0::containers::SignedBeaconBlockHeader,
        preset::{Mainnet, Minimal},
    };

    use crate::misc;

    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Proof {
        leaf: H256,
        leaf_index: u64,
        branch: Vec<H256>,
    }

    #[duplicate_item(
        glob                                                                                           function_name                    preset    phase;
        ["consensus-spec-tests/tests/mainnet/altair/light_client/single_merkle_proof/*/*"]             [altair_mainnet_beacon_state]    [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/light_client/single_merkle_proof/*/*"]             [altair_minimal_beacon_state]    [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/bellatrix/light_client/single_merkle_proof/*/*/"]         [bellatrix_mainnet_beacon_state] [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/light_client/single_merkle_proof/*/*/"]         [bellatrix_minimal_beacon_state] [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/capella/light_client/single_merkle_proof/BeaconState/*/"] [capella_mainnet_beacon_state]   [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/light_client/single_merkle_proof/BeaconState/*/"] [capella_minimal_beacon_state]   [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/deneb/light_client/single_merkle_proof/BeaconState/*/"]   [deneb_mainnet_beacon_state]     [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/light_client/single_merkle_proof/BeaconState/*/"]   [deneb_minimal_beacon_state]     [Minimal] [Deneb];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let config = preset::default_config().start_and_stay_in(Phase::phase);
        run_light_client_case::<_, CombinedBeaconState<preset>>(&config, case);
    }

    #[duplicate_item(
        glob                                                                                               function_name                       object_type;
        ["consensus-spec-tests/tests/mainnet/capella/light_client/single_merkle_proof/BeaconBlockBody/*/"] [capella_mainnet_beacon_block_body] [CapellaBeaconBlockBody<Mainnet>];
        ["consensus-spec-tests/tests/minimal/capella/light_client/single_merkle_proof/BeaconBlockBody/*/"] [capella_minimal_beacon_block_body] [CapellaBeaconBlockBody<Minimal>];
        ["consensus-spec-tests/tests/mainnet/deneb/light_client/single_merkle_proof/BeaconBlockBody/*/"]   [deneb_mainnet_beacon_block_body]   [DenebBeaconBlockBody<Mainnet>];
        ["consensus-spec-tests/tests/minimal/deneb/light_client/single_merkle_proof/BeaconBlockBody/*/"]   [deneb_minimal_beacon_block_body]   [DenebBeaconBlockBody<Minimal>];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_light_client_case::<(), object_type>(&(), case);
    }

    #[duplicate_item(
        glob                                                                                            function_name                            preset;
        ["consensus-spec-tests/tests/mainnet/deneb/merkle_proof/single_merkle_proof/BeaconBlockBody/*"] [deneb_mainnet_beacon_block_body_proofs] [Mainnet];
        ["consensus-spec-tests/tests/minimal/deneb/merkle_proof/single_merkle_proof/BeaconBlockBody/*"] [deneb_minimal_beacon_block_body_proofs] [Minimal];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let Proof {
            leaf,
            leaf_index,
            branch,
        } = case.yaml("proof");

        // TODO(feature/deneb): Review how `commitment_index` is calculated.
        //                      See if `consensus-specs` has anything similar.
        //                      Consider rewriting to match `consensus-specs`.
        // Unlike the name suggests, `leaf_index` is actually a generalized index.
        // `is_valid_merkle_branch` expects an index that includes only leaves.
        let commitment_index = leaf_index % <preset as Preset>::MaxBlobCommitmentsPerBlock::U64;
        let index_at_commitment_depth = index_at_commitment_depth::<preset>(commitment_index);

        let block_body = case.ssz_default::<DenebBeaconBlockBody<preset>>("object");

        // > Check that `is_valid_merkle_branch` confirms `leaf` at `leaf_index` to verify
        // > against `has_tree_root(state)` and `proof`.
        assert!(is_valid_merkle_branch(
            leaf,
            branch.iter().copied(),
            index_at_commitment_depth,
            block_body.hash_tree_root(),
        ));

        // Reuse `merkle_proof` test cases to test `is_valid_blob_sidecar_inclusion_proof`.
        assert!(is_valid_blob_sidecar_inclusion_proof(
            &incomplete_blob_sidecar(commitment_index, &block_body, branch.iter().copied())
                .expect("blob sidecar should be constructed successfully")
        ));

        let proof = misc::kzg_commitment_inclusion_proof(&block_body, commitment_index)
            .expect("inclusion proof should be constructed successfully");

        // > If the implementation supports generating merkle proofs, check that the
        // > self-generated proof matches the `proof` provided with the test.
        assert_eq!(proof.as_slice(), branch);
    }

    fn run_light_client_case<C, T: SszRead<C> + SszHash>(context: &C, case: Case) {
        let Proof {
            leaf,
            leaf_index,
            branch,
        } = case.yaml("proof");

        // Unlike the name suggests, `leaf_index` is actually a generalized index.
        // `is_valid_merkle_branch` expects an index that includes only leaves.
        let index_at_leaf_depth = leaf_index - leaf_index.prev_power_of_two();

        let root = case.ssz::<_, T>(context, "object").hash_tree_root();

        // > Check that `is_valid_merkle_branch` confirms `leaf` at `leaf_index` to verify
        // > against `has_tree_root(state)` and `proof`.
        assert!(is_valid_merkle_branch(
            leaf,
            branch,
            index_at_leaf_depth,
            root,
        ));

        // We do not implement the following assertion:
        // > If the implementation supports generating merkle proofs, check that the
        // > self-generated proof matches the `proof` provided with the test.
        //
        // We do not have code that can construct a proof for an arbitrary index.
        // We can construct proofs for specific indices if needed.
        // We do that for blob KZG commitments in beacon block bodies.
    }

    // `merkle_proof` test cases do not contain enough information to construct a valid sidecar,
    // but this should be enough to test `is_valid_blob_sidecar_inclusion_proof`.
    fn incomplete_blob_sidecar<P: Preset>(
        commitment_index: BlobIndex,
        body: &DenebBeaconBlockBody<P>,
        inclusion_proof: impl IntoIterator<Item = H256>,
    ) -> Result<BlobSidecar<P>> {
        let mut signed_block_header = SignedBeaconBlockHeader::default();
        signed_block_header.message.body_root = body.hash_tree_root();

        Ok(BlobSidecar {
            index: commitment_index,
            kzg_commitment: body.blob_kzg_commitments[usize::try_from(commitment_index)?],
            signed_block_header,
            kzg_commitment_inclusion_proof: ContiguousVector::try_from_iter(inclusion_proof)?,
            ..BlobSidecar::default()
        })
    }
}

#[cfg(test)]
mod extra_tests {
    use bls::{SecretKey, SecretKeyBytes};
    use std_ext::CopyExt as _;
    use tap::Conv as _;
    use types::{
        phase0::{
            beacon_state::BeaconState as Phase0BeaconState, consts::FAR_FUTURE_EPOCH,
            containers::Checkpoint,
        },
        preset::Mainnet,
    };

    use crate::verifier::SingleVerifier;

    use super::*;

    #[test]
    fn test_not_activated() {
        let validator = inactive_validator();
        let epoch = 10;

        assert!(!is_active_validator(&validator, epoch));
    }

    #[test]
    fn test_activated() {
        let validator = Validator {
            activation_epoch: 4,
            ..inactive_validator()
        };
        let epoch = 10;

        assert!(is_active_validator(&validator, epoch));
    }

    #[test]
    fn test_exited() {
        let validator = Validator {
            exit_epoch: 10,
            ..inactive_validator()
        };
        let epoch = 10;

        assert!(!is_active_validator(&validator, epoch));
    }

    #[test]
    fn test_already_slashed() {
        let validator = Validator {
            slashed: true,
            ..exiting_validator()
        };
        let epoch = 10;

        assert!(!is_slashable_validator(&validator, epoch));
    }

    #[test]
    fn test_not_slashable_not_active() {
        let validator = inactive_validator();
        let epoch = 10;

        assert!(!is_slashable_validator(&validator, epoch));
    }

    #[test]
    fn test_not_slashable_withdrawable() {
        let validator = exiting_validator();
        let epoch = 11;

        assert!(!is_slashable_validator(&validator, epoch));
    }

    #[test]
    fn test_slashable() {
        let validator = exiting_validator();
        let epoch = 10;

        assert!(is_slashable_validator(&validator, epoch));
    }

    #[test]
    fn test_double_vote_attestation_data() {
        let data_1 = AttestationData {
            target: Checkpoint {
                root: H256::repeat_byte(1),
                ..Checkpoint::default()
            },
            ..AttestationData::default()
        };
        let data_2 = AttestationData::default();

        assert!(is_slashable_attestation_data(data_1, data_2));
    }

    #[test]
    fn test_equal_attestation_data() {
        let data_1 = AttestationData::default();
        let data_2 = AttestationData::default();

        assert!(!is_slashable_attestation_data(data_1, data_2));
    }

    #[test]
    fn test_surround_vote_attestation_data() {
        let data_1 = AttestationData {
            source: Checkpoint {
                epoch: 0,
                ..Checkpoint::default()
            },
            target: Checkpoint {
                epoch: 4,
                ..Checkpoint::default()
            },
            ..AttestationData::default()
        };
        let data_2 = AttestationData {
            source: Checkpoint {
                epoch: 1,
                ..Checkpoint::default()
            },
            target: Checkpoint {
                epoch: 3,
                ..Checkpoint::default()
            },
            ..AttestationData::default()
        };

        assert!(is_slashable_attestation_data(data_1, data_2));
    }

    #[test]
    fn test_not_slashable_attestation_data() {
        let data_1 = AttestationData {
            source: Checkpoint {
                epoch: 0,
                ..Checkpoint::default()
            },
            target: Checkpoint {
                epoch: 4,
                ..Checkpoint::default()
            },
            ..AttestationData::default()
        };
        let data_2 = AttestationData {
            source: Checkpoint {
                epoch: 4,
                root: H256::repeat_byte(1),
            },
            target: Checkpoint {
                epoch: 5,
                root: H256::repeat_byte(1),
            },
            ..AttestationData::default()
        };

        assert!(!is_slashable_attestation_data(data_1, data_2));
    }

    #[test]
    fn test_valid_merkle_branch() {
        let leaf_00 = H256::repeat_byte(0xaa);
        let leaf_01 = H256::repeat_byte(0xbb);
        let leaf_10 = H256::repeat_byte(0xcc);
        let leaf_11 = H256::repeat_byte(0xdd);

        let internal_0x = hashing::hash_256_256(leaf_00, leaf_01);
        let internal_1x = hashing::hash_256_256(leaf_10, leaf_11);

        let root = hashing::hash_256_256(internal_0x, internal_1x);

        assert!(is_valid_merkle_branch(
            leaf_00,
            [leaf_01, internal_1x],
            0,
            root,
        ));

        assert!(is_valid_merkle_branch(
            leaf_01,
            [leaf_00, internal_1x],
            1,
            root,
        ));

        assert!(is_valid_merkle_branch(
            leaf_10,
            [leaf_11, internal_0x],
            2,
            root,
        ));

        assert!(is_valid_merkle_branch(
            leaf_11,
            [leaf_10, internal_0x],
            3,
            root,
        ));
    }

    #[test]
    fn test_invalid_merkle_branch() {
        let leaf_00 = H256::repeat_byte(0xaa);
        let leaf_01 = H256::repeat_byte(0xbb);
        let leaf_10 = H256::repeat_byte(0xcc);
        let leaf_11 = H256::repeat_byte(0xdd);

        let internal_0x = hashing::hash_256_256(leaf_00, leaf_01);
        let internal_1x = hashing::hash_256_256(leaf_10, leaf_11);

        let root = hashing::hash_256_256(internal_0x, internal_1x);

        assert!(!is_valid_merkle_branch(
            leaf_00,
            // This should be `[leaf_01, internal_1x]`.
            [leaf_01, internal_0x],
            0,
            root,
        ));

        assert!(!is_valid_merkle_branch(
            leaf_11,
            [leaf_10, internal_0x],
            3,
            // This should be `root`.
            H256::repeat_byte(0xff),
        ));

        assert!(!is_valid_merkle_branch(
            leaf_11,
            [leaf_10, internal_0x],
            // This should be `3`.
            0,
            root,
        ));
    }

    #[test]
    fn validate_received_indexed_attestation_index_set_not_sorted() {
        let state = Phase0BeaconState::<Mainnet>::default();

        let attestation = IndexedAttestation {
            attesting_indices: [2, 1, 3].try_into().expect("length is under maximum"),
            ..IndexedAttestation::default()
        };

        validate_received_indexed_attestation(
            &Config::mainnet(),
            &state,
            &attestation,
            SingleVerifier,
        )
        .expect_err("validation should fail");
    }

    #[test]
    fn validate_received_indexed_attestation_nonexistent_validators() {
        let state = Phase0BeaconState::<Mainnet>::default();

        let attestation = IndexedAttestation {
            attesting_indices: [0].try_into().expect("length is under maximum"),
            ..IndexedAttestation::default()
        };

        validate_received_indexed_attestation(
            &Config::mainnet(),
            &state,
            &attestation,
            SingleVerifier,
        )
        .expect_err("validation should fail");
    }

    #[test]
    fn validate_received_indexed_attestation_invalid_signature() {
        let state = Phase0BeaconState::<Mainnet> {
            validators: [
                inactive_validator(),
                inactive_validator(),
                inactive_validator(),
            ]
            .try_into()
            .expect("length is under maximum"),
            ..Phase0BeaconState::default()
        };

        let attestation = IndexedAttestation {
            attesting_indices: [0, 1, 2].try_into().expect("length is under maximum"),
            ..IndexedAttestation::default()
        };

        validate_received_indexed_attestation(
            &Config::mainnet(),
            &state,
            &attestation,
            SingleVerifier,
        )
        .expect_err("validation should fail");
    }

    #[test]
    fn validate_received_indexed_attestation_valid_signature() -> Result<()> {
        let config = Config::mainnet();

        let secret_key_1 = b"????????????????????????????????"
            .copy()
            .conv::<SecretKeyBytes>()
            .try_conv::<SecretKey>()?;

        let secret_key_2 = b"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            .copy()
            .conv::<SecretKeyBytes>()
            .try_conv::<SecretKey>()?;

        let state = Phase0BeaconState::<Mainnet> {
            validators: [
                Validator {
                    pubkey: secret_key_1.to_public_key().into(),
                    ..inactive_validator()
                },
                Validator {
                    pubkey: secret_key_2.to_public_key().into(),
                    ..inactive_validator()
                },
            ]
            .try_into()?,
            ..Phase0BeaconState::default()
        };

        let data = AttestationData {
            beacon_block_root: H256::repeat_byte(0xff),
            ..AttestationData::default()
        };

        let signature_1 = data.sign(&config, &state, &secret_key_1);
        let signature_2 = data.sign(&config, &state, &secret_key_2);

        let aggregate_signature = signature_1.aggregate(signature_2);

        let attestation = IndexedAttestation {
            attesting_indices: [0, 1].try_into()?,
            data,
            signature: aggregate_signature.into(),
        };

        validate_received_indexed_attestation(&config, &state, &attestation, SingleVerifier)
    }

    fn inactive_validator() -> Validator {
        Validator {
            activation_eligibility_epoch: FAR_FUTURE_EPOCH,
            activation_epoch: FAR_FUTURE_EPOCH,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
            ..Validator::default()
        }
    }

    fn exiting_validator() -> Validator {
        Validator {
            exit_epoch: 10,
            withdrawable_epoch: 11,
            ..Validator::default()
        }
    }
}
