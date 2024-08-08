use core::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;

use arithmetic::NonZeroExt as _;
use builder_api::consts::{
    BUILDER_PROPOSAL_DELAY_TOLERANCE, DOMAIN_APPLICATION_BUILDER,
    EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION, PREFERRED_EXECUTION_GAS_LIMIT,
};
use byteorder::LittleEndian;
use serde::Serialize;
use ssz::Endianness;
use static_assertions::assert_type_eq_all;
use typenum::Unsigned as _;
use types::{
    altair::consts::{
        SyncCommitteeSubnetCount, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_SYNC_COMMITTEE,
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, PROPOSER_WEIGHT, SYNC_REWARD_WEIGHT,
        TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE, TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT,
        TIMELY_SOURCE_FLAG_INDEX, TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_FLAG_INDEX,
        TIMELY_TARGET_WEIGHT, WEIGHT_DENOMINATOR,
    },
    bellatrix::primitives::Gas,
    capella::consts::DOMAIN_BLS_TO_EXECUTION_CHANGE,
    config::Config,
    phase0::{
        consts::{
            AttestationSubnetCount, DepositContractTreeDepth, JustificationBitsLength,
            ATTESTATION_PROPAGATION_SLOT_RANGE, BASE_REWARDS_PER_EPOCH, BLS_WITHDRAWAL_PREFIX,
            DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
            DOMAIN_DEPOSIT, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
            ETH1_ADDRESS_WITHDRAWAL_PREFIX, FAR_FUTURE_EPOCH, GENESIS_EPOCH, GENESIS_SLOT,
            INTERVALS_PER_SLOT, TARGET_AGGREGATORS_PER_COMMITTEE,
        },
        primitives::{DomainType, Epoch, NodeId, Slot},
    },
    preset::{AltairPreset, BellatrixPreset, CapellaPreset, DenebPreset, Phase0Preset, Preset},
};

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct FullConfig {
    // Variables configurable through presets and configurations
    #[serde(flatten)]
    phase0_preset: Phase0Preset,
    #[serde(flatten)]
    altair_preset: AltairPreset,
    #[serde(flatten)]
    bellatrix_preset: BellatrixPreset,
    #[serde(flatten)]
    capella_preset: CapellaPreset,
    #[serde(flatten)]
    deneb_preset: DenebPreset,
    #[serde(flatten)]
    config: Arc<Config>,

    // The remaining fields represent constants.
    //
    // The Eth Beacon Node API specification states that the response should include them:
    // <https://ethereum.github.io/beacon-APIs/#/Config/getSpec>
    //
    // Some API clients expect them:
    // <https://github.com/sigp/lighthouse/issues/2638>

    // Phase 0 miscellaneous beacon chain constants
    #[serde(with = "serde_utils::string_or_native")]
    base_rewards_per_epoch: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    deposit_contract_tree_depth: usize,
    endianness: &'static str,
    #[serde(with = "serde_utils::string_or_native")]
    far_future_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    genesis_epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    genesis_slot: Slot,
    #[serde(with = "serde_utils::string_or_native")]
    justification_bits_length: NonZeroU64,

    // Phase 0 withdrawal prefixes
    #[serde(with = "serde_utils::prefixed_hex_or_bytes_slice")]
    bls_withdrawal_prefix: &'static [u8],
    #[serde(with = "serde_utils::prefixed_hex_or_bytes_slice")]
    eth1_address_withdrawal_prefix: &'static [u8],

    // Phase 0 domain types
    domain_aggregate_and_proof: DomainType,
    domain_beacon_attester: DomainType,
    domain_beacon_proposer: DomainType,
    domain_deposit: DomainType,
    domain_randao: DomainType,
    domain_selection_proof: DomainType,
    domain_voluntary_exit: DomainType,

    // Phase 0 beacon chain fork choice constants
    #[serde(with = "serde_utils::string_or_native")]
    intervals_per_slot: NonZeroUsize,

    // Phase 0 networking constants (incomplete)
    #[serde(with = "serde_utils::string_or_native")]
    attestation_propagation_slot_range: u64,
    #[serde(with = "serde_utils::string_or_native")]
    attestation_subnet_count: usize,
    #[serde(with = "serde_utils::string_or_native")]
    node_id_bits: u16,

    // Phase 0 honest validator constants
    #[serde(with = "serde_utils::string_or_native")]
    target_aggregators_per_committee: NonZeroU64,

    // Altair participation flag indices
    #[serde(with = "serde_utils::string_or_native")]
    timely_head_flag_index: usize,
    #[serde(with = "serde_utils::string_or_native")]
    timely_source_flag_index: usize,
    #[serde(with = "serde_utils::string_or_native")]
    timely_target_flag_index: usize,

    // Altair incentivization weights
    #[serde(with = "serde_utils::string_or_native")]
    proposer_weight: u64,
    #[serde(with = "serde_utils::string_or_native")]
    sync_reward_weight: u64,
    #[serde(with = "serde_utils::string_or_native")]
    timely_head_weight: u64,
    #[serde(with = "serde_utils::string_or_native")]
    timely_source_weight: u64,
    #[serde(with = "serde_utils::string_or_native")]
    timely_target_weight: u64,
    #[serde(with = "serde_utils::string_or_native")]
    weight_denominator: NonZeroU64,

    // Altair domain types
    domain_contribution_and_proof: DomainType,
    domain_sync_committee: DomainType,
    domain_sync_committee_selection_proof: DomainType,

    // Altair honest validator constants
    #[serde(with = "serde_utils::string_or_native")]
    sync_committee_subnet_count: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    target_aggregators_per_sync_subcommittee: NonZeroU64,

    // Capella domain types
    domain_bls_to_execution_change: DomainType,

    // TODO(feature/deneb): Add constants from the Polynomial Commitments specification if needed.

    // Builder constants
    #[serde(with = "serde_utils::string_or_native")]
    builder_proposal_delay_tolerance: u64,
    domain_application_builder: DomainType,
    #[serde(with = "serde_utils::string_or_native")]
    epochs_per_validator_registration_submission: u64,
    #[serde(with = "serde_utils::string_or_native")]
    preferred_execution_gas_limit: Gas,
}

impl FullConfig {
    pub fn new<P: Preset>(config: Arc<Config>) -> Self {
        assert_type_eq_all!(Endianness, LittleEndian);

        let endianness = "little";

        Self {
            // Variables configurable through presets and configurations
            phase0_preset: Phase0Preset::new::<P>(),
            altair_preset: AltairPreset::new::<P>(),
            bellatrix_preset: BellatrixPreset::new::<P>(),
            capella_preset: CapellaPreset::new::<P>(),
            deneb_preset: DenebPreset::new::<P>(),
            config,

            // Phase 0 miscellaneous beacon chain constants
            base_rewards_per_epoch: BASE_REWARDS_PER_EPOCH,
            deposit_contract_tree_depth: DepositContractTreeDepth::USIZE,
            endianness,
            far_future_epoch: FAR_FUTURE_EPOCH,
            genesis_epoch: GENESIS_EPOCH,
            genesis_slot: GENESIS_SLOT,
            justification_bits_length: JustificationBitsLength::non_zero(),

            // Phase 0 withdrawal prefixes
            bls_withdrawal_prefix: BLS_WITHDRAWAL_PREFIX,
            eth1_address_withdrawal_prefix: ETH1_ADDRESS_WITHDRAWAL_PREFIX,

            // Phase 0 domain types
            domain_aggregate_and_proof: DOMAIN_AGGREGATE_AND_PROOF,
            domain_beacon_attester: DOMAIN_BEACON_ATTESTER,
            domain_beacon_proposer: DOMAIN_BEACON_PROPOSER,
            domain_deposit: DOMAIN_DEPOSIT,
            domain_randao: DOMAIN_RANDAO,
            domain_selection_proof: DOMAIN_SELECTION_PROOF,
            domain_voluntary_exit: DOMAIN_VOLUNTARY_EXIT,

            // Phase 0 beacon chain fork choice constants
            intervals_per_slot: INTERVALS_PER_SLOT,

            // Phase 0 networking constants (incomplete)
            attestation_propagation_slot_range: ATTESTATION_PROPAGATION_SLOT_RANGE,
            attestation_subnet_count: AttestationSubnetCount::USIZE,
            node_id_bits: NodeId::BITS,

            // Phase 0 honest validator constants
            target_aggregators_per_committee: TARGET_AGGREGATORS_PER_COMMITTEE,

            // Altair participation flag indices
            timely_head_flag_index: TIMELY_HEAD_FLAG_INDEX,
            timely_source_flag_index: TIMELY_SOURCE_FLAG_INDEX,
            timely_target_flag_index: TIMELY_TARGET_FLAG_INDEX,

            // Altair incentivization weights
            proposer_weight: PROPOSER_WEIGHT,
            sync_reward_weight: SYNC_REWARD_WEIGHT,
            timely_head_weight: TIMELY_HEAD_WEIGHT,
            timely_source_weight: TIMELY_SOURCE_WEIGHT,
            timely_target_weight: TIMELY_TARGET_WEIGHT,
            weight_denominator: WEIGHT_DENOMINATOR,

            // Altair domain types
            domain_contribution_and_proof: DOMAIN_CONTRIBUTION_AND_PROOF,
            domain_sync_committee: DOMAIN_SYNC_COMMITTEE,
            domain_sync_committee_selection_proof: DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,

            // Altair honest validator constants
            sync_committee_subnet_count: SyncCommitteeSubnetCount::non_zero(),
            target_aggregators_per_sync_subcommittee: TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,

            // Capella domain types
            domain_bls_to_execution_change: DOMAIN_BLS_TO_EXECUTION_CHANGE,

            // Builder constants
            builder_proposal_delay_tolerance: BUILDER_PROPOSAL_DELAY_TOLERANCE,
            domain_application_builder: DOMAIN_APPLICATION_BUILDER,
            epochs_per_validator_registration_submission:
                EPOCHS_PER_VALIDATOR_REGISTRATION_SUBMISSION,
            preferred_execution_gas_limit: PREFERRED_EXECUTION_GAS_LIMIT,
        }
    }
}

#[cfg(test)]
mod tests {
    use types::preset::Mainnet;

    use super::*;

    #[test]
    fn full_config_json_contains_no_numbers() {
        let full_config = FullConfig::new::<Mainnet>(Arc::new(Config::mainnet()));

        serde_utils::assert_json_contains_no_numbers(full_config);
    }
}
