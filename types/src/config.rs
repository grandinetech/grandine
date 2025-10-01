use core::{cmp::Ordering, num::NonZeroU64, time::Duration};
use std::{borrow::Cow, collections::BTreeMap};

use derive_more::Constructor;
use enum_iterator::Sequence as _;
use hex_literal::hex;
use nonzero_ext::nonzero;
use once_cell::sync::OnceCell;
use serde::{de::IgnoredAny, Deserialize, Serialize};
use serde_utils::shared::Sortable;
use serde_with::{As, DurationMilliSeconds};
use ssz::{ContiguousList, DynamicList, SszWrite};
use thiserror::Error;
use typenum::Unsigned as _;

use crate::{
    bellatrix::primitives::Difficulty,
    fulu::containers::DataColumnsByRootIdentifier,
    nonstandard::{Phase, Toption},
    phase0::{
        consts::{FAR_FUTURE_EPOCH, GENESIS_EPOCH},
        primitives::{
            ChainId, DomainType, Epoch, ExecutionAddress, ExecutionBlockHash, Gwei, NetworkId,
            Slot, UnixSeconds, Version, H160, H256, H32,
        },
    },
    preset::{Preset, PresetName},
};

/// Configuration variables customizable at runtime.
///
/// See [configurations in `consensus-specs`](https://github.com/ethereum/consensus-specs/tree/aac851f860fa384916f62027b2dbe3318a354c5b/configs).
///
/// The `*_fork_epoch` fields have type `Epoch` for compatibility with standard configurations.
/// `Toption<Epoch>` would be more appropriate.
#[expect(
    clippy::unsafe_derive_deserialize,
    reason = "A false positive triggered by `nonzero!`. \
             `Config` has no invariants. It is intended to be deserialized from user input. \
              The `unsafe` block in `nonzero!` only operates on the literal passed to it."
)]
#[expect(
    clippy::struct_field_names,
    reason = "struct_field_name is allowed to have config_name, as it starts with the same name as struct"
)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "SCREAMING_SNAKE_CASE")]
pub struct Config {
    // Meta
    pub config_name: Cow<'static, str>,
    pub preset_base: PresetName,

    // Genesis
    #[serde(with = "serde_utils::string_or_native")]
    pub genesis_delay: u64,
    pub genesis_fork_version: Version,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_genesis_active_validator_count: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_genesis_time: UnixSeconds,

    // Forking
    #[serde(with = "serde_utils::string_or_native")]
    pub altair_fork_epoch: Epoch,
    pub altair_fork_version: Version,
    #[serde(with = "serde_utils::string_or_native")]
    pub bellatrix_fork_epoch: Epoch,
    pub bellatrix_fork_version: Version,
    #[serde(with = "serde_utils::string_or_native")]
    pub capella_fork_epoch: Epoch,
    pub capella_fork_version: Version,
    #[serde(with = "serde_utils::string_or_native")]
    pub deneb_fork_epoch: Epoch,
    pub deneb_fork_version: Version,
    #[serde(with = "serde_utils::string_or_native")]
    pub electra_fork_epoch: Epoch,
    pub electra_fork_version: Version,
    #[serde(with = "serde_utils::string_or_native")]
    pub fulu_fork_epoch: Epoch,
    pub fulu_fork_version: Version,

    // Time parameters
    #[serde(with = "serde_utils::string_or_native")]
    pub eth1_follow_distance: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_validator_withdrawability_delay: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub seconds_per_eth1_block: u64,
    #[deprecated = "use `Config::slot_duration_ms` instead"]
    #[serde(with = "serde_utils::string_or_native")]
    pub seconds_per_slot: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    pub shard_committee_period: u64,
    #[serde(with = "As::<DurationMilliSeconds<String>>")]
    pub slot_duration_ms: Duration,

    // Validator cycle
    #[serde(with = "serde_utils::string_or_native")]
    pub churn_limit_quotient: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    pub ejection_balance: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub inactivity_score_bias: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    pub inactivity_score_recovery_rate: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_per_epoch_churn_limit: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_per_epoch_activation_churn_limit: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_per_epoch_churn_limit_electra: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_per_epoch_activation_exit_churn_limit: Gwei,

    // Fork choice
    #[serde(with = "serde_utils::string_or_native")]
    pub proposer_score_boost: u64,

    // Deposit contract
    #[serde(with = "serde_utils::string_or_native")]
    pub deposit_chain_id: ChainId,
    pub deposit_contract_address: ExecutionAddress,
    #[serde(with = "serde_utils::string_or_native")]
    pub deposit_network_id: NetworkId,

    // Networking
    #[serde(with = "serde_utils::string_or_native")]
    pub attestation_subnet_extra_bits: u8,
    #[serde(with = "serde_utils::string_or_native")]
    pub epochs_per_subnet_subscription: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_payload_size: usize,
    pub message_domain_valid_snappy: DomainType,
    #[serde(with = "serde_utils::string_or_native")]
    pub subnets_per_node: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_blobs_per_block: usize,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_blobs_per_block_electra: usize,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_request_blocks: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_request_blocks_deneb: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_request_blob_sidecars: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_request_data_column_sidecars: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_epochs_for_blob_sidecars_requests: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_epochs_for_block_requests: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub blob_sidecar_subnet_count: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    pub min_epochs_for_data_column_sidecars_requests: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub data_column_sidecar_subnet_count: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_request_blob_sidecars_electra: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub blob_sidecar_subnet_count_electra: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_request_blob_sidecars_fulu: u64,
    #[serde(with = "serde_utils::sorted_list_desc_by_key")]
    pub blob_schedule: Vec<BlobScheduleEntry>,

    // Transition
    pub terminal_block_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::string_or_native")]
    pub terminal_block_hash_activation_epoch: Epoch,
    pub terminal_total_difficulty: Difficulty,

    // Custody
    #[serde(with = "serde_utils::string_or_native")]
    pub custody_requirement: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub number_of_custody_groups: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub samples_per_slot: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_custody_requirement: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub balance_per_additional_custody_group: Gwei,

    #[serde(skip_serializing)]
    pub blacklisted_blocks: Vec<H256>,

    // Derived
    #[serde(skip)]
    pub max_data_columns_by_root_request: OnceCell<usize>,

    // Later phases and other unknown variables
    //
    // Collect unknown variables in a map so we can log a warning about them.
    // The downside to this is that we can no longer define `Config`s as constants.
    #[expect(
        clippy::zero_sized_map_values,
        reason = "False positive. Serde can only flatten structs and maps."
    )]
    #[serde(flatten, skip_serializing)]
    pub unknown: BTreeMap<String, IgnoredAny>,
}

impl Default for Config {
    #[expect(
        deprecated,
        reason = "seconds_per_slot is still present in the consensus specs as of v1.6.0-alpha.5"
    )]
    fn default() -> Self {
        Self {
            // Meta
            //
            // Use `default` as the default `config_name` and override it in `Config::mainnet`.
            // This way custom network data will be kept separate from mainnet data if a user
            // forgets to specify a custom `CONFIG_NAME`.
            config_name: Cow::Borrowed("default"),
            preset_base: PresetName::Mainnet,

            // Genesis
            genesis_delay: 604_800,
            genesis_fork_version: H32(hex!("00000000")),
            min_genesis_active_validator_count: nonzero!(1_u64 << 14),
            min_genesis_time: 0,

            // Forking
            altair_fork_epoch: FAR_FUTURE_EPOCH,
            altair_fork_version: H32(hex!("01000000")),
            bellatrix_fork_epoch: FAR_FUTURE_EPOCH,
            bellatrix_fork_version: H32(hex!("02000000")),
            capella_fork_epoch: FAR_FUTURE_EPOCH,
            capella_fork_version: H32(hex!("03000000")),
            deneb_fork_epoch: FAR_FUTURE_EPOCH,
            deneb_fork_version: H32(hex!("04000000")),
            electra_fork_epoch: FAR_FUTURE_EPOCH,
            electra_fork_version: H32(hex!("05000000")),
            fulu_fork_epoch: FAR_FUTURE_EPOCH,
            fulu_fork_version: H32(hex!("06000000")),

            // Time parameters
            eth1_follow_distance: 2048,
            min_validator_withdrawability_delay: 256,
            seconds_per_eth1_block: 14,
            seconds_per_slot: nonzero!(12_u64),
            shard_committee_period: 256,
            slot_duration_ms: Duration::from_millis(12000),

            // Validator cycle
            churn_limit_quotient: nonzero!(1_u64 << 16),
            ejection_balance: 16_000_000_000,
            inactivity_score_bias: nonzero!(4_u64),
            inactivity_score_recovery_rate: 16,
            max_per_epoch_activation_churn_limit: 8,
            min_per_epoch_churn_limit: 4,
            min_per_epoch_churn_limit_electra: 128_000_000_000,
            max_per_epoch_activation_exit_churn_limit: 256_000_000_000,

            // Fork choice
            proposer_score_boost: 40,

            // Deposit contract
            deposit_chain_id: 0,
            deposit_contract_address: ExecutionAddress::zero(),
            deposit_network_id: 0,

            // Networking
            attestation_subnet_extra_bits: 0,
            epochs_per_subnet_subscription: nonzero!(256_u64),
            max_payload_size: 10_485_760,
            message_domain_valid_snappy: H32(hex!("01000000")),
            subnets_per_node: 2,
            max_blobs_per_block: 6,
            max_blobs_per_block_electra: 9,
            max_request_blocks: 1024,
            max_request_blocks_deneb: 128,
            max_request_blob_sidecars: 768,
            max_request_data_column_sidecars: 0x4000,
            min_epochs_for_blob_sidecars_requests: 4096,
            min_epochs_for_block_requests: 33024,
            blob_sidecar_subnet_count: nonzero!(6_u64),
            min_epochs_for_data_column_sidecars_requests: 4096,
            data_column_sidecar_subnet_count: 128,
            max_request_blob_sidecars_electra: 1152,
            blob_sidecar_subnet_count_electra: nonzero!(9_u64),
            max_request_blob_sidecars_fulu: 1536,
            blob_schedule: vec![],

            // Transition
            terminal_block_hash: ExecutionBlockHash::zero(),
            terminal_block_hash_activation_epoch: FAR_FUTURE_EPOCH,
            terminal_total_difficulty: Difficulty::from_be_bytes(hex!(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00"
            )),

            // Custody
            custody_requirement: 4,
            number_of_custody_groups: 128,
            samples_per_slot: 8,
            validator_custody_requirement: 8,
            balance_per_additional_custody_group: 32_000_000_000,

            blacklisted_blocks: vec![],

            max_data_columns_by_root_request: OnceCell::new(),

            // Later phases and other unknown variables
            unknown: BTreeMap::new(),
        }
    }
}

#[derive(Constructor, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct BlobScheduleEntry {
    #[serde(with = "serde_utils::string_or_native")]
    pub epoch: Epoch,
    #[serde(with = "serde_utils::string_or_native")]
    pub max_blobs_per_block: usize,
}

impl Sortable for BlobScheduleEntry {
    fn key(&self) -> impl Ord {
        self.epoch
    }
}

// TODO(Grandine Team): Consider adding the linked repositories as submodules and adding
//                      tests that verify built-in configurations match YAML files in them.

impl Config {
    /// [Mainnet configuration](https://github.com/eth-clients/mainnet/blob/978f1794eada6f85bee76e4d2d5959a5fb8e0cc5/metadata/config.yaml).
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("mainnet"),

            // Genesis
            min_genesis_time: 1_606_824_000,

            // Forking
            altair_fork_epoch: 74240,
            bellatrix_fork_epoch: 144_896,
            capella_fork_epoch: 194_048,
            deneb_fork_epoch: 269_568,
            electra_fork_epoch: 364_032,

            // Deposit contract
            deposit_chain_id: 1,
            deposit_contract_address: H160(hex!("00000000219ab540356cBB839Cbe05303d7705Fa")),
            deposit_network_id: 1,

            // Transition
            terminal_total_difficulty: Difficulty::from_u128(58_750_000_000_000_000_000_000),

            ..Self::default()
        }
    }

    /// [Minimal configuration](https://github.com/ethereum/consensus-specs/blob/aac851f860fa384916f62027b2dbe3318a354c5b/configs/minimal.yaml).
    #[must_use]
    pub fn minimal() -> Self {
        #[expect(
            deprecated,
            reason = "seconds_per_slot is still present in the consensus specs as of v1.6.0-alpha.5"
        )]
        Self {
            // Meta
            config_name: Cow::Borrowed("minimal"),
            preset_base: PresetName::Minimal,

            // Genesis
            genesis_delay: 300,
            genesis_fork_version: H32(hex!("00000001")),
            min_genesis_active_validator_count: nonzero!(64_u64),
            min_genesis_time: 1_578_009_600,

            // Forking
            altair_fork_version: H32(hex!("01000001")),
            bellatrix_fork_version: H32(hex!("02000001")),
            capella_fork_version: H32(hex!("03000001")),
            deneb_fork_version: H32(hex!("04000001")),
            electra_fork_version: H32(hex!("05000001")),
            fulu_fork_version: H32(hex!("06000001")),

            // Time parameters
            eth1_follow_distance: 16,
            seconds_per_slot: nonzero!(6_u64),
            shard_committee_period: 64,
            slot_duration_ms: Duration::from_millis(6000),

            // Validator cycle
            churn_limit_quotient: nonzero!(32_u64),
            max_per_epoch_activation_churn_limit: 4,
            min_per_epoch_churn_limit: 2,
            min_per_epoch_churn_limit_electra: 64_000_000_000,
            max_per_epoch_activation_exit_churn_limit: 128_000_000_000,

            // Deposit contract
            deposit_chain_id: 5,
            deposit_contract_address: H160(hex!("1234567890123456789012345678901234567890")),
            deposit_network_id: 5,

            // Networking
            min_epochs_for_block_requests: 272,

            ..Self::default()
        }
    }

    /// [Medalla configuration](https://github.com/eth-clients/eth2-networks/blob/674f7a1d01d9c18345456eab76e3871b3df2126b/shared/medalla/config.yaml).
    ///
    /// Also available at <https://github.com/goerli/medalla/blob/124fe40d26e8a10fa44dbe48dcba828ea1237054/medalla/chain.yaml>.
    #[must_use]
    pub fn medalla() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("medalla"),
            preset_base: PresetName::Medalla,

            // Genesis
            genesis_delay: 172_800,
            genesis_fork_version: H32(hex!("00000001")),
            min_genesis_time: 1_596_546_008,

            // Time parameters
            eth1_follow_distance: 1024,

            // Deposit contract
            deposit_chain_id: 5,
            deposit_contract_address: H160(hex!("07b39F4fDE4A38bACe212b546dAc87C58DfE3fDC")),
            deposit_network_id: 5,

            ..Self::default()
        }
    }

    /// [Goerli configuration](https://github.com/eth-clients/goerli/blob/6522ac6684693740cd4ddcc2a0662e03702aa4a1/prater/config.yaml)
    ///
    /// Formerly known as Prater.
    #[must_use]
    pub fn goerli() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("goerli"),

            // Genesis
            genesis_delay: 1_919_188,
            genesis_fork_version: H32(hex!("00001020")),
            min_genesis_time: 1_614_588_812,

            // Forking
            altair_fork_epoch: 36660,
            altair_fork_version: H32(hex!("01001020")),
            bellatrix_fork_epoch: 112_260,
            bellatrix_fork_version: H32(hex!("02001020")),
            capella_fork_epoch: 162_304,
            capella_fork_version: H32(hex!("03001020")),
            deneb_fork_epoch: 231_680,
            deneb_fork_version: H32(hex!("04001020")),

            // Deposit contract
            deposit_chain_id: 5,
            deposit_contract_address: H160(hex!("ff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b")),
            deposit_network_id: 5,

            // Transition
            terminal_total_difficulty: Difficulty::from_u64(10_790_000),

            // Networking
            max_request_blocks: 1024,

            ..Self::default()
        }
    }

    /// [Sepolia configuration](https://github.com/eth-clients/sepolia/blob/56f0bff41cecab6c661251d72b73ceecc52c5701/metadata/config.yaml)
    #[must_use]
    pub fn sepolia() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("sepolia"),

            // Genesis
            genesis_delay: 86_400,
            genesis_fork_version: H32(hex!("90000069")),
            min_genesis_active_validator_count: nonzero!(1300_u64),
            min_genesis_time: 1_655_647_200,

            // Forking
            altair_fork_epoch: 50,
            altair_fork_version: H32(hex!("90000070")),
            bellatrix_fork_epoch: 100,
            bellatrix_fork_version: H32(hex!("90000071")),
            capella_fork_epoch: 56832,
            capella_fork_version: H32(hex!("90000072")),
            deneb_fork_epoch: 132_608,
            deneb_fork_version: H32(hex!("90000073")),
            electra_fork_epoch: 222_464,
            electra_fork_version: H32(hex!("90000074")),
            fulu_fork_epoch: 272_640,
            fulu_fork_version: H32(hex!("90000075")),

            // Deposit contract
            deposit_chain_id: 11_155_111,
            deposit_contract_address: H160(hex!("7f02C3E3c98b133055B8B348B2Ac625669Ed295D")),
            deposit_network_id: 11_155_111,

            // Transition
            terminal_total_difficulty: Difficulty::from_u128(17_000_000_000_000_000),

            // Networking
            blob_schedule: vec![
                BlobScheduleEntry {
                    epoch: 274_176,
                    max_blobs_per_block: 15,
                },
                BlobScheduleEntry {
                    epoch: 275_712,
                    max_blobs_per_block: 21,
                },
            ],

            ..Self::default()
        }
    }

    /// [Withdrawal devnet 3 configuration](https://github.com/ethpandaops/withdrawals-testnet/blob/a87272d32cc69766629f4a10b1d5183637747914/withdrawal-devnet-3/custom_config_data/config.yaml).
    #[must_use]
    pub fn withdrawal_devnet_3() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("testnet"),

            // Genesis
            genesis_delay: 120,
            genesis_fork_version: H32(hex!("10000040")),
            min_genesis_active_validator_count: nonzero!(47000_u64),
            min_genesis_time: 1_673_953_200,

            // Forking
            altair_fork_epoch: 0,
            altair_fork_version: H32(hex!("20000040")),
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: H32(hex!("30000040")),
            capella_fork_epoch: 20,
            capella_fork_version: H32(hex!("40000040")),

            // Time parameters
            eth1_follow_distance: 12,

            // Deposit contract
            deposit_chain_id: 1_337_807,
            deposit_contract_address: ExecutionAddress::repeat_byte(0x42),
            deposit_network_id: 1_337_807,

            // Transition
            terminal_total_difficulty: Difficulty::ZERO,

            ..Self::default()
        }
    }

    /// [Withdrawal devnet 4 configuration](https://github.com/ethpandaops/withdrawals-testnet/blob/a87272d32cc69766629f4a10b1d5183637747914/withdrawal-devnet-4/custom_config_data/config.yaml).
    #[must_use]
    pub fn withdrawal_devnet_4() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("testnet"),

            // Genesis
            genesis_delay: 120,
            genesis_fork_version: H32(hex!("10000041")),
            min_genesis_active_validator_count: nonzero!(565_000_u64),
            min_genesis_time: 1_674_635_400,

            // Forking
            altair_fork_epoch: 0,
            altair_fork_version: H32(hex!("20000041")),
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: H32(hex!("30000041")),
            capella_fork_epoch: 20,
            capella_fork_version: H32(hex!("40000041")),

            // Time parameters
            eth1_follow_distance: 12,

            // Deposit contract
            deposit_chain_id: 1_337_808,
            deposit_contract_address: ExecutionAddress::repeat_byte(0x42),
            deposit_network_id: 1_337_808,

            // Transition
            terminal_total_difficulty: Difficulty::ZERO,

            ..Self::default()
        }
    }

    /// [Holesky configuration](https://github.com/eth-clients/holesky/blob/8aec65f11f0c986d6b76b2eb902420635eb9b815/metadata/config.yaml)
    #[must_use]
    pub fn holesky() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("holesky"),

            // Genesis
            genesis_delay: 300,
            genesis_fork_version: H32(hex!("01017000")),
            min_genesis_time: 1_695_902_100,

            // Forking
            altair_fork_epoch: 0,
            altair_fork_version: H32(hex!("02017000")),
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: H32(hex!("03017000")),
            capella_fork_epoch: 256,
            capella_fork_version: H32(hex!("04017000")),
            deneb_fork_epoch: 29_696,
            deneb_fork_version: H32(hex!("05017000")),
            electra_fork_epoch: 115_968,
            electra_fork_version: H32(hex!("06017000")),
            fulu_fork_epoch: 165_120,
            fulu_fork_version: H32(hex!("07017000")),

            // Validator cycle
            ejection_balance: 28_000_000_000,

            // Deposit contract
            deposit_chain_id: 17_000,
            deposit_contract_address: ExecutionAddress::repeat_byte(0x42),
            deposit_network_id: 17_000,

            // Transition
            terminal_total_difficulty: Difficulty::ZERO,

            // Networking
            blob_schedule: vec![
                BlobScheduleEntry {
                    epoch: 166_400,
                    max_blobs_per_block: 15,
                },
                BlobScheduleEntry {
                    epoch: 167_936,
                    max_blobs_per_block: 21,
                },
            ],

            blacklisted_blocks: vec![H256(hex!(
                "2db899881ed8546476d0b92c6aa9110bea9a4cd0dbeb5519eb0ea69575f1f359"
            ))],

            ..Self::default()
        }
    }

    /// [Holesky devnet configuration](https://github.com/ethpandaops/holesky-test/blob/00bb216f79f986276e4eb1cbeb1da0fa5fb21309/network-configs/devnet-2m-test/config.yaml).
    #[must_use]
    pub fn holesky_devnet() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("holesky-devnet"),

            // Genesis
            genesis_delay: 300,
            genesis_fork_version: H32(hex!("10759732")),
            min_genesis_time: 1_690_992_000,
            min_genesis_active_validator_count: nonzero!(2_100_000_u64),

            // Forking
            altair_fork_epoch: 0,
            altair_fork_version: H32(hex!("20759732")),
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: H32(hex!("30759732")),
            capella_fork_epoch: 5,
            capella_fork_version: H32(hex!("40759732")),

            // Deposit contract
            deposit_chain_id: 7_094_445_817,
            deposit_contract_address: H160(hex!("6f22fFbC56eFF051aECF839396DD1eD9aD6BBA9D")),
            deposit_network_id: 7_094_445_817,

            // Transition
            terminal_total_difficulty: Difficulty::ZERO,

            // Eth1
            seconds_per_eth1_block: 12,

            // Time
            min_validator_withdrawability_delay: 1,
            shard_committee_period: 1,
            eth1_follow_distance: 12,

            // Validator cycle
            ejection_balance: 31_000_000_000,

            ..Self::default()
        }
    }

    /// [Hoodi configuration](https://github.com/eth-clients/hoodi/blob/21a110a60e6558a2ba7c819fa4b80029d49ab205/metadata/config.yaml)
    #[must_use]
    pub fn hoodi() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("hoodi"),

            // Genesis
            genesis_delay: 600,
            genesis_fork_version: H32(hex!("10000910")),
            min_genesis_time: 1_742_212_800,

            // Forking
            altair_fork_epoch: 0,
            altair_fork_version: H32(hex!("20000910")),
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: H32(hex!("30000910")),
            capella_fork_epoch: 0,
            capella_fork_version: H32(hex!("40000910")),
            deneb_fork_epoch: 0,
            deneb_fork_version: H32(hex!("50000910")),
            electra_fork_epoch: 2048,
            electra_fork_version: H32(hex!("60000910")),
            fulu_fork_epoch: 50_688,
            fulu_fork_version: H32(hex!("70000910")),

            // Time parameters
            seconds_per_eth1_block: 12,

            // Deposit contract
            deposit_chain_id: 560_048,
            deposit_contract_address: ExecutionAddress::from_slice(
                &hex::decode("00000000219ab540356cBB839Cbe05303d7705Fa")
                    .expect("Hoodi deposit contract address contains invalid bytes"),
            ),
            deposit_network_id: 560_048,

            // Networking
            data_column_sidecar_subnet_count: 128,
            blob_schedule: vec![
                BlobScheduleEntry {
                    epoch: 52_480,
                    max_blobs_per_block: 15,
                },
                BlobScheduleEntry {
                    epoch: 54_016,
                    max_blobs_per_block: 21,
                },
            ],

            // Transition
            terminal_total_difficulty: Difficulty::ZERO,
            // Custody
            samples_per_slot: 8,

            ..Self::default()
        }
    }

    // [Pectra devnet 6 configuration](https://github.com/ethpandaops/pectra-devnets/blob/8bb780acb223896287ffb034db571455c876e56d/network-configs/devnet-6/metadata/config.yaml)
    #[must_use]
    pub fn pectra_devnet_6() -> Self {
        Self {
            // Meta
            config_name: Cow::Borrowed("testnet"),

            // Genesis
            genesis_delay: 60,
            genesis_fork_version: H32(hex!("10585557")),
            min_genesis_active_validator_count: nonzero!(71_000_u64),
            min_genesis_time: 1_738_603_800,

            // Forking
            altair_fork_epoch: 0,
            altair_fork_version: H32(hex!("20585557")),
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: H32(hex!("30585557")),
            capella_fork_epoch: 0,
            capella_fork_version: H32(hex!("40585557")),
            deneb_fork_epoch: 0,
            deneb_fork_version: H32(hex!("50585557")),
            electra_fork_epoch: 10,
            electra_fork_version: H32(hex!("60585557")),

            // Time parameters
            min_validator_withdrawability_delay: 2,
            seconds_per_eth1_block: 12,
            shard_committee_period: 256,

            // Validator cycle
            churn_limit_quotient: nonzero!(128_u64),

            // Deposit contract
            deposit_chain_id: 7_072_151_312,
            deposit_contract_address: H160(hex!("4242424242424242424242424242424242424242")),
            deposit_network_id: 7_072_151_312,

            // Networking
            max_request_blocks: 1024,

            // Transition
            terminal_block_hash: ExecutionBlockHash::zero(),
            terminal_block_hash_activation_epoch: FAR_FUTURE_EPOCH,
            terminal_total_difficulty: Difficulty::from_be_bytes(hex!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),

            // Custody
            samples_per_slot: 8,

            ..Self::default()
        }
    }

    /// Modifies `self` to start in `phase` but never upgrade.
    ///
    /// This is needed to run `consensus-spec-tests`.
    /// They contain data that is arguably invalid: containers in slots that don't match the phase.
    /// This sort of thing is possible with the right configuration, but the tests use the default
    /// values of `*_FORK_EPOCH` in both mainnet and minimal configurations, so they're still wrong.
    #[must_use]
    pub fn start_and_stay_in(mut self, phase: Phase) -> Self {
        self.config_name = Cow::Owned(format!("{phase}-{}", self.config_name));
        self.upgrade_once(phase, GENESIS_EPOCH)
    }

    #[must_use]
    pub fn upgrade_once(mut self, post_phase: Phase, fork_epoch: Epoch) -> Self {
        for (phase, field) in self.fork_epochs_mut() {
            *field = match phase.cmp(&post_phase) {
                Ordering::Less => GENESIS_EPOCH,
                Ordering::Equal => fork_epoch,
                Ordering::Greater => FAR_FUTURE_EPOCH,
            };
        }

        self
    }

    #[must_use]
    pub fn rapid_upgrade(mut self) -> Self {
        self.config_name.to_mut().insert_str(0, "rapid-upgrade-");

        for ((_, field), epoch) in self.fork_epochs_mut().zip(1..) {
            *field = epoch;
        }

        self
    }

    // TODO(Grandine Team): Validate more. See the following for properties that must hold:
    //                      - <https://github.com/ethereum/consensus-specs/issues/407>
    //                      - <https://github.com/ethereum/consensus-specs/pull/2444>
    pub fn validate(&self) -> Result<(), Error> {
        if self.config_name.is_empty() {
            return Err(Error::NameEmpty);
        }

        // See <https://github.com/ethereum/consensus-specs/blob/aac851f860fa384916f62027b2dbe3318a354c5b/configs/mainnet.yaml#L10>.
        for character in self.config_name.chars() {
            if !matches!(character, 'a'..='z' | '0'..='9' | '-') {
                return Err(Error::NameContainsIllegalCharacters);
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn genesis_phase(&self) -> Phase {
        self.phase_at_epoch(GENESIS_EPOCH)
    }

    #[inline]
    #[must_use]
    pub const fn version(&self, phase: Phase) -> Version {
        match phase {
            Phase::Phase0 => self.genesis_fork_version,
            Phase::Altair => self.altair_fork_version,
            Phase::Bellatrix => self.bellatrix_fork_version,
            Phase::Capella => self.capella_fork_version,
            Phase::Deneb => self.deneb_fork_version,
            Phase::Electra => self.electra_fork_version,
            Phase::Fulu => self.fulu_fork_version,
        }
    }

    #[must_use]
    pub fn version_at_epoch(&self, epoch: Epoch) -> Version {
        let phase = self.phase_at_epoch(epoch);
        self.version(phase)
    }

    #[inline]
    #[must_use]
    pub const fn fork_epoch(&self, phase: Phase) -> Epoch {
        match phase {
            Phase::Phase0 => GENESIS_EPOCH,
            Phase::Altair => self.altair_fork_epoch,
            Phase::Bellatrix => self.bellatrix_fork_epoch,
            Phase::Capella => self.capella_fork_epoch,
            Phase::Deneb => self.deneb_fork_epoch,
            Phase::Electra => self.electra_fork_epoch,
            Phase::Fulu => self.fulu_fork_epoch,
        }
    }

    #[must_use]
    pub fn fork_slot<P: Preset>(&self, phase: Phase) -> Toption<Slot> {
        self.fork_epoch(phase)
            .checked_mul(P::SlotsPerEpoch::U64)
            .map_or(Toption::None, Toption::Some)
    }

    #[must_use]
    pub fn is_phase_enabled<P: Preset>(&self, phase: Phase) -> bool {
        self.fork_slot::<P>(phase).into_option().is_some()
    }

    #[must_use]
    pub fn phase_at_epoch(&self, epoch: Epoch) -> Phase {
        self.fork_epochs()
            .take_while(|(_, fork_epoch)| *fork_epoch <= epoch)
            .map(|(phase, _)| phase)
            .last()
            .unwrap_or(Phase::Phase0)
    }

    #[must_use]
    pub fn phase_at_slot<P: Preset>(&self, slot: Slot) -> Phase {
        self.fork_slots::<P>()
            .take_while(|(_, fork_slot)| *fork_slot <= Toption::Some(slot))
            .map(|(phase, _)| phase)
            .last()
            .unwrap_or(Phase::Phase0)
    }

    #[must_use]
    pub fn next_phase_at_slot<P: Preset>(&self, slot: Slot) -> Option<Phase> {
        self.fork_slots::<P>()
            .find(|(_, fork_slot)| Some(slot) < fork_slot.into_option())
            .map(|(phase, _)| phase)
    }

    #[must_use]
    pub const fn is_peerdas_scheduled(&self) -> bool {
        self.fulu_fork_epoch != FAR_FUTURE_EPOCH
    }

    #[must_use]
    pub const fn max_request_blocks(&self, phase: Phase) -> u64 {
        match phase {
            Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella => {
                self.max_request_blocks
            }
            Phase::Deneb | Phase::Electra | Phase::Fulu => self.max_request_blocks_deneb,
        }
    }

    #[must_use]
    pub const fn blob_sidecar_subnet_count(&self, phase: Phase) -> NonZeroU64 {
        match phase {
            Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella | Phase::Deneb => {
                self.blob_sidecar_subnet_count
            }
            Phase::Electra | Phase::Fulu => self.blob_sidecar_subnet_count_electra,
        }
    }

    #[must_use]
    pub const fn max_request_blob_sidecars(&self, phase: Phase) -> u64 {
        match phase {
            Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella | Phase::Deneb => {
                self.max_request_blob_sidecars
            }
            Phase::Electra | Phase::Fulu => self.max_request_blob_sidecars_electra,
        }
    }

    #[must_use]
    pub fn max_message_size(&self) -> usize {
        core::cmp::max(
            self.max_payload_size_compressed()
                .checked_add(1024)
                .expect("max_message_size should not overflow"),
            1024 * 1024,
        )
    }

    #[must_use]
    pub fn max_payload_size_compressed(&self) -> usize {
        Self::max_compressed_len(self.max_payload_size)
            .expect("max_compressed_len for max_payload_size should not overflow")
    }

    #[must_use]
    pub fn max_compressed_len(n: usize) -> Option<usize> {
        32_usize.checked_add(n)?.checked_add(n / 6)
    }

    #[must_use]
    pub fn max_blob_sideacar_subnet_count(&self) -> u64 {
        self.blob_sidecar_subnet_count
            .get()
            .max(self.blob_sidecar_subnet_count_electra.get())
    }

    #[must_use]
    pub const fn custody_group_count(&self, subscribe_all_data_column_subnets: bool) -> u64 {
        if subscribe_all_data_column_subnets {
            self.number_of_custody_groups
        } else {
            self.custody_requirement
        }
    }

    /// Return the number of custody group to sample per slot.
    #[must_use]
    pub fn sampling_size_custody_groups(&self, custody_group_count: u64) -> u64 {
        core::cmp::max(custody_group_count, self.samples_per_slot)
    }

    /// Return the number of data column sidecar to download per slot.
    #[must_use]
    pub fn sampling_column_count<P: Preset>(&self, custody_group_count: u64) -> u64 {
        let sampling_size = self.sampling_size_custody_groups(custody_group_count);

        sampling_size.saturating_mul(self.columns_per_group::<P>())
    }

    #[must_use]
    pub const fn custody_size<P: Preset>(&self, sampling_column_count: u64) -> u64 {
        sampling_column_count.saturating_div(self.columns_per_group::<P>())
    }

    #[must_use]
    pub const fn columns_per_group<P: Preset>(&self) -> u64 {
        P::NumberOfColumns::U64.saturating_div(self.number_of_custody_groups)
    }

    #[must_use]
    pub fn get_blob_schedule_entry(&self, epoch: Epoch) -> BlobScheduleEntry {
        // There is no need to sort everytime the function called, `blob_schedule` has been sorted by
        // `epoch` in descending order.
        self.blob_schedule
            .iter()
            .find_map(|entry| (epoch >= entry.epoch).then_some(entry.clone()))
            .unwrap_or_else(|| {
                BlobScheduleEntry::new(self.electra_fork_epoch, self.max_blobs_per_block_electra)
            })
    }

    #[must_use]
    pub fn max_blobs_per_block(&self, epoch: Epoch) -> u64 {
        let phase = self.phase_at_epoch(epoch);
        let max_blobs = match phase {
            Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella | Phase::Deneb => {
                self.max_blobs_per_block
            }
            Phase::Electra => self.max_blobs_per_block_electra,
            Phase::Fulu => self.get_blob_schedule_entry(epoch).max_blobs_per_block,
        };

        max_blobs
            .try_into()
            .expect("number of max blobs in block should fit in u64")
    }

    #[must_use]
    pub fn max_data_columns_by_root_request<P: Preset>(&self) -> usize {
        *self.max_data_columns_by_root_request.get_or_init(|| {
            DynamicList::<DataColumnsByRootIdentifier<P>>::full(
                DataColumnsByRootIdentifier {
                    block_root: H256::zero(),
                    columns: ContiguousList::full(0),
                },
                usize::try_from(self.max_request_blocks_deneb).expect("u64 to usize"),
            )
            .to_ssz()
            .expect("Unable to get DataColumnSidecarsByRoot full length")
            .len()
        })
    }

    fn fork_slots<P: Preset>(&self) -> impl Iterator<Item = (Phase, Toption<Slot>)> + '_ {
        enum_iterator::all().map(|phase| (phase, self.fork_slot::<P>(phase)))
    }

    fn fork_epochs(&self) -> impl Iterator<Item = (Phase, Epoch)> {
        // Do not remove the type annotation.
        // It ensures that this method is up to date when new phases are added.
        let fields: [_; Phase::CARDINALITY - 1] = [
            self.altair_fork_epoch,
            self.bellatrix_fork_epoch,
            self.capella_fork_epoch,
            self.deneb_fork_epoch,
            self.electra_fork_epoch,
            self.fulu_fork_epoch,
        ];

        enum_iterator::all().skip(1).zip(fields)
    }

    fn fork_epochs_mut(&mut self) -> impl Iterator<Item = (Phase, &mut Epoch)> {
        // Do not remove the type annotation.
        // It ensures that this method is up to date when new phases are added.
        let fields: [_; Phase::CARDINALITY - 1] = [
            &mut self.altair_fork_epoch,
            &mut self.bellatrix_fork_epoch,
            &mut self.capella_fork_epoch,
            &mut self.deneb_fork_epoch,
            &mut self.electra_fork_epoch,
            &mut self.fulu_fork_epoch,
        ];

        enum_iterator::all().skip(1).zip(fields)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration name is empty")]
    NameEmpty,
    #[error("configuration name contains illegal characters")]
    NameContainsIllegalCharacters,
    #[error("blob schedule is not defined")]
    BlobScheduleUndefined,
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Refactoring worsens readability, which is more important in tests."
)]
#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test_case(Config::mainnet())]
    #[test_case(Config::minimal())]
    #[test_case(Config::medalla())]
    #[test_case(Config::goerli())]
    #[test_case(Config::sepolia())]
    #[test_case(Config::withdrawal_devnet_3())]
    #[test_case(Config::withdrawal_devnet_4())]
    #[test_case(Config::holesky())]
    #[test_case(Config::holesky_devnet())]
    fn config_is_valid(config: Config) -> Result<(), Error> {
        config.validate()
    }
}
