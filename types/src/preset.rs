#![allow(clippy::module_name_repetitions)]

use core::{fmt::Debug, hash::Hash, num::NonZeroU64, ops::Sub};

use arithmetic::NonZeroExt as _;
use bls::CachedPublicKey;
use generic_array::ArrayLength;
use nonzero_ext::nonzero;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use ssz::{
    BitVectorBits, ByteVectorBytes, ContiguousVectorElements, FitsInU64, MerkleBits,
    MerkleElements, PersistentVectorElements, UnhashedBundleSize,
};
use strum::{Display, EnumString};
use typenum::{
    IsGreaterOrEqual, NonZero, Prod, Quot, Sub1, True, Unsigned, B1, U1048576, U1073741824,
    U1099511627776, U128, U16, U16777216, U17, U2, U2048, U256, U32, U4, U4096, U512, U6, U64,
    U65536, U8, U8192, U9,
};

use crate::{
    altair::consts::SyncCommitteeSubnetCount,
    bellatrix::primitives::Transaction,
    capella::containers::{SignedBlsToExecutionChange, Withdrawal},
    config::Config,
    deneb::{
        consts::BytesPerFieldElement,
        primitives::{Blob, KzgCommitment, KzgProof},
    },
    phase0::{
        containers::{
            Attestation, AttesterSlashing, Deposit, ProposerSlashing, SignedVoluntaryExit,
        },
        primitives::{Gwei, ValidatorIndex, H256},
    },
};

#[cfg(test)]
use ::{enum_iterator::Sequence, strum::VariantNames};

/// Compile-time configuration variables.
///
/// See [presets in `consensus-specs`](https://github.com/ethereum/consensus-specs/tree/aac851f860fa384916f62027b2dbe3318a354c5b/presets).
pub trait Preset: Copy + Eq + Ord + Hash + Default + Debug + Send + Sync + 'static {
    // Phase 0
    type EpochsPerEth1VotingPeriod: Unsigned + NonZero;
    type EpochsPerHistoricalRoot: Unsigned + NonZero;
    type EpochsPerHistoricalVector: PersistentVectorElements<H256, UnhashedBundleSize<H256>>
        + Debug
        + Send
        + Sync;
    type EpochsPerSlashingsVector: PersistentVectorElements<Gwei, UnhashedBundleSize<Gwei>>
        + Debug
        + Send
        + Sync;
    type HistoricalRootsLimit: Unsigned + Debug + Send + Sync;
    type MaxAttestations: MerkleElements<Attestation<Self>> + Eq + Debug + Send + Sync;
    type MaxAttesterSlashings: MerkleElements<AttesterSlashing<Self>> + Eq + Debug + Send + Sync;
    type MaxDeposits: MerkleElements<Deposit> + Eq + Debug + Send + Sync;
    type MaxProposerSlashings: MerkleElements<ProposerSlashing> + Eq + Debug + Send + Sync;
    type MaxValidatorsPerCommittee: MerkleElements<ValidatorIndex>
        + MerkleBits
        + NonZero
        + Eq
        + Ord
        + Debug
        + Send
        + Sync;
    type MaxVoluntaryExits: MerkleElements<SignedVoluntaryExit> + Eq + Debug + Send + Sync;
    type SlotsPerEpoch: Unsigned + NonZero + Sub<B1>;
    type ValidatorRegistryLimit: FitsInU64 + NonZero + Debug + Send + Sync;

    // Altair
    type SyncCommitteeSize: ContiguousVectorElements<ValidatorIndex>
        + ContiguousVectorElements<CachedPublicKey>
        + MerkleElements<CachedPublicKey>
        + BitVectorBits
        + MerkleBits
        + Eq
        + Debug
        + Send
        + Sync;

    // Bellatrix
    type BytesPerLogsBloom: ByteVectorBytes + MerkleElements<u8> + Eq + Debug;
    type MaxBytesPerTransaction: MerkleElements<u8> + Send + Sync;
    type MaxExtraDataBytes: MerkleElements<u8> + Eq + Debug + Send + Sync;
    type MaxTransactionsPerPayload: MerkleElements<Transaction<Self>> + Eq + Debug + Send + Sync;

    // Capella
    type MaxBlsToExecutionChanges: MerkleElements<SignedBlsToExecutionChange>
        + Eq
        + Debug
        + Send
        + Sync;
    type MaxWithdrawalsPerPayload: MerkleElements<Withdrawal> + NonZero + Eq + Debug + Send + Sync;

    // TODO(feature/deneb): `KZG_COMMITMENT_INCLUSION_PROOF_DEPTH` is derived from
    //                      `MAX_BLOB_COMMITMENTS_PER_BLOCK` but still included in
    //                      the preset even in `consensus-specs`.
    //                      Consider adding bounds to verify they are consistent.
    // Deneb
    type FieldElementsPerBlob: Unsigned + NonZero;
    type KzgCommitmentInclusionProofDepth: ContiguousVectorElements<H256>
        + MerkleElements<H256>
        + ArrayLength<H256, ArrayType: Copy>
        + Debug
        + Eq;
    type MaxBlobCommitmentsPerBlock: MerkleElements<KzgCommitment> + Eq + Debug + Send + Sync;
    type MaxBlobsPerBlock: MerkleElements<Blob<Self>>
        + MerkleElements<KzgCommitment>
        + MerkleElements<KzgProof>
        + Eq
        + Debug
        + Send
        + Sync;

    // Derived type-level variables
    type BytesPerBlob: ByteVectorBytes + MerkleElements<u8>;
    // This is a [manual desugaring] of associated type bounds as described in RFC 2289.
    // This is needed because feature `associated_type_bounds` is not stable.
    // The [alternative desugaring] would be preferable if feature `implied_bounds` were stable.
    //
    // [manual desugaring]:      https://github.com/rust-lang/rfcs/blob/a0df6023eff2353b19367c29c9006898cd2c3fed/text/2289-associated-type-bounds.md#the-desugaring-for-associated-types
    // [alternative desugaring]: https://github.com/rust-lang/rfcs/blob/a0df6023eff2353b19367c29c9006898cd2c3fed/text/2289-associated-type-bounds.md#an-alternative-desugaring-of-bounds-on-associated-types
    type MaxAttestationsPerEpoch: Unsigned + Debug + Send + Sync;
    type SlotsPerEth1VotingPeriod: Unsigned + NonZero + Debug + Send + Sync;
    // The `Eq` bound is needed to work around a `clippy::derive_partial_eq_without_eq` false
    // positive for `HistoricalBatch`.
    type SlotsPerHistoricalRoot: PersistentVectorElements<H256, UnhashedBundleSize<H256>>
        + IsGreaterOrEqual<Sub1<Self::SlotsPerEpoch>, Output = True>
        + Eq
        + Debug
        + Send
        + Sync;
    // This variable has been renamed a number of times and no longer even exists in
    // `consensus-specs`, but it's still needed in our implementation.
    type SyncSubcommitteeSize: BitVectorBits
        + MerkleBits
        + Unsigned
        + NonZero
        + Eq
        + Hash
        + Debug
        + Send
        + Sync;

    // Meta
    const NAME: PresetName;

    // Phase 0
    const BASE_REWARD_FACTOR: u64 = 64;
    const EFFECTIVE_BALANCE_INCREMENT: NonZeroU64 = nonzero!(1_000_000_000_u64);
    const HYSTERESIS_DOWNWARD_MULTIPLIER: u64 = 1;
    const HYSTERESIS_QUOTIENT: NonZeroU64 = nonzero!(4_u64);
    const HYSTERESIS_UPWARD_MULTIPLIER: u64 = 5;
    const INACTIVITY_PENALTY_QUOTIENT: NonZeroU64 = nonzero!(1_u64 << 26);
    const MAX_COMMITTEES_PER_SLOT: NonZeroU64 = nonzero!(64_u64);
    const MAX_EFFECTIVE_BALANCE: Gwei = 32_000_000_000;
    const MAX_SEED_LOOKAHEAD: u64 = 4;
    const MIN_ATTESTATION_INCLUSION_DELAY: NonZeroU64 = NonZeroU64::MIN;
    const MIN_DEPOSIT_AMOUNT: Gwei = 1_000_000_000;
    const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64 = 4;
    const MIN_SEED_LOOKAHEAD: u64 = 1;
    const MIN_SLASHING_PENALTY_QUOTIENT: NonZeroU64 = nonzero!(128_u64);
    const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 1;
    const PROPOSER_REWARD_QUOTIENT: NonZeroU64 = nonzero!(8_u64);
    const SHUFFLE_ROUND_COUNT: u8 = 90;
    const TARGET_COMMITTEE_SIZE: NonZeroU64 = nonzero!(128_u64);
    const WHISTLEBLOWER_REWARD_QUOTIENT: NonZeroU64 = nonzero!(512_u64);

    // Altair
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: NonZeroU64 = nonzero!(256_u64);
    const INACTIVITY_PENALTY_QUOTIENT_ALTAIR: NonZeroU64 = nonzero!(3_u64 << 24);
    const MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR: NonZeroU64 = nonzero!(64_u64);
    const MIN_SYNC_COMMITTEE_PARTICIPANTS: usize = 1;
    const PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR: u64 = 2;
    // Preset files in `consensus-specs` contain `UPDATE_TIMEOUT` as well,
    // but it's derived from other variables in the preset.

    // Bellatrix
    const INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: NonZeroU64 = nonzero!(1_u64 << 24);
    const MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: NonZeroU64 = nonzero!(32_u64);
    const PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64 = 3;

    // Capella
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 1 << 14;

    /// Returns the default configuration associated with a preset.
    ///
    /// This should only be used in tests and benchmarks.
    ///
    /// This must be a function instead of a constant because of [`Config.unknown`].
    ///
    /// [`Config.unknown`]: Config#structfield.unknown
    #[must_use]
    fn default_config() -> Config {
        Self::NAME.default_config()
    }
}

/// [Mainnet preset](https://github.com/ethereum/consensus-specs/tree/aac851f860fa384916f62027b2dbe3318a354c5b/presets/mainnet).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Mainnet;

impl Preset for Mainnet {
    // Phase 0
    type EpochsPerEth1VotingPeriod = U64;
    type EpochsPerHistoricalRoot = U256;
    type EpochsPerHistoricalVector = U65536;
    type EpochsPerSlashingsVector = U8192;
    type HistoricalRootsLimit = U16777216;
    type MaxAttestations = U128;
    type MaxAttesterSlashings = U2;
    type MaxDeposits = U16;
    type MaxProposerSlashings = U16;
    type MaxValidatorsPerCommittee = U2048;
    type MaxVoluntaryExits = U16;
    type SlotsPerEpoch = U32;
    type ValidatorRegistryLimit = U1099511627776;

    // Altair
    type SyncCommitteeSize = U512;

    // Bellatrix
    type BytesPerLogsBloom = U256;
    type MaxBytesPerTransaction = U1073741824;
    type MaxExtraDataBytes = U32;
    type MaxTransactionsPerPayload = U1048576;

    // Capella
    type MaxBlsToExecutionChanges = U16;
    type MaxWithdrawalsPerPayload = U16;

    // Deneb
    type FieldElementsPerBlob = U4096;
    type MaxBlobCommitmentsPerBlock = U4096;
    type MaxBlobsPerBlock = U6;
    type KzgCommitmentInclusionProofDepth = U17;

    // Derived type-level variables
    type BytesPerBlob = Prod<BytesPerFieldElement, Self::FieldElementsPerBlob>;
    type MaxAttestationsPerEpoch = Prod<Self::MaxAttestations, Self::SlotsPerEpoch>;
    type SlotsPerEth1VotingPeriod = Prod<Self::EpochsPerEth1VotingPeriod, Self::SlotsPerEpoch>;
    type SlotsPerHistoricalRoot = Prod<Self::EpochsPerHistoricalRoot, Self::SlotsPerEpoch>;
    type SyncSubcommitteeSize = Quot<Self::SyncCommitteeSize, SyncCommitteeSubnetCount>;

    // Meta
    const NAME: PresetName = PresetName::Mainnet;
}

macro_rules! delegate_preset_items {
    (
        super $base_preset: ident;
        $(type $associated_type: ident;)*
        $(const $associated_constant: ident : $constant_type: ty;)*
        $(fn $associated_function: ident : $function_return_type: ty;)*
    ) => {
        $(type $associated_type = <$base_preset as Preset>::$associated_type;)*
        $(
            const $associated_constant: $constant_type =
                <$base_preset as Preset>::$associated_constant;
        )*
        $(
            fn $associated_function() -> $function_return_type {
                <$base_preset as Preset>::$associated_function()
            }
        )*
    };
}

/// [Minimal preset](https://github.com/ethereum/consensus-specs/tree/aac851f860fa384916f62027b2dbe3318a354c5b/presets/minimal).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Minimal;

impl Preset for Minimal {
    delegate_preset_items! {
        super Mainnet;

        // Phase 0
        type HistoricalRootsLimit;
        type MaxAttestations;
        type MaxAttesterSlashings;
        type MaxDeposits;
        type MaxProposerSlashings;
        type MaxValidatorsPerCommittee;
        type MaxVoluntaryExits;
        type ValidatorRegistryLimit;

        // Bellatrix
        type BytesPerLogsBloom;
        type MaxBytesPerTransaction;
        type MaxExtraDataBytes;
        type MaxTransactionsPerPayload;

        // Capella
        type MaxBlsToExecutionChanges;

        // Deneb
        type FieldElementsPerBlob;
        type MaxBlobsPerBlock;
    }

    // Phase 0
    type EpochsPerEth1VotingPeriod = U4;
    type EpochsPerHistoricalRoot = U8;
    type EpochsPerHistoricalVector = U64;
    type EpochsPerSlashingsVector = U64;
    type SlotsPerEpoch = U8;

    // Altair
    type SyncCommitteeSize = U32;

    // Capella
    type MaxWithdrawalsPerPayload = U4;

    // Deneb
    type MaxBlobCommitmentsPerBlock = U16;
    type KzgCommitmentInclusionProofDepth = U9;

    // Derived type-level variables
    type BytesPerBlob = Prod<BytesPerFieldElement, Self::FieldElementsPerBlob>;
    type MaxAttestationsPerEpoch = Prod<Self::MaxAttestations, Self::SlotsPerEpoch>;
    type SlotsPerEth1VotingPeriod = Prod<Self::EpochsPerEth1VotingPeriod, Self::SlotsPerEpoch>;
    type SlotsPerHistoricalRoot = Prod<Self::EpochsPerHistoricalRoot, Self::SlotsPerEpoch>;
    type SyncSubcommitteeSize = Quot<Self::SyncCommitteeSize, SyncCommitteeSubnetCount>;

    // Meta
    const NAME: PresetName = PresetName::Minimal;

    // Phase 0
    const INACTIVITY_PENALTY_QUOTIENT: NonZeroU64 = nonzero!(1_u64 << 25);
    const MAX_COMMITTEES_PER_SLOT: NonZeroU64 = nonzero!(4_u64);
    const MIN_SLASHING_PENALTY_QUOTIENT: NonZeroU64 = nonzero!(64_u64);
    const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 2;
    const SHUFFLE_ROUND_COUNT: u8 = 10;
    const TARGET_COMMITTEE_SIZE: NonZeroU64 = nonzero!(4_u64);

    // Altair
    const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: NonZeroU64 = nonzero!(8_u64);

    // Capella
    const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16;
}

/// [Medalla preset](https://github.com/eth-clients/eth2-networks/blob/674f7a1d01d9c18345456eab76e3871b3df2126b/shared/medalla/config.yaml).
///
/// Also available at <https://github.com/goerli/medalla/blob/124fe40d26e8a10fa44dbe48dcba828ea1237054/medalla/chain.yaml>.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Medalla;

impl Preset for Medalla {
    delegate_preset_items! {
        super Mainnet;

        // Phase 0
        type EpochsPerHistoricalRoot;
        type EpochsPerHistoricalVector;
        type EpochsPerSlashingsVector;
        type HistoricalRootsLimit;
        type MaxAttestations;
        type MaxAttesterSlashings;
        type MaxDeposits;
        type MaxProposerSlashings;
        type MaxValidatorsPerCommittee;
        type MaxVoluntaryExits;
        type SlotsPerEpoch;
        type ValidatorRegistryLimit;

        // Altair
        type SyncCommitteeSize;

        // Bellatrix
        type BytesPerLogsBloom;
        type MaxBytesPerTransaction;
        type MaxExtraDataBytes;
        type MaxTransactionsPerPayload;

        // Capella
        type MaxBlsToExecutionChanges;
        type MaxWithdrawalsPerPayload;

        // Deneb
        type FieldElementsPerBlob;
        type MaxBlobCommitmentsPerBlock;
        type MaxBlobsPerBlock;
        type KzgCommitmentInclusionProofDepth;

        // Derived type-level variables
        type BytesPerBlob;
        type MaxAttestationsPerEpoch;
        type SlotsPerHistoricalRoot;
        type SyncSubcommitteeSize;
    }

    // Phase 0
    type EpochsPerEth1VotingPeriod = U32;

    // Derived type-level variables
    type SlotsPerEth1VotingPeriod = Prod<Self::EpochsPerEth1VotingPeriod, Self::SlotsPerEpoch>;

    // Meta
    const NAME: PresetName = PresetName::Medalla;

    // Phase 0
    const INACTIVITY_PENALTY_QUOTIENT: NonZeroU64 = nonzero!(1_u64 << 24);
    const MIN_SLASHING_PENALTY_QUOTIENT: NonZeroU64 = nonzero!(32_u64);
    const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 3;
}

#[derive(Clone, Copy, Debug, Display, EnumString, DeserializeFromStr, SerializeDisplay)]
#[strum(serialize_all = "lowercase")]
#[cfg_attr(test, derive(PartialEq, Eq, Sequence, VariantNames))]
pub enum PresetName {
    Mainnet,
    Minimal,
    Medalla,
}

impl PresetName {
    #[must_use]
    pub fn phase0_preset(self) -> Phase0Preset {
        match self {
            Self::Mainnet => Phase0Preset::new::<Mainnet>(),
            Self::Minimal => Phase0Preset::new::<Minimal>(),
            Self::Medalla => Phase0Preset::new::<Medalla>(),
        }
    }

    #[must_use]
    pub fn altair_preset(self) -> AltairPreset {
        match self {
            Self::Mainnet => AltairPreset::new::<Mainnet>(),
            Self::Minimal => AltairPreset::new::<Minimal>(),
            Self::Medalla => AltairPreset::new::<Medalla>(),
        }
    }

    #[must_use]
    pub fn bellatrix_preset(self) -> BellatrixPreset {
        match self {
            Self::Mainnet => BellatrixPreset::new::<Mainnet>(),
            Self::Minimal => BellatrixPreset::new::<Minimal>(),
            Self::Medalla => BellatrixPreset::new::<Medalla>(),
        }
    }

    #[must_use]
    pub fn capella_preset(self) -> CapellaPreset {
        match self {
            Self::Mainnet => CapellaPreset::new::<Mainnet>(),
            Self::Minimal => CapellaPreset::new::<Minimal>(),
            Self::Medalla => CapellaPreset::new::<Medalla>(),
        }
    }

    #[must_use]
    pub fn deneb_preset(self) -> DenebPreset {
        match self {
            Self::Mainnet => DenebPreset::new::<Mainnet>(),
            Self::Minimal => DenebPreset::new::<Minimal>(),
            Self::Medalla => DenebPreset::new::<Medalla>(),
        }
    }

    fn default_config(self) -> Config {
        match self {
            Self::Mainnet => Config::mainnet(),
            Self::Minimal => Config::minimal(),
            Self::Medalla => Config::medalla(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
pub struct Phase0Preset {
    // > Misc
    #[serde(with = "serde_utils::string_or_native")]
    hysteresis_downward_multiplier: u64,
    #[serde(with = "serde_utils::string_or_native")]
    hysteresis_quotient: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    hysteresis_upward_multiplier: u64,
    #[serde(with = "serde_utils::string_or_native")]
    max_committees_per_slot: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    max_validators_per_committee: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    shuffle_round_count: u8,
    #[serde(with = "serde_utils::string_or_native")]
    target_committee_size: NonZeroU64,

    // > Gwei values
    #[serde(with = "serde_utils::string_or_native")]
    effective_balance_increment: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    max_effective_balance: Gwei,
    #[serde(with = "serde_utils::string_or_native")]
    min_deposit_amount: Gwei,

    // > Time parameters
    #[serde(with = "serde_utils::string_or_native")]
    epochs_per_eth1_voting_period: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    max_seed_lookahead: u64,
    #[serde(with = "serde_utils::string_or_native")]
    min_attestation_inclusion_delay: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    min_epochs_to_inactivity_penalty: u64,
    #[serde(with = "serde_utils::string_or_native")]
    min_seed_lookahead: u64,
    #[serde(with = "serde_utils::string_or_native")]
    slots_per_epoch: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    slots_per_historical_root: NonZeroU64,

    // > State list lengths
    #[serde(with = "serde_utils::string_or_native")]
    epochs_per_historical_vector: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    epochs_per_slashings_vector: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    historical_roots_limit: u64,
    #[serde(with = "serde_utils::string_or_native")]
    validator_registry_limit: NonZeroU64,

    // > Reward and penalty quotients
    #[serde(with = "serde_utils::string_or_native")]
    base_reward_factor: u64,
    #[serde(with = "serde_utils::string_or_native")]
    inactivity_penalty_quotient: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    min_slashing_penalty_quotient: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    proportional_slashing_multiplier: u64,
    #[serde(with = "serde_utils::string_or_native")]
    proposer_reward_quotient: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    whistleblower_reward_quotient: NonZeroU64,

    // > Max operations per block
    #[serde(with = "serde_utils::string_or_native")]
    max_attestations: u64,
    #[serde(with = "serde_utils::string_or_native")]
    max_attester_slashings: u64,
    #[serde(with = "serde_utils::string_or_native")]
    max_deposits: u64,
    #[serde(with = "serde_utils::string_or_native")]
    max_proposer_slashings: u64,
    #[serde(with = "serde_utils::string_or_native")]
    max_voluntary_exits: u64,
}

impl Phase0Preset {
    #[must_use]
    pub fn new<P: Preset>() -> Self {
        Self {
            // > Misc
            hysteresis_downward_multiplier: P::HYSTERESIS_DOWNWARD_MULTIPLIER,
            hysteresis_quotient: P::HYSTERESIS_QUOTIENT,
            hysteresis_upward_multiplier: P::HYSTERESIS_UPWARD_MULTIPLIER,
            max_committees_per_slot: P::MAX_COMMITTEES_PER_SLOT,
            max_validators_per_committee: P::MaxValidatorsPerCommittee::non_zero(),
            shuffle_round_count: P::SHUFFLE_ROUND_COUNT,
            target_committee_size: P::TARGET_COMMITTEE_SIZE,

            // > Gwei values
            effective_balance_increment: P::EFFECTIVE_BALANCE_INCREMENT,
            max_effective_balance: P::MAX_EFFECTIVE_BALANCE,
            min_deposit_amount: P::MIN_DEPOSIT_AMOUNT,

            // > Time parameters
            epochs_per_eth1_voting_period: P::EpochsPerEth1VotingPeriod::non_zero(),
            max_seed_lookahead: P::MAX_SEED_LOOKAHEAD,
            min_attestation_inclusion_delay: P::MIN_ATTESTATION_INCLUSION_DELAY,
            min_epochs_to_inactivity_penalty: P::MIN_EPOCHS_TO_INACTIVITY_PENALTY,
            min_seed_lookahead: P::MIN_SEED_LOOKAHEAD,
            slots_per_epoch: P::SlotsPerEpoch::non_zero(),
            slots_per_historical_root: P::SlotsPerHistoricalRoot::non_zero(),

            // > State list lengths
            epochs_per_historical_vector: P::EpochsPerHistoricalVector::non_zero(),
            epochs_per_slashings_vector: P::EpochsPerSlashingsVector::non_zero(),
            historical_roots_limit: P::HistoricalRootsLimit::U64,
            validator_registry_limit: P::ValidatorRegistryLimit::non_zero(),

            // > Reward and penalty quotients
            base_reward_factor: P::BASE_REWARD_FACTOR,
            inactivity_penalty_quotient: P::INACTIVITY_PENALTY_QUOTIENT,
            min_slashing_penalty_quotient: P::MIN_SLASHING_PENALTY_QUOTIENT,
            proportional_slashing_multiplier: P::PROPORTIONAL_SLASHING_MULTIPLIER,
            proposer_reward_quotient: P::PROPOSER_REWARD_QUOTIENT,
            whistleblower_reward_quotient: P::WHISTLEBLOWER_REWARD_QUOTIENT,

            // > Max operations per block
            max_attestations: P::MaxAttestations::U64,
            max_attester_slashings: P::MaxAttesterSlashings::U64,
            max_deposits: P::MaxDeposits::U64,
            max_proposer_slashings: P::MaxProposerSlashings::U64,
            max_voluntary_exits: P::MaxVoluntaryExits::U64,
        }
    }

    #[must_use]
    pub const fn slots_per_epoch(&self) -> NonZeroU64 {
        self.slots_per_epoch
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
pub struct AltairPreset {
    // > Updated penalty values
    #[serde(with = "serde_utils::string_or_native")]
    inactivity_penalty_quotient_altair: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    min_slashing_penalty_quotient_altair: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    proportional_slashing_multiplier_altair: u64,

    // > Sync committee
    #[serde(with = "serde_utils::string_or_native")]
    epochs_per_sync_committee_period: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    sync_committee_size: NonZeroU64,

    // > Sync protocol
    #[serde(with = "serde_utils::string_or_native")]
    min_sync_committee_participants: usize,
    #[serde(with = "serde_utils::string_or_native")]
    update_timeout: NonZeroU64,
}

impl AltairPreset {
    #[must_use]
    pub fn new<P: Preset>() -> Self {
        Self {
            // > Updated penalty values
            inactivity_penalty_quotient_altair: P::INACTIVITY_PENALTY_QUOTIENT_ALTAIR,
            min_slashing_penalty_quotient_altair: P::MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR,
            proportional_slashing_multiplier_altair: P::PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR,

            // > Sync committee
            epochs_per_sync_committee_period: P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
            sync_committee_size: P::SyncCommitteeSize::non_zero(),

            // > Sync protocol
            min_sync_committee_participants: P::MIN_SYNC_COMMITTEE_PARTICIPANTS,
            update_timeout: (P::SlotsPerEpoch::U64 * P::EPOCHS_PER_SYNC_COMMITTEE_PERIOD.get())
                .try_into()
                .expect("both factors are nonzero"),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
pub struct BellatrixPreset {
    // > Updated penalty values
    #[serde(with = "serde_utils::string_or_native")]
    inactivity_penalty_quotient_bellatrix: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    min_slashing_penalty_quotient_bellatrix: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    proportional_slashing_multiplier_bellatrix: u64,

    // > Execution
    #[serde(with = "serde_utils::string_or_native")]
    bytes_per_logs_bloom: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    max_bytes_per_transaction: u64,
    #[serde(with = "serde_utils::string_or_native")]
    max_extra_data_bytes: u64,
    #[serde(with = "serde_utils::string_or_native")]
    max_transactions_per_payload: u64,
}

impl BellatrixPreset {
    #[must_use]
    pub fn new<P: Preset>() -> Self {
        Self {
            // > Updated penalty values
            inactivity_penalty_quotient_bellatrix: P::INACTIVITY_PENALTY_QUOTIENT_BELLATRIX,
            min_slashing_penalty_quotient_bellatrix: P::MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX,
            proportional_slashing_multiplier_bellatrix:
                P::PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX,

            // > Execution
            bytes_per_logs_bloom: P::BytesPerLogsBloom::non_zero(),
            max_bytes_per_transaction: P::MaxBytesPerTransaction::U64,
            max_extra_data_bytes: P::MaxExtraDataBytes::U64,
            max_transactions_per_payload: P::MaxTransactionsPerPayload::U64,
        }
    }
}

#[allow(clippy::struct_field_names)]
// Clippy does approve of all members starting with max.
// However, specification is written with these terms.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
pub struct CapellaPreset {
    // > Max operations per block
    #[serde(with = "serde_utils::string_or_native")]
    max_bls_to_execution_changes: u64,

    // > Execution
    #[serde(with = "serde_utils::string_or_native")]
    max_withdrawals_per_payload: NonZeroU64,

    // > Withdrawals processing
    #[serde(with = "serde_utils::string_or_native")]
    max_validators_per_withdrawals_sweep: u64,
}

impl CapellaPreset {
    #[must_use]
    pub fn new<P: Preset>() -> Self {
        Self {
            // > Max operations per block
            max_bls_to_execution_changes: P::MaxBlsToExecutionChanges::U64,

            // > Execution
            max_withdrawals_per_payload: P::MaxWithdrawalsPerPayload::non_zero(),

            // > Withdrawals processing
            max_validators_per_withdrawals_sweep: P::MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
pub struct DenebPreset {
    // > Misc
    #[serde(with = "serde_utils::string_or_native")]
    field_elements_per_blob: NonZeroU64,
    #[serde(with = "serde_utils::string_or_native")]
    max_blob_commitments_per_block: u64,
    #[serde(with = "serde_utils::string_or_native")]
    max_blobs_per_block: u64,
    #[serde(with = "serde_utils::string_or_native")]
    kzg_committment_inclusion_proof_depth: u64,
}

impl DenebPreset {
    #[must_use]
    pub fn new<P: Preset>() -> Self {
        Self {
            // > Misc
            field_elements_per_blob: P::FieldElementsPerBlob::non_zero(),
            max_blob_commitments_per_block: P::MaxBlobCommitmentsPerBlock::U64,
            max_blobs_per_block: P::MaxBlobsPerBlock::U64,
            kzg_committment_inclusion_proof_depth: P::KzgCommitmentInclusionProofDepth::U64,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ops::Deref;

    // use strum::VariantNames as _;

    use crate::nonstandard::Phase;

    use super::*;

    // Ensure that `PresetName` has a variant for each `Preset` impl
    // and that all `Preset::NAME` implementations are distinct.
    #[test]
    fn preset_types_constants_variants_all_match() {
        let types = include_str!("preset.rs")
            .lines()
            .filter_map(|line| line.strip_prefix("impl Preset for "))
            .filter_map(|line| line.strip_suffix(" {"))
            .map(str::to_lowercase);

        let constants = include_str!("preset.rs")
            .lines()
            .filter_map(|line| line.strip_prefix("    const NAME: PresetName = PresetName::"))
            .filter_map(|line| line.strip_suffix(';'))
            .map(str::to_lowercase);

        let variants = PresetName::VARIANTS
            .iter()
            .map(Deref::deref)
            .map(str::to_owned);

        itertools::assert_equal(types, variants.clone());
        itertools::assert_equal(constants, variants);
    }

    #[test]
    fn preset_bases_are_consistent_with_default_configs() {
        for preset_name in enum_iterator::all::<PresetName>() {
            assert_eq!(preset_name.default_config().preset_base, preset_name);
        }
    }

    #[test]
    fn preset_struct_construction_does_not_panic() {
        for preset_name in enum_iterator::all::<PresetName>() {
            // Do not remove the type annotation.
            // It ensures that this test is up to date when new phases are added.
            let _: [&dyn Send; Phase::CARDINALITY] = [
                &preset_name.phase0_preset(),
                &preset_name.altair_preset(),
                &preset_name.bellatrix_preset(),
                &preset_name.capella_preset(),
                &preset_name.deneb_preset(),
            ];
        }
    }
}
