use core::num::NonZeroU64;
use std::sync::Arc;

use anyhow::{ensure, Result};
use arithmetic::U64Ext as _;
use bls::Backend;
use deposit_tree::DepositTree;
use helper_functions::{accessors, misc, mutators::increase_balance};
use ssz::{PersistentList, PersistentVector, SszHash as _};
use std_ext::ArcExt as _;
use thiserror::Error;
use transition_functions::combined;
use types::{
    altair::{
        beacon_state::BeaconState as AltairBeaconState,
        containers::{BeaconBlock as AltairBeaconBlock, BeaconBlockBody as AltairBeaconBlockBody},
    },
    bellatrix::{
        beacon_state::BeaconState as BellatrixBeaconState,
        containers::{
            BeaconBlock as BellatrixBeaconBlock, BeaconBlockBody as BellatrixBeaconBlockBody,
        },
    },
    capella::{
        beacon_state::BeaconState as CapellaBeaconState,
        containers::{
            BeaconBlock as CapellaBeaconBlock, BeaconBlockBody as CapellaBeaconBlockBody,
        },
    },
    combined::{BeaconBlock, BeaconState, ExecutionPayloadHeader, SignedBeaconBlock},
    config::Config,
    deneb::{
        beacon_state::BeaconState as DenebBeaconState,
        containers::{BeaconBlock as DenebBeaconBlock, BeaconBlockBody as DenebBeaconBlockBody},
    },
    electra::{
        beacon_state::BeaconState as ElectraBeaconState,
        consts::UNSET_DEPOSIT_REQUESTS_START_INDEX,
        containers::{
            BeaconBlock as ElectraBeaconBlock, BeaconBlockBody as ElectraBeaconBlockBody,
        },
    },
    nonstandard::{FinalizedCheckpoint, Phase, RelativeEpoch, WithOrigin},
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::{GENESIS_EPOCH, GENESIS_SLOT},
        containers::{
            BeaconBlock as Phase0BeaconBlock, BeaconBlockBody as Phase0BeaconBlockBody,
            BeaconBlockHeader, DepositData, Fork,
        },
        primitives::{DepositIndex, ExecutionBlockHash, UnixSeconds, H256},
    },
    preset::Preset,
    traits::BeaconState as _,
};

pub struct Incremental<'config, P: Preset> {
    config: &'config Config,
    beacon_state: BeaconState<P>,
    deposit_tree: DepositTree,
    backend: Backend,
}

impl<'config, P: Preset> Incremental<'config, P> {
    /// <https://github.com/ethereum/consensus-specs/blob/2fa396f67df35df236b6aa6fe714a59ee1032dc8/specs/phase0/beacon-chain.md#genesis>
    #[must_use]
    pub fn new(config: &'config Config, backend: Backend) -> Self {
        let slot = GENESIS_SLOT;
        let phase = config.phase_at_slot::<P>(slot);
        let version = config.version(phase);

        let fork = Fork {
            previous_version: version,
            current_version: version,
            epoch: GENESIS_EPOCH,
        };

        let body_root = match phase {
            Phase::Phase0 => Phase0BeaconBlockBody::<P>::default().hash_tree_root(),
            Phase::Altair => AltairBeaconBlockBody::<P>::default().hash_tree_root(),
            Phase::Bellatrix => BellatrixBeaconBlockBody::<P>::default().hash_tree_root(),
            Phase::Capella => CapellaBeaconBlockBody::<P>::default().hash_tree_root(),
            Phase::Deneb => DenebBeaconBlockBody::<P>::default().hash_tree_root(),
            Phase::Electra => ElectraBeaconBlockBody::<P>::default().hash_tree_root(),
        };

        let latest_block_header = BeaconBlockHeader {
            slot,
            body_root,
            ..BeaconBlockHeader::default()
        };

        let beacon_state = match phase {
            Phase::Phase0 => Phase0BeaconState {
                slot,
                fork,
                latest_block_header,
                ..Phase0BeaconState::default()
            }
            .into(),
            Phase::Altair => AltairBeaconState {
                slot,
                fork,
                latest_block_header,
                ..AltairBeaconState::default()
            }
            .into(),
            Phase::Bellatrix => BellatrixBeaconState {
                slot,
                fork,
                latest_block_header,
                ..BellatrixBeaconState::default()
            }
            .into(),
            Phase::Capella => CapellaBeaconState {
                slot,
                fork,
                latest_block_header,
                ..CapellaBeaconState::default()
            }
            .into(),
            Phase::Deneb => DenebBeaconState {
                slot,
                fork,
                latest_block_header,
                ..DenebBeaconState::default()
            }
            .into(),
            Phase::Electra => ElectraBeaconState {
                slot,
                fork,
                latest_block_header,
                deposit_requests_start_index: UNSET_DEPOSIT_REQUESTS_START_INDEX,
                ..ElectraBeaconState::default()
            }
            .into(),
        };

        Self {
            config,
            beacon_state,
            deposit_tree: DepositTree::default(),
            backend,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_genesis_state(self.config, &self.beacon_state)
    }

    pub fn set_eth1_timestamp(&mut self, eth1_timestamp: UnixSeconds) {
        *self.beacon_state.genesis_time_mut() = eth1_timestamp + self.config.genesis_delay;
    }

    pub fn add_deposit_data(
        &mut self,
        data: DepositData,
        deposit_index: DepositIndex,
    ) -> Result<()> {
        let is_post_electra = self.beacon_state.is_post_electra();
        let eth1_data = self.beacon_state.eth1_data_mut();

        eth1_data.deposit_root = self
            .deposit_tree
            .push_and_compute_root(deposit_index, data)?;

        eth1_data.deposit_count = self.deposit_tree.deposit_count;

        if let Some(validator_index) =
            combined::process_deposit_data(self.config, &mut self.beacon_state, data, self.backend)?
        {
            if let Some(state) = self.beacon_state.post_electra_mut() {
                let pending_deposits = state.pending_deposits().clone();

                for deposit in &pending_deposits {
                    let validator_index = accessors::index_of_public_key(state, deposit.pubkey)
                        .expect(
                            "public keys in state.pending_deposits are taken from state.validators",
                        );

                    let balance = state.balances_mut().get_mut(validator_index)?;
                    increase_balance(balance, deposit.amount);
                }

                *state.pending_deposits_mut() = PersistentList::default();
            }

            let balance = *self.beacon_state.balances().get(validator_index)?;

            let validator = self
                .beacon_state
                .validators_mut()
                .get_mut(validator_index)?;

            if is_post_electra {
                validator.effective_balance = balance
                    .prev_multiple_of(P::EFFECTIVE_BALANCE_INCREMENT)
                    .min(misc::get_max_effective_balance::<P>(validator));

                if validator.effective_balance >= P::MIN_ACTIVATION_BALANCE {
                    validator.activation_eligibility_epoch = GENESIS_EPOCH;
                    validator.activation_epoch = GENESIS_EPOCH;
                }
            } else {
                validator.effective_balance = balance
                    .prev_multiple_of(P::EFFECTIVE_BALANCE_INCREMENT)
                    .min(P::MAX_EFFECTIVE_BALANCE);

                if validator.effective_balance == P::MAX_EFFECTIVE_BALANCE {
                    validator.activation_eligibility_epoch = GENESIS_EPOCH;
                    validator.activation_epoch = GENESIS_EPOCH;
                }
            }
        }

        Ok(())
    }

    pub fn finish(
        self,
        eth1_block_hash: ExecutionBlockHash,
        execution_payload_header: Option<ExecutionPayloadHeader<P>>,
    ) -> Result<(BeaconState<P>, DepositTree)> {
        let Self {
            mut beacon_state,
            deposit_tree,
            ..
        } = self;

        beacon_state.eth1_data_mut().block_hash = eth1_block_hash;

        // > Seed RANDAO with Eth1 entropy
        *beacon_state.randao_mixes_mut() = PersistentVector::repeat_element(eth1_block_hash);

        // > Set genesis validators root for domain separation and chain versioning
        *beacon_state.genesis_validators_root_mut() = beacon_state.validators().hash_tree_root();

        // > [New in Altair] Fill in sync committees
        // > Note: A duplicate committee is assigned for the current and next committee at genesis
        if let Some(state) = beacon_state.post_altair_mut() {
            let sync_committee = accessors::get_next_sync_committee(state, self.backend)?;
            *state.current_sync_committee_mut() = sync_committee.clone_arc();
            *state.next_sync_committee_mut() = sync_committee;
        }

        // > [New in Bellatrix] Initialize the execution payload header
        // > If empty, will initialize a chain that has not yet gone through the Merge transition
        let beacon_state = beacon_state.with_execution_payload_header(execution_payload_header)?;

        Ok((beacon_state, deposit_tree))
    }
}

#[derive(Clone)]
pub enum AnchorCheckpointProvider<P: Preset> {
    Predefined(WithOrigin<FinalizedCheckpoint<P>>, H256),
    Custom(WithOrigin<FinalizedCheckpoint<P>>),
}

impl<P: Preset> AnchorCheckpointProvider<P> {
    pub fn custom_from_genesis(genesis_state: Arc<BeaconState<P>>) -> Self {
        let block = Arc::new(beacon_block(&genesis_state));

        Self::Custom(WithOrigin::new_from_genesis(FinalizedCheckpoint {
            block,
            state: genesis_state,
        }))
    }

    #[must_use]
    pub fn checkpoint(&self) -> WithOrigin<FinalizedCheckpoint<P>> {
        match self {
            Self::Custom(checkpoint) | Self::Predefined(checkpoint, _) => checkpoint.clone(),
        }
    }

    #[must_use]
    pub fn state_root(&self) -> H256 {
        match self {
            Self::Predefined(_, state_root) => *state_root,
            Self::Custom(checkpoint) => checkpoint.value.state.hash_tree_root(),
        }
    }
}

#[derive(Debug, Error)]
enum GenesisTriggerError {
    #[error("too early ({actual_genesis_time} < {minimum_genesis_time})")]
    TooEarly {
        minimum_genesis_time: UnixSeconds,
        actual_genesis_time: UnixSeconds,
    },
    #[error("not enough active validators ({actual_validator_count} < {minimum_validator_count})")]
    NotEnoughActiveValidators {
        minimum_validator_count: NonZeroU64,
        actual_validator_count: u64,
    },
}

/// <https://github.com/ethereum/consensus-specs/blob/2fa396f67df35df236b6aa6fe714a59ee1032dc8/specs/phase0/beacon-chain.md#genesis-block>
#[must_use]
pub fn beacon_block<P: Preset>(genesis_state: &BeaconState<P>) -> SignedBeaconBlock<P> {
    beacon_block_internal(genesis_state.phase(), genesis_state.hash_tree_root())
}

fn beacon_block_internal<P: Preset>(phase: Phase, state_root: H256) -> SignedBeaconBlock<P> {
    // The way the genesis block is constructed makes it possible for many parties to independently
    // produce the same block. But why does the genesis block have to exist at all? Perhaps the
    // first block could be proposed by a validator as well (and not necessarily in slot 0)?

    // Note that `BeaconBlock.body.eth1_data` is not set to `genesis_state.eth1_data()`.
    match phase {
        Phase::Phase0 => BeaconBlock::from(Phase0BeaconBlock::default()),
        Phase::Altair => BeaconBlock::from(AltairBeaconBlock::default()),
        Phase::Bellatrix => BeaconBlock::from(BellatrixBeaconBlock::default()),
        Phase::Capella => BeaconBlock::from(CapellaBeaconBlock::default()),
        Phase::Deneb => BeaconBlock::from(DenebBeaconBlock::default()),
        Phase::Electra => BeaconBlock::from(ElectraBeaconBlock::default()),
    }
    .with_state_root(state_root)
    .with_zero_signature()
}

/// <https://github.com/ethereum/consensus-specs/blob/2fa396f67df35df236b6aa6fe714a59ee1032dc8/specs/phase0/beacon-chain.md#genesis-state>
fn validate_genesis_state<P: Preset>(config: &Config, state: &BeaconState<P>) -> Result<()> {
    let minimum_genesis_time = config.min_genesis_time;
    let actual_genesis_time = state.genesis_time();

    ensure!(
        minimum_genesis_time <= actual_genesis_time,
        GenesisTriggerError::TooEarly {
            minimum_genesis_time,
            actual_genesis_time,
        },
    );

    let minimum_validator_count = config.min_genesis_active_validator_count;
    // `helper_functions::accessors::active_validator_count_u64` cannot be used here.
    // Caching is not designed to work with candidate genesis states.
    let actual_validator_count =
        accessors::get_active_validator_indices(state, RelativeEpoch::Current)
            .count()
            .try_into()?;

    ensure!(
        minimum_validator_count.get() <= actual_validator_count,
        GenesisTriggerError::NotEnoughActiveValidators {
            minimum_validator_count,
            actual_validator_count,
        },
    );

    Ok(())
}

#[cfg(test)]
mod spec_tests {
    use bls::Backend;
    use duplicate::duplicate_item;
    use serde::Deserialize;
    use spec_test_utils::Case;
    use test_generator::test_resources;
    use types::{
        phase0::{
            containers::Deposit,
            primitives::{ExecutionBlockHash, UnixSeconds},
        },
        preset::Minimal,
    };

    use super::*;

    // We do not honor `bls_setting` in genesis tests because none of them customize it.
    //
    // The globs passed to `test_resources` match all presets but we run the test cases with
    // the minimal preset because genesis tests are only provided for the minimal preset.

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Eth1 {
        eth1_block_hash: ExecutionBlockHash,
        eth1_timestamp: UnixSeconds,
    }

    #[duplicate_item(
        glob                                                                  function_name              phase;
        ["consensus-spec-tests/tests/*/phase0/genesis/initialization/*/*"]    [phase0_initialization]    [Phase0];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_initialization_case(case, Phase::phase);
    }

    #[duplicate_item(
        glob                                                            function_name;
        ["consensus-spec-tests/tests/*/phase0/genesis/validity/*/*"]    [phase0_validity];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        run_validity_case(case);
    }

    fn run_initialization_case(case: Case, phase: Phase) {
        let config = Arc::new(Config::minimal().start_and_stay_in(phase));

        let Eth1 {
            eth1_block_hash,
            eth1_timestamp,
        } = case.yaml("eth1");

        let meta = case.meta();
        let deposits_count = meta.deposits_count;
        let deposits = case.numbered_default::<Deposit>("deposits", 0..deposits_count);
        let expected_genesis_state = case.ssz::<_, BeaconState<Minimal>>(&config, "state");

        let execution_payload_header = match phase {
            Phase::Phase0 | Phase::Altair => {
                assert!(!case.exists("execution_payload_header"));
                None
            }
            Phase::Bellatrix => case
                .try_ssz_default("execution_payload_header")
                .map(ExecutionPayloadHeader::Bellatrix),
            Phase::Capella => case
                .try_ssz_default("execution_payload_header")
                .map(ExecutionPayloadHeader::Capella),
            Phase::Deneb | Phase::Electra => case
                .try_ssz_default("execution_payload_header")
                .map(ExecutionPayloadHeader::Deneb),
        };

        assert_eq!(
            execution_payload_header.is_some(),
            meta.execution_payload_header,
        );

        let mut incremental = Incremental::new(&config, Backend::default());

        incremental.set_eth1_timestamp(eth1_timestamp);

        for (deposit, index) in deposits.zip(0..) {
            incremental
                .add_deposit_data(deposit.data, index)
                .expect("deposits are not enough to fill tree and have correct indices");
        }

        let (actual_genesis_state, _) = incremental
            .finish(eth1_block_hash, execution_payload_header)
            .expect("genesis state should be constructed successfully");

        assert_eq!(actual_genesis_state, expected_genesis_state);
    }

    fn run_validity_case(case: Case) {
        let config = Config::minimal().start_and_stay_in(Phase::Phase0);
        let genesis_state = case.ssz::<_, BeaconState<Minimal>>(&config, "genesis");
        let is_valid = case.yaml("is_valid");

        let result = validate_genesis_state(&config, &genesis_state);

        if is_valid {
            result.expect("state should be a valid genesis state");
        } else {
            result.expect_err("state should not be a valid genesis state");
        }
    }
}

#[cfg(test)]
mod extra_tests {
    use bls::{Backend, SecretKey, SecretKeyBytes};
    use helper_functions::signing::SignForAllForks;
    use std_ext::CopyExt as _;
    use tap::Conv as _;
    use types::{
        phase0::{containers::DepositMessage, primitives::H256},
        preset::Mainnet,
    };

    use super::*;

    #[test]
    fn genesis_add_deposit_data_activates_validator_if_top_up_maxes_balance() -> Result<()> {
        let config = Config::mainnet();
        let half_deposit_data = half_deposit_data::<Mainnet>()?;
        let eth1_block_hash = ExecutionBlockHash::default();

        let mut incremental = Incremental::<Mainnet>::new(&config, Backend::default());

        incremental.add_deposit_data(half_deposit_data, 0)?;
        incremental.add_deposit_data(half_deposit_data, 1)?;

        let (beacon_state, _) = incremental.finish(eth1_block_hash, None)?;

        assert_eq!(beacon_state.validators().len_usize(), 1);
        assert_eq!(
            accessors::active_validator_count_usize(&beacon_state, RelativeEpoch::Current),
            1,
        );

        Ok(())
    }

    fn half_deposit_data<P: Preset>() -> Result<DepositData> {
        let secret_key = SecretKey::try_from_with_backend(
            b"????????????????????????????????"
                .copy()
                .conv::<SecretKeyBytes>(),
            Backend::default(),
        )?;

        let pubkey = secret_key.to_public_key().into();
        let withdrawal_credentials = H256::default();
        let amount = P::MAX_EFFECTIVE_BALANCE / 2;

        let deposit_message = DepositMessage {
            pubkey,
            withdrawal_credentials,
            amount,
        };

        let signature = deposit_message
            .sign(&P::default_config(), &secret_key)
            .into();

        Ok(DepositData {
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
        })
    }
}
