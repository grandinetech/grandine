use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::BitVector;
use typenum::Unsigned;
use types::{
    cache::Cache,
    collections::{
        Attestations, Balances, Eth1DataVotes, HistoricalRoots, RandaoMixes, RecentRoots,
        Slashings, Validators,
    },
    phase0::{
        beacon_state::BeaconState,
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, Fork, Validator},
        primitives::{DepositIndex, Epoch, Gwei, H256, Slot, UnixSeconds},
    },
    preset::{Preset, SlotsPerHistoricalRoot},
};

#[derive(Debug, Clone, Default, Derivative, Serialize, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub struct BeaconStateDelta<P: Preset> {
    // > Versioning
    pub genesis_time: UnixSeconds,
    pub genesis_validators_root: H256,
    pub slot: Slot,
    pub fork: Fork,

    // > History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: Vec<H256>,
    pub state_roots: Vec<H256>,
    pub historical_roots: Option<HistoricalRoots<P>>,

    // > Eth1
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: Eth1DataVotes<P>,
    pub eth1_deposit_index: DepositIndex,

    // > Registry
    pub validators: ValidatorsChange,
    pub balances: BalanceDiffs,

    // > Randomness
    pub randao_mixes: RandaoChange,

    // > Slashings
    pub slashings: Option<Vec<SlashingChange>>,

    // > Attestations
    pub previous_epoch_attestations: Attestations<P>,
    pub current_epoch_attestations: Attestations<P>,

    // > Finality
    pub justification_bits: Option<BitVector<JustificationBitsLength>>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // Cache
    #[derivative(PartialEq = "ignore")]
    #[serde(skip)]
    pub cache: Cache,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RandaoChange {
    pub start_idx: u64,
    pub new_mixes: Vec<H256>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SlashingChange {
    pub index: u64,
    pub new_slashing: Gwei,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BalanceDiffs {
    tags: BitTagVec,
    small_diffs: Vec<i32>,
    target_values: Vec<Gwei>,
    new_balances: Vec<Gwei>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ValidatorFieldChanges {
    pub withdrawal_credentials: Option<H256>,
    pub effective_balance: Option<Gwei>,
    pub slashed: Option<bool>,
    pub activation_eligibility_epoch: Option<Epoch>,
    pub activation_epoch: Option<Epoch>,
    pub exit_epoch: Option<Epoch>,
    pub withdrawable_epoch: Option<Epoch>,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct ValidatorsChange {
    pub new_validators: Vec<Validator>,
    pub modified_validators: Vec<(u64, ValidatorFieldChanges)>,
}

// represent each field with a tag,
// since values are restricted, especially in the case of balances
// and it can be represented enough with 4 values,
// therefore tags 00, 01, 10 and 11
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BitTagVec {
    data: Vec<u8>, // 4 entries per byte
    len: usize,
}

const SET_NO_CHANGE: u8 = 0b00;
const SET_TO_ZERO: u8 = 0b10;
const SET_TO_DIFF: u8 = 0b11;
const SET_TO_TARGET_VALUE: u8 = 0b01;

impl BitTagVec {
    pub fn new(len: usize) -> Self {
        let bytes = len.div_ceil(4);
        Self {
            data: vec![0; bytes],
            len,
        }
    }

    #[inline]
    pub fn set(&mut self, idx: usize, tag: u8) {
        let byte = idx / 4;
        let shift = (idx % 4) * 2;

        self.data[byte] |= (tag & 0b11) << shift;
    }

    #[inline]
    pub fn get(&self, idx: usize) -> u8 {
        let byte = idx / 4;
        let shift = (idx % 4) * 2;
        (self.data[byte] >> shift) & 0b11
    }
}

pub fn delta<P: Preset>(base: &BeaconState<P>, target: BeaconState<P>) -> BeaconStateDelta<P> {
    let base_slot = base.slot;
    let target_slot = target.slot;

    let genesis_time = target.genesis_time;

    let genesis_validators_root = target.genesis_validators_root;
    let fork = target.fork;
    let slot = target_slot;
    let latest_block_header = target.latest_block_header;

    let target_block_roots = target.block_roots;
    let block_roots = roots_delta::<P>(base_slot, target_slot, &target_block_roots);

    let target_state_roots = target.state_roots;
    let state_roots = roots_delta::<P>(base_slot, target_slot, &target_state_roots);

    let historical_roots =
        (target.historical_roots != base.historical_roots).then_some(target.historical_roots);

    let eth1_data = target.eth1_data;
    let eth1_data_votes = target.eth1_data_votes;
    let eth1_deposit_index = target.eth1_deposit_index;

    let validators = validators_delta::<P>(&base.validators, &target.validators);
    let balances = balances_delta::<P>(&base.balances, &target.balances);

    let randao_mixes = randao_delta::<P>(base_slot, target_slot, &target.randao_mixes);

    let slashings =
        slashings_delta::<P>(base_slot, &base.slashings, target_slot, &target.slashings);

    let previous_epoch_attestations = target.previous_epoch_attestations;
    let current_epoch_attestations = target.current_epoch_attestations;

    let justification_bits =
        (target.justification_bits != base.justification_bits).then_some(target.justification_bits);

    let previous_justified_checkpoint = target.previous_justified_checkpoint;
    let current_justified_checkpoint = target.current_justified_checkpoint;
    let finalized_checkpoint = target.finalized_checkpoint;

    let cache = target.cache;

    BeaconStateDelta {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_attestations,
        current_epoch_attestations,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        cache,
    }
}

pub fn apply_delta<P: Preset>(base: BeaconState<P>, delta: BeaconStateDelta<P>) -> BeaconState<P> {
    let genesis_time = delta.genesis_time;
    let genesis_validators_root = delta.genesis_validators_root;
    let fork = delta.fork;
    let slot = delta.slot;

    let latest_block_header = delta.latest_block_header;
    let block_roots = apply_roots_delta::<P>(base.slot, base.block_roots, &delta.block_roots);
    let state_roots = apply_roots_delta::<P>(base.slot, base.state_roots, &delta.state_roots);

    let historical_roots = match delta.historical_roots {
        Some(historical_roots) => historical_roots,
        None => base.historical_roots,
    };

    let eth1_data = delta.eth1_data;
    let eth1_data_votes = delta.eth1_data_votes;
    let eth1_deposit_index = delta.eth1_deposit_index;

    let validators = apply_validators_delta::<P>(base.validators, delta.validators);
    let balances = apply_balances_delta::<P>(base.balances, delta.balances);

    let randao_mixes = apply_randao::<P>(base.randao_mixes, &delta.randao_mixes);

    let slashings = apply_slashings::<P>(base.slashings, delta.slashings);

    let previous_epoch_attestations = delta.previous_epoch_attestations;
    let current_epoch_attestations = delta.current_epoch_attestations;

    let justification_bits = match delta.justification_bits {
        Some(justification_bits) => justification_bits,
        None => base.justification_bits,
    };

    let previous_justified_checkpoint = delta.previous_justified_checkpoint;
    let current_justified_checkpoint = delta.current_justified_checkpoint;
    let finalized_checkpoint = delta.finalized_checkpoint;

    let cache = delta.cache;

    BeaconState {
        genesis_time,
        genesis_validators_root,
        slot,
        fork,
        latest_block_header,
        block_roots,
        state_roots,
        historical_roots,
        eth1_data,
        eth1_data_votes,
        eth1_deposit_index,
        validators,
        balances,
        randao_mixes,
        slashings,
        previous_epoch_attestations,
        current_epoch_attestations,
        justification_bits,
        previous_justified_checkpoint,
        current_justified_checkpoint,
        finalized_checkpoint,
        cache,
    }
}

pub(super) fn roots_delta<P: Preset>(
    base_slot: Slot,
    target_slot: Slot,
    target_roots: &RecentRoots<P>,
) -> Vec<H256> {
    let inputs = target_slot - base_slot;

    let roots: Vec<_> = (0..inputs)
        .map(|i| *target_roots.mod_index(base_slot + i))
        .collect();

    roots
}

pub(super) fn apply_roots_delta<P: Preset>(
    base_slot: Slot,
    mut base_roots: RecentRoots<P>,
    delta: &[H256],
) -> RecentRoots<P> {
    for (i, change) in delta.iter().enumerate() {
        *base_roots.mod_index_mut((base_slot + i as u64) % SlotsPerHistoricalRoot::<P>::U64) =
            *change;
    }

    base_roots
}

pub(super) fn validators_delta<P: Preset>(
    base_validators: &Validators<P>,
    target_validators: &Validators<P>,
) -> ValidatorsChange {
    let base_len = base_validators.len_usize();

    let new_validators = target_validators
        .into_iter()
        .skip(base_len)
        .cloned()
        .collect();

    let mut modified_validators = vec![];
    for (i, (v1, v2)) in base_validators
        .into_iter()
        .zip(target_validators.into_iter())
        .enumerate()
    {
        if v1 != v2 {
            let changes = ValidatorFieldChanges {
                withdrawal_credentials: (v1.withdrawal_credentials != v2.withdrawal_credentials)
                    .then_some(v2.withdrawal_credentials),

                effective_balance: (v1.effective_balance != v2.effective_balance)
                    .then_some(v2.effective_balance),

                slashed: (v1.slashed != v2.slashed).then_some(v2.slashed),

                activation_eligibility_epoch: (v1.activation_eligibility_epoch
                    != v2.activation_eligibility_epoch)
                    .then_some(v2.activation_eligibility_epoch),

                activation_epoch: (v1.activation_epoch != v2.activation_epoch)
                    .then_some(v2.activation_epoch),

                exit_epoch: (v1.exit_epoch != v2.exit_epoch).then_some(v2.exit_epoch),

                withdrawable_epoch: (v1.withdrawable_epoch != v2.withdrawable_epoch)
                    .then_some(v2.withdrawable_epoch),
            };

            modified_validators.push((i as u64, changes));
        }
    }

    ValidatorsChange {
        new_validators,
        modified_validators,
    }
}

pub(super) fn apply_validators_delta<P: Preset>(
    mut base_validators: Validators<P>,
    vc: ValidatorsChange,
) -> Validators<P> {
    // Apply field changes to existing validators
    for (i, changes) in &vc.modified_validators {
        let validator = base_validators
            .get_mut(*i)
            .expect("Failed to get mut index in base_validators");

        if let Some(wc) = changes.withdrawal_credentials {
            validator.withdrawal_credentials = wc;
        }
        if let Some(eb) = changes.effective_balance {
            validator.effective_balance = eb;
        }
        if let Some(slashed) = changes.slashed {
            validator.slashed = slashed;
        }
        if let Some(aee) = changes.activation_eligibility_epoch {
            validator.activation_eligibility_epoch = aee;
        }
        if let Some(ae) = changes.activation_epoch {
            validator.activation_epoch = ae;
        }
        if let Some(ee) = changes.exit_epoch {
            validator.exit_epoch = ee;
        }
        if let Some(we) = changes.withdrawable_epoch {
            validator.withdrawable_epoch = we;
        }
    }

    // Append new validators
    for validator in vc.new_validators {
        base_validators
            .push(validator)
            .expect("Failed to push to base_validators");
    }

    base_validators
}

pub(super) fn balances_delta<P: Preset>(
    base_balances: &Balances<P>,
    target_balances: &Balances<P>,
) -> BalanceDiffs {
    let base_len = base_balances.len_usize();

    let new_balances: Vec<Gwei> = target_balances
        .into_iter()
        .skip(base_len)
        .copied()
        .collect();

    let mut tags = BitTagVec::new(base_len);
    let mut small_diffs = Vec::new();
    let mut target_values = Vec::new();
    for (i, (&v1, &v2)) in base_balances
        .into_iter()
        .zip(target_balances.into_iter())
        .enumerate()
    {
        if v1 == v2 {
            // Tag stays 0b00 for same value
            continue;
        }

        if v2 == 0 {
            tags.set(i, SET_TO_ZERO);
        } else if v1 == 0 {
            tags.set(i, SET_TO_TARGET_VALUE);
            target_values.push(v2);
        } else {
            // v1 != v2 and both are non-zero
            let diff = i64::try_from(v2).expect("v2 exceeds i64::MAX")
                - i64::try_from(v1).expect("v1 exceeds i64::MAX");

            if i32::try_from(diff).is_ok() {
                tags.set(i, SET_TO_DIFF);
                small_diffs.push(i32::try_from(diff).expect("Exceeds i32"));
            } else {
                tags.set(i, SET_TO_TARGET_VALUE);
                target_values.push(v2);
            }
        }
    }

    BalanceDiffs {
        tags,
        small_diffs,
        target_values,
        new_balances,
    }
}

pub(super) fn apply_balances_delta<P: Preset>(
    mut base_balances: Balances<P>,
    bd: BalanceDiffs,
) -> Balances<P> {
    let len1 = base_balances.len_usize();
    let mut small_diff_idx = 0;
    let mut target_val_idx = 0;

    for i in 0..len1 {
        let tag = bd.tags.get(i);
        match tag {
            SET_NO_CHANGE => {}
            SET_TO_TARGET_VALUE => {
                let new_val = bd.target_values[target_val_idx];
                *base_balances
                    .get_mut(i as u64)
                    .expect("Failed to get mut value at index for base_balances") = new_val;
                target_val_idx += 1;
            }
            SET_TO_ZERO => {
                *base_balances
                    .get_mut(i as u64)
                    .expect("Failed to get mut value at index for base_balances") = 0;
            }
            SET_TO_DIFF => {
                let initial = i64::try_from(
                    *base_balances
                        .get(i as u64)
                        .expect("Failed to get mut value at index for base_balances"),
                )
                .expect("balance exceeds i64::MAX");

                let diff = i64::from(bd.small_diffs[small_diff_idx]);
                *base_balances
                    .get_mut(i as u64)
                    .expect("Failed to get mut value at index for base_balances") =
                    u64::try_from(initial + diff)
                        .expect("balance calculation resulted in negative or overflow");

                small_diff_idx += 1;
            }
            _ => unreachable!("processed as two bits"),
        }
    }

    for balance in bd.new_balances {
        base_balances
            .push(balance)
            .expect("Failed to push to base_balances");
    }

    base_balances
}

pub(super) fn randao_delta<P: Preset>(
    base_slot: Slot,
    target_slot: Slot,
    target_randao: &RandaoMixes<P>,
) -> RandaoChange {
    let modulus = P::EpochsPerHistoricalVector::U64;

    let base_epoch = base_slot / P::SlotsPerEpoch::U64;
    let target_epoch = target_slot / P::SlotsPerEpoch::U64;

    let num_epochs_changed = target_epoch - base_epoch + 1;

    let start_idx = base_epoch % modulus;

    let new_mixes: Vec<_> = (0..num_epochs_changed)
        .map(|offset| *target_randao.mod_index(start_idx + offset))
        .collect();

    RandaoChange {
        start_idx,
        new_mixes,
    }
}

pub(super) fn apply_randao<P: Preset>(
    mut base_randao_mixes: RandaoMixes<P>,
    randao_changes: &RandaoChange,
) -> RandaoMixes<P> {
    for (i, change) in randao_changes.new_mixes.iter().enumerate() {
        *base_randao_mixes.mod_index_mut(randao_changes.start_idx + i as u64) = *change;
    }

    base_randao_mixes
}

pub(super) fn slashings_delta<P: Preset>(
    base_slot: Slot,
    base_slashings: &Slashings<P>,
    target_slot: Slot,
    target_slashings: &Slashings<P>,
) -> Option<Vec<SlashingChange>> {
    if base_slashings == target_slashings {
        return None;
    }

    let modulus = P::EpochsPerSlashingsVector::U64;

    let base_epoch = base_slot / P::SlotsPerEpoch::U64;
    let target_epoch = target_slot / P::SlotsPerEpoch::U64;

    let num_epochs_changed = target_epoch - base_epoch;

    let start_epoch = base_epoch + 1;
    let start_idx = start_epoch % modulus;

    let slashing_changes: Vec<_> = (0..num_epochs_changed)
        .filter_map(|offset| {
            let idx = (start_idx + offset) % modulus;
            let base_val = base_slashings.mod_index(idx);
            let target_val = target_slashings.mod_index(idx);

            if base_val == target_val {
                None
            } else {
                Some(SlashingChange {
                    index: idx,
                    new_slashing: *target_val,
                })
            }
        })
        .collect();

    if slashing_changes.is_empty() {
        None
    } else {
        Some(slashing_changes)
    }
}

pub(super) fn apply_slashings<P: Preset>(
    mut base_slashings: Slashings<P>,
    slashing_changes: Option<Vec<SlashingChange>>,
) -> Slashings<P> {
    match slashing_changes {
        Some(slashing_changes) => {
            for change in &slashing_changes {
                *base_slashings.mod_index_mut(change.index) = change.new_slashing;
            }

            base_slashings
        }
        None => base_slashings,
    }
}
