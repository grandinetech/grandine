use std::sync::Arc;

use eth_state_diff::{ArchivedBeaconStateDelta, DiffSource, DiffTarget, ForkName};
use ssz::{SszRead, SszSize, SszWrite};
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;
use types::{
    ProposerLookahead,
    combined::BeaconState,
    config::Config,
    nonstandard::PubkeyList,
    phase0::{containers::Validator, validator_list::ValidatorList},
    preset::{Mainnet, Preset},
    traits::SszValidatorList as _,
};

use super::DiffEngine;

type ValidatorRegistryLimit = <Mainnet as Preset>::ValidatorRegistryLimit;
type FuluState = types::fulu::beacon_state::BeaconState<Mainnet>;

pub struct EthStateDiff;

#[derive(Clone)]
pub struct EthState {
    slot: u64,
    capella_fork_slot: u64,
    scalar_header: Vec<u8>,
    balances: Vec<u64>,
    validators: Vec<u8>,
    block_roots: Vec<[u8; 32]>,
    state_roots: Vec<[u8; 32]>,
    randao_mixes: Vec<[u8; 32]>,
    slashings: Vec<u64>,
    eth1_data_votes: Vec<u8>,
    // Grandine retains this legacy field in post-Capella states, but
    // eth-state-diff correctly treats it as removed from the fork layout.
    historical_roots: Vec<u8>,
    previous_participation: Vec<u8>,
    current_participation: Vec<u8>,
    inactivity_scores: Vec<u64>,
    current_sync_committee: Vec<u8>,
    next_sync_committee: Vec<u8>,
    historical_summaries: Vec<u8>,
    pending_deposits: Vec<u8>,
    pending_partial_withdrawals: Vec<u8>,
    pending_consolidations: Vec<u8>,
    // Public keys are immutable and shared between Grandine states. The flat
    // validator buffer still carries appended keys for the diff.
    pubkeys: PubkeyList,
}

#[expect(
    clippy::fallible_impl_from,
    reason = "the adapter only models the Fulu state layout; other phases are a benchmark \
              configuration error"
)]
impl From<Arc<BeaconState<Mainnet>>> for EthState {
    fn from(state: Arc<BeaconState<Mainnet>>) -> Self {
        let state = state.as_ref();
        let BeaconState::Fulu(state) = state else {
            panic!("eth-state-diff benchmark currently supports Fulu states only");
        };

        let config = Config::mainnet();
        let capella_fork_slot = config
            .capella_fork_epoch
            .saturating_mul(<Mainnet as Preset>::SlotsPerEpoch::U64);

        Self {
            slot: state.slot,
            capella_fork_slot,
            scalar_header: serialize_scalar_header(state),
            balances: state.balances.into_iter().copied().collect(),
            validators: serialize(&state.validators),
            block_roots: state.block_roots.into_iter().map(|root| root.0).collect(),
            state_roots: state.state_roots.into_iter().map(|root| root.0).collect(),
            randao_mixes: state.randao_mixes.into_iter().map(|root| root.0).collect(),
            slashings: state.slashings.into_iter().copied().collect(),
            eth1_data_votes: serialize(&state.eth1_data_votes),
            historical_roots: serialize(&state.historical_roots),
            previous_participation: serialize(&state.previous_epoch_participation),
            current_participation: serialize(&state.current_epoch_participation),
            inactivity_scores: state.inactivity_scores.into_iter().copied().collect(),
            current_sync_committee: serialize(&state.current_sync_committee),
            next_sync_committee: serialize(&state.next_sync_committee),
            historical_summaries: serialize(&state.historical_summaries),
            pending_deposits: serialize(&state.pending_deposits),
            pending_partial_withdrawals: serialize(&state.pending_partial_withdrawals),
            pending_consolidations: serialize(&state.pending_consolidations),
            pubkeys: state.validators.pubkeys().clone(),
        }
    }
}

impl From<EthState> for Arc<BeaconState<Mainnet>> {
    fn from(data: EthState) -> Self {
        restore_fulu(data)
    }
}

impl EthState {
    fn update_slot(&mut self) {
        self.slot = u64::from_le_bytes(
            self.scalar_header[40..48]
                .try_into()
                .expect("slot must be eight bytes"),
        );
    }
}

fn serialize_scalar_header(state: &FuluState) -> Vec<u8> {
    let mut bytes = Vec::new();

    append_ssz(&mut bytes, &state.genesis_time);
    append_ssz(&mut bytes, &state.genesis_validators_root);
    append_ssz(&mut bytes, &state.slot);
    append_ssz(&mut bytes, &state.fork);
    append_ssz(&mut bytes, &state.latest_block_header);
    append_ssz(&mut bytes, &state.eth1_data);
    append_ssz(&mut bytes, &state.eth1_deposit_index);
    append_ssz(&mut bytes, &state.justification_bits);
    append_ssz(&mut bytes, &state.previous_justified_checkpoint);
    append_ssz(&mut bytes, &state.current_justified_checkpoint);
    append_ssz(&mut bytes, &state.finalized_checkpoint);
    append_ssz(&mut bytes, &state.latest_execution_payload_header);
    append_ssz(&mut bytes, &state.next_withdrawal_index);
    append_ssz(&mut bytes, &state.next_withdrawal_validator_index);
    append_ssz(&mut bytes, &state.deposit_requests_start_index);
    append_ssz(&mut bytes, &state.deposit_balance_to_consume);
    append_ssz(&mut bytes, &state.exit_balance_to_consume);
    append_ssz(&mut bytes, &state.earliest_exit_epoch);
    append_ssz(&mut bytes, &state.consolidation_balance_to_consume);
    append_ssz(&mut bytes, &state.earliest_consolidation_epoch);
    append_ssz(&mut bytes, &state.proposer_lookahead);

    bytes
}

fn append_ssz<T: SszWrite>(bytes: &mut Vec<u8>, value: &T) {
    bytes.extend_from_slice(&serialize(value));
}

fn serialize<T: SszWrite>(value: &T) -> Vec<u8> {
    value.to_ssz().expect("should serialize")
}

struct EthDiffSource<'a> {
    base: &'a EthState,
    changed: &'a EthState,
}

impl DiffSource for EthDiffSource<'_> {
    fn fork(&self) -> ForkName {
        ForkName::Fulu
    }

    fn slot(&self) -> (u64, u64) {
        (self.base.slot, self.changed.slot)
    }

    fn capella_fork_slot(&self) -> u64 {
        self.changed.capella_fork_slot
    }

    fn scalar_header(&self) -> Vec<u8> {
        self.changed.scalar_header.clone()
    }

    fn balances(&self) -> (&[u64], &[u64]) {
        (&self.base.balances, &self.changed.balances)
    }

    fn validators(&self) -> (&[u8], &[u8]) {
        (&self.base.validators, &self.changed.validators)
    }

    fn block_roots(&self) -> &[[u8; 32]] {
        &self.changed.block_roots
    }

    fn state_roots(&self) -> &[[u8; 32]] {
        &self.changed.state_roots
    }

    fn randao_mixes(&self) -> &[[u8; 32]] {
        &self.changed.randao_mixes
    }

    fn slashings(&self) -> (&[u64], &[u64]) {
        (&self.base.slashings, &self.changed.slashings)
    }

    fn eth1_data_votes(&self) -> (&[u8], &[u8]) {
        (&self.base.eth1_data_votes, &self.changed.eth1_data_votes)
    }

    fn historical_roots(&self) -> Option<&[u8]> {
        None
    }

    fn previous_epoch_attestations(&self) -> Option<(&[u8], &[u8])> {
        None
    }

    fn current_epoch_attestations(&self) -> Option<(&[u8], &[u8])> {
        None
    }

    fn previous_participation(&self) -> Option<(&[u8], &[u8])> {
        Some((
            &self.base.previous_participation,
            &self.changed.previous_participation,
        ))
    }

    fn current_participation(&self) -> Option<(&[u8], &[u8])> {
        Some((
            &self.base.current_participation,
            &self.changed.current_participation,
        ))
    }

    fn inactivity_scores(&self) -> Option<(&[u64], &[u64])> {
        Some((
            &self.base.inactivity_scores,
            &self.changed.inactivity_scores,
        ))
    }

    fn current_sync_committee(&self) -> Option<(&[u8], &[u8])> {
        Some((
            &self.base.current_sync_committee,
            &self.changed.current_sync_committee,
        ))
    }

    fn next_sync_committee(&self) -> Option<(&[u8], &[u8])> {
        Some((
            &self.base.next_sync_committee,
            &self.changed.next_sync_committee,
        ))
    }

    fn historical_summaries(&self) -> Option<&[u8]> {
        Some(&self.changed.historical_summaries)
    }

    fn pending_deposits(&self) -> Option<(&[u8], &[u8])> {
        Some((&self.base.pending_deposits, &self.changed.pending_deposits))
    }

    fn pending_partial_withdrawals(&self) -> Option<(&[u8], &[u8])> {
        Some((
            &self.base.pending_partial_withdrawals,
            &self.changed.pending_partial_withdrawals,
        ))
    }

    fn pending_consolidations(&self) -> Option<(&[u8], &[u8])> {
        Some((
            &self.base.pending_consolidations,
            &self.changed.pending_consolidations,
        ))
    }
}

impl DiffTarget for EthState {
    fn get_fork(&self) -> ForkName {
        ForkName::Fulu
    }

    fn scalar_header_mut(&mut self) -> &mut Vec<u8> {
        &mut self.scalar_header
    }

    fn balances_mut(&mut self) -> &mut Vec<u64> {
        &mut self.balances
    }

    fn validators_mut(&mut self) -> &mut Vec<u8> {
        &mut self.validators
    }

    fn block_roots_mut(&mut self) -> &mut [[u8; 32]] {
        &mut self.block_roots
    }

    fn state_roots_mut(&mut self) -> &mut [[u8; 32]] {
        &mut self.state_roots
    }

    fn randao_mixes_mut(&mut self) -> &mut [[u8; 32]] {
        &mut self.randao_mixes
    }

    fn slashings_mut(&mut self) -> &mut [u64] {
        &mut self.slashings
    }

    fn eth1_data_votes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.eth1_data_votes
    }

    fn historical_roots_mut(&mut self) -> Option<&mut Vec<u8>> {
        None
    }

    fn previous_epoch_attestations_mut(&mut self) -> Option<&mut Vec<u8>> {
        None
    }

    fn current_epoch_attestations_mut(&mut self) -> Option<&mut Vec<u8>> {
        None
    }

    fn previous_participation_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.previous_participation)
    }

    fn current_participation_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.current_participation)
    }

    fn inactivity_scores_mut(&mut self) -> Option<&mut Vec<u64>> {
        Some(&mut self.inactivity_scores)
    }

    fn current_sync_committee_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.current_sync_committee)
    }

    fn next_sync_committee_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.next_sync_committee)
    }

    fn historical_summaries_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.historical_summaries)
    }

    fn pending_deposits_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.pending_deposits)
    }

    fn pending_partial_withdrawals_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.pending_partial_withdrawals)
    }

    fn pending_consolidations_mut(&mut self) -> Option<&mut Vec<u8>> {
        Some(&mut self.pending_consolidations)
    }
}

fn restore_fulu(data: EthState) -> Arc<BeaconState<Mainnet>> {
    let config = Config::mainnet();
    let mut state = FuluState::default();

    restore_fulu_scalar_header(&mut state, &data.scalar_header, &config);

    state.block_roots = read_ssz(&config, roots_to_bytes(&data.block_roots), "block roots");
    state.state_roots = read_ssz(&config, roots_to_bytes(&data.state_roots), "state roots");
    state.historical_roots = read_ssz(&config, data.historical_roots, "historical roots");
    state.validators = restore_validators(&data.validators, data.pubkeys, &config);
    state.balances = read_ssz(&config, u64s_to_bytes(&data.balances), "balances");
    state.randao_mixes = read_ssz(&config, roots_to_bytes(&data.randao_mixes), "randao mixes");
    state.slashings = read_ssz(&config, u64s_to_bytes(&data.slashings), "slashings");
    state.eth1_data_votes = read_ssz(&config, data.eth1_data_votes, "eth1 data votes");
    state.previous_epoch_participation = read_ssz(
        &config,
        data.previous_participation,
        "previous participation",
    );
    state.current_epoch_participation =
        read_ssz(&config, data.current_participation, "current participation");
    state.inactivity_scores = read_ssz(
        &config,
        u64s_to_bytes(&data.inactivity_scores),
        "inactivity scores",
    );
    state.current_sync_committee = read_ssz(
        &config,
        data.current_sync_committee,
        "current sync committee",
    );
    state.next_sync_committee = read_ssz(&config, data.next_sync_committee, "next sync committee");
    state.historical_summaries =
        read_ssz(&config, data.historical_summaries, "historical summaries");
    state.pending_deposits = read_ssz(&config, data.pending_deposits, "pending deposits");
    state.pending_partial_withdrawals = read_ssz(
        &config,
        data.pending_partial_withdrawals,
        "pending partial withdrawals",
    );
    state.pending_consolidations = read_ssz(
        &config,
        data.pending_consolidations,
        "pending consolidations",
    );

    Arc::new(BeaconState::from(state))
}

fn read_ssz<T: SszRead<Config>>(config: &Config, bytes: impl AsRef<[u8]>, field: &str) -> T {
    T::from_ssz(config, bytes).unwrap_or_else(|error| panic!("should restore {field}: {error}"))
}

/// Restores the validator registry, inheriting public keys from the base state.
///
/// Public keys are append-only, so the base state's list already covers every
/// validator a delta did not add. Reusing the list also reuses its public key
/// -> index map instead of rebuilding it from `bytes` during every restore.
#[expect(
    clippy::default_trait_access,
    reason = "`bls` is not a dependency of this crate, so `PublicKeyBytes` cannot be named"
)]
fn restore_validators(
    bytes: &[u8],
    mut pubkeys: PubkeyList,
    config: &Config,
) -> ValidatorList<ValidatorRegistryLimit> {
    let size = Validator::SIZE.get();
    assert_eq!(
        bytes.len().checked_rem(size),
        Some(0),
        "validator bytes should contain complete validators",
    );
    let base_validator_count = pubkeys.iter().len();

    // Validators appended by the delta are not in the base's list yet.
    pubkeys.extend(
        bytes
            .chunks_exact(size)
            .skip(base_validator_count)
            .map(|chunk| read_validator(config, chunk).pubkey),
    );

    // The registry is built with public keys left zeroed. Indexing them here is
    // exactly the work `set_pubkeys` makes unnecessary.
    let mut validators = ValidatorList::try_from_iter(bytes.chunks_exact(size).map(|chunk| {
        let mut validator = read_validator(config, chunk);
        validator.pubkey = Default::default();
        validator
    }))
    .expect("should restore validators");

    validators
        .set_pubkeys(&pubkeys)
        .expect("public key list should cover every restored validator");

    validators
}

fn read_validator(config: &Config, bytes: &[u8]) -> Validator {
    read_ssz(config, bytes, "validator")
}

fn restore_fulu_scalar_header(state: &mut FuluState, header: &[u8], config: &Config) {
    let mut offset = 0;

    state.genesis_time = read_fixed(config, header, &mut offset);
    state.genesis_validators_root = read_fixed(config, header, &mut offset);
    state.slot = read_fixed(config, header, &mut offset);
    state.fork = read_fixed(config, header, &mut offset);
    state.latest_block_header = read_fixed(config, header, &mut offset);
    state.eth1_data = read_fixed(config, header, &mut offset);
    state.eth1_deposit_index = read_fixed(config, header, &mut offset);
    state.justification_bits = read_fixed(config, header, &mut offset);
    state.previous_justified_checkpoint = read_fixed(config, header, &mut offset);
    state.current_justified_checkpoint = read_fixed(config, header, &mut offset);
    state.finalized_checkpoint = read_fixed(config, header, &mut offset);

    let trailing_size = <u64 as SszSize>::SIZE
        .get()
        .saturating_mul(8)
        .saturating_add(ProposerLookahead::<Mainnet>::SIZE.get());
    let execution_header_end = header
        .len()
        .checked_sub(trailing_size)
        .expect("Fulu scalar header should contain all trailing fields");
    state.latest_execution_payload_header = read_ssz(
        config,
        &header[offset..execution_header_end],
        "execution payload header",
    );
    offset = execution_header_end;

    state.next_withdrawal_index = read_fixed(config, header, &mut offset);
    state.next_withdrawal_validator_index = read_fixed(config, header, &mut offset);
    state.deposit_requests_start_index = read_fixed(config, header, &mut offset);
    state.deposit_balance_to_consume = read_fixed(config, header, &mut offset);
    state.exit_balance_to_consume = read_fixed(config, header, &mut offset);
    state.earliest_exit_epoch = read_fixed(config, header, &mut offset);
    state.consolidation_balance_to_consume = read_fixed(config, header, &mut offset);
    state.earliest_consolidation_epoch = read_fixed(config, header, &mut offset);
    state.proposer_lookahead = read_fixed(config, header, &mut offset);

    assert_eq!(
        offset,
        header.len(),
        "scalar header should be fully consumed"
    );
}

fn read_fixed<T: SszRead<Config> + SszSize>(
    config: &Config,
    bytes: &[u8],
    offset: &mut usize,
) -> T {
    let end = offset
        .checked_add(T::SIZE.get())
        .expect("SSZ field offset should not overflow");
    let field = bytes
        .get(*offset..end)
        .expect("scalar header should contain the complete SSZ field");
    *offset = end;
    read_ssz(config, field, "scalar field")
}

fn roots_to_bytes(roots: &[[u8; 32]]) -> Vec<u8> {
    roots.iter().flatten().copied().collect()
}

fn u64s_to_bytes(values: &[u64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

impl DiffEngine for EthStateDiff {
    type Prepared = EthState;
    type Patch = Vec<u8>;

    fn prepare(&self, state: Arc<BeaconState<Mainnet>>) -> Self::Prepared {
        state.into()
    }

    fn restore(&self, prepared: Self::Prepared) -> Arc<BeaconState<Mainnet>> {
        prepared.into()
    }

    fn diff(&self, base: &Self::Prepared, changed: &Self::Prepared) -> Self::Patch {
        let source = EthDiffSource { base, changed };
        let delta = eth_state_diff::create(&source);
        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&delta)
            .expect("should serialize eth-state-diff delta");

        zstd::encode_all(serialized.as_slice(), zstd::DEFAULT_COMPRESSION_LEVEL)
            .expect("should compress eth-state-diff delta")
    }

    fn apply(&self, base: Self::Prepared, patch: Self::Patch) -> Self::Prepared {
        let decompressed =
            zstd::decode_all(patch.as_slice()).expect("should decompress eth-state-diff delta");
        let delta =
            rkyv::access::<ArchivedBeaconStateDelta, rkyv::rancor::Error>(decompressed.as_slice())
                .expect("should access eth-state-diff delta");
        let mut base =
            eth_state_diff::apply(base, delta).expect("eth-state-diff delta should apply");
        base.update_slot();
        base
    }
}
