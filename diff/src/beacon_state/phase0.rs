use core::marker::PhantomData;

use ssz::{BitVector, H256, Ssz};
use types::{
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::JustificationBitsLength,
        containers::{BeaconBlockHeader, Checkpoint, Eth1Data, PendingAttestation},
        primitives::{DepositIndex, Gwei, Slot},
    },
    preset::Preset,
    traits::BeaconState,
};

use crate::{
    compress::Compressed,
    error::Error,
    list::{BalancesPatch, PositionalPatch, ValidatorListPatch, VectorPatch},
    patch::{Patch, PatchConfig},
    replace::ReplacePatch,
};

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct Phase0StatePatchV1<P: Preset> {
    phase0: Phase0Patch<P>,

    previous_epoch_attestations: Compressed<PositionalPatch<PendingAttestation<P>>>,
    current_epoch_attestations: Compressed<PositionalPatch<PendingAttestation<P>>>,
}

impl<P: Preset> Patch<Phase0BeaconState<P>> for Phase0StatePatchV1<P> {
    fn diff(
        config: PatchConfig,
        base: &Phase0BeaconState<P>,
        changed: &Phase0BeaconState<P>,
    ) -> Result<Self, Error> {
        Ok(Self {
            phase0: Patch::diff(config, base, changed)?,
            previous_epoch_attestations: Patch::diff(
                config,
                &base.previous_epoch_attestations,
                &changed.previous_epoch_attestations,
            )?,
            current_epoch_attestations: Patch::diff(
                config,
                &base.current_epoch_attestations,
                &changed.current_epoch_attestations,
            )?,
        })
    }

    fn apply(self, base: &mut Phase0BeaconState<P>) -> Result<(), Error> {
        self.phase0.apply(base)?;
        self.previous_epoch_attestations
            .apply(&mut base.previous_epoch_attestations)?;
        self.current_epoch_attestations
            .apply(&mut base.current_epoch_attestations)
    }
}

#[derive(Debug, Clone, Ssz)]
#[ssz(derive_hash = false)]
pub struct Phase0Patch<P: Preset> {
    // TODO(new-db-layout): with new DB layout, this field probably can be
    // dropped, as it will be saved in key.
    slot: ReplacePatch<Slot>,

    // > History
    latest_block_header: ReplacePatch<BeaconBlockHeader>,
    block_roots: VectorPatch<H256>,
    state_roots: VectorPatch<H256>,
    historical_roots: PositionalPatch<H256>,

    // > Eth1
    eth1_data: ReplacePatch<Eth1Data>,
    eth1_data_votes: Compressed<PositionalPatch<Eth1Data>>,
    eth1_deposit_index: ReplacePatch<DepositIndex>,

    // > Registry
    validators: Compressed<ValidatorListPatch>,
    balances: Compressed<BalancesPatch>,

    // > Randomness
    randao_mixes: VectorPatch<H256>,

    // > Slashings
    slashings: VectorPatch<Gwei>,

    // > Finality
    justification_bits: ReplacePatch<BitVector<JustificationBitsLength>>,
    previous_justified_checkpoint: ReplacePatch<Checkpoint>,
    current_justified_checkpoint: ReplacePatch<Checkpoint>,
    finalized_checkpoint: ReplacePatch<Checkpoint>,

    #[ssz(skip)]
    phantom: PhantomData<P>,
}

impl<P: Preset, S: BeaconState<P>> Patch<S> for Phase0Patch<P> {
    fn diff(config: PatchConfig, base: &S, changed: &S) -> Result<Self, Error> {
        // These are not part of the patch: `genesis_time` and `genesis_validators_root` never
        // change, and `BeaconState` exposes no way to write `fork` back. The hierarchy is
        // phase-anchored, so a delta parent is always in the same phase and they always match.
        // Refuse rather than silently reconstruct a state with the wrong versioning fields.
        if base.genesis_time() != changed.genesis_time()
            || base.genesis_validators_root() != changed.genesis_validators_root()
            || base.fork() != changed.fork()
        {
            return Err(Error::UnsupportedDiff);
        }

        Ok(Self {
            slot: Patch::diff(config, &base.slot(), &changed.slot())?,
            latest_block_header: Patch::diff(
                config,
                &base.latest_block_header(),
                &changed.latest_block_header(),
            )?,
            block_roots: Patch::diff(config, base.block_roots(), changed.block_roots())?,
            state_roots: Patch::diff(config, base.state_roots(), changed.state_roots())?,
            historical_roots: Patch::diff(
                config,
                base.historical_roots(),
                changed.historical_roots(),
            )?,
            eth1_data: Patch::diff(config, &base.eth1_data(), &changed.eth1_data())?,
            eth1_data_votes: Patch::diff(
                config,
                base.eth1_data_votes(),
                changed.eth1_data_votes(),
            )?,
            eth1_deposit_index: Patch::diff(
                config,
                &base.eth1_deposit_index(),
                &changed.eth1_deposit_index(),
            )?,
            validators: Patch::diff(config, base.validators(), changed.validators())?,
            balances: Patch::diff(config, base.balances(), changed.balances())?,
            randao_mixes: Patch::diff(config, base.randao_mixes(), changed.randao_mixes())?,
            slashings: Patch::diff(config, base.slashings(), changed.slashings())?,
            justification_bits: Patch::diff(
                config,
                &base.justification_bits(),
                &changed.justification_bits(),
            )?,
            previous_justified_checkpoint: Patch::diff(
                config,
                &base.previous_justified_checkpoint(),
                &changed.previous_justified_checkpoint(),
            )?,
            current_justified_checkpoint: Patch::diff(
                config,
                &base.current_justified_checkpoint(),
                &changed.current_justified_checkpoint(),
            )?,
            finalized_checkpoint: Patch::diff(
                config,
                &base.finalized_checkpoint(),
                &changed.finalized_checkpoint(),
            )?,
            phantom: PhantomData,
        })
    }

    fn apply(self, base: &mut S) -> Result<(), Error> {
        self.slot.apply(base.slot_mut())?;
        self.latest_block_header
            .apply(base.latest_block_header_mut())?;
        self.block_roots.apply(base.block_roots_mut())?;
        self.state_roots.apply(base.state_roots_mut())?;
        self.historical_roots.apply(base.historical_roots_mut())?;
        self.eth1_data.apply(base.eth1_data_mut())?;
        self.eth1_data_votes.apply(base.eth1_data_votes_mut())?;
        self.eth1_deposit_index
            .apply(base.eth1_deposit_index_mut())?;
        self.validators.apply(base.validators_mut())?;
        self.balances.apply(base.balances_mut())?;
        self.randao_mixes.apply(base.randao_mixes_mut())?;
        self.slashings.apply(base.slashings_mut())?;
        self.justification_bits
            .apply(base.justification_bits_mut())?;
        self.previous_justified_checkpoint
            .apply(base.previous_justified_checkpoint_mut())?;
        self.current_justified_checkpoint
            .apply(base.current_justified_checkpoint_mut())?;
        self.finalized_checkpoint
            .apply(base.finalized_checkpoint_mut())?;

        Ok(())
    }
}
