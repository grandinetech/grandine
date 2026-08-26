use ssz::{BitVector, Ssz};
use types::{
    capella::containers::Withdrawal,
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        containers::{BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid},
        primitives::BuilderIndex,
    },
    phase0::primitives::ExecutionBlockHash,
    preset::{Preset, SlotsPerHistoricalRoot},
    traits::PostGloasBeaconState,
};

use crate::{
    beacon_state::{
        altair::AltairPatch, capella::CapellaPatch, electra::ElectraPatch, fulu::FuluPatch,
        phase0::Phase0Patch,
    },
    compress::Compressed,
    error::Error,
    list::{BuilderListPatch, PositionalPatch, PtcPatch, QueuePatch, VectorPatch},
    patch::{Patch, PatchConfig},
    replace::ReplacePatch,
};

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct GloasStatePatchV1<P: Preset> {
    phase0: Phase0Patch<P>,
    altair: AltairPatch<P>,
    capella: CapellaPatch<P>,
    electra: ElectraPatch<P>,
    fulu: FuluPatch<P>,
    gloas: GloasPatch<P>,
}

impl<P: Preset> Patch<GloasBeaconState<P>> for GloasStatePatchV1<P> {
    fn diff(
        config: PatchConfig,
        base: &GloasBeaconState<P>,
        changed: &GloasBeaconState<P>,
    ) -> Result<Self, Error> {
        Ok(Self {
            phase0: Patch::diff(config, base, changed)?,
            altair: Patch::diff(config, base, changed)?,
            capella: Patch::diff(config, base, changed)?,
            electra: Patch::diff(config, base, changed)?,
            fulu: Patch::diff(config, base, changed)?,
            gloas: Patch::diff(config, base, changed)?,
        })
    }

    fn apply(self, base: &mut GloasBeaconState<P>) -> Result<(), Error> {
        self.phase0.apply(base)?;
        self.altair.apply(base)?;
        self.capella.apply(base)?;
        self.electra.apply(base)?;
        self.fulu.apply(base)?;

        self.gloas.apply(base)
    }
}

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct GloasPatch<P: Preset> {
    latest_block_hash: ReplacePatch<ExecutionBlockHash>,
    builders: Compressed<BuilderListPatch>,
    next_withdrawal_builder_index: ReplacePatch<BuilderIndex>,
    execution_payload_availability: ReplacePatch<Compressed<BitVector<SlotsPerHistoricalRoot<P>>>>,
    builder_pending_payments: Compressed<VectorPatch<BuilderPendingPayment>>,
    builder_pending_withdrawals: Compressed<QueuePatch<BuilderPendingWithdrawal>>,
    latest_execution_payload_bid: ReplacePatch<ExecutionPayloadBid<P>>,
    payload_expected_withdrawals: Compressed<PositionalPatch<Withdrawal>>,
    ptc_window: Compressed<PtcPatch<P>>,
}

impl<P: Preset, S: PostGloasBeaconState<P>> Patch<S> for GloasPatch<P> {
    fn diff(config: PatchConfig, base: &S, changed: &S) -> Result<Self, Error> {
        Ok(Self {
            latest_block_hash: Patch::diff(
                config,
                &base.latest_block_hash(),
                &changed.latest_block_hash(),
            )?,
            builders: Patch::diff(config, base.builders(), changed.builders())?,
            next_withdrawal_builder_index: Patch::diff(
                config,
                &base.next_withdrawal_builder_index(),
                &changed.next_withdrawal_builder_index(),
            )?,
            execution_payload_availability: Patch::diff(
                config,
                &base.execution_payload_availability(),
                &changed.execution_payload_availability(),
            )?,
            builder_pending_payments: Patch::diff(
                config,
                base.builder_pending_payments(),
                changed.builder_pending_payments(),
            )?,
            builder_pending_withdrawals: Patch::diff(
                config,
                base.builder_pending_withdrawals(),
                changed.builder_pending_withdrawals(),
            )?,
            latest_execution_payload_bid: Patch::diff(
                config,
                base.latest_execution_payload_bid(),
                changed.latest_execution_payload_bid(),
            )?,
            payload_expected_withdrawals: Patch::diff(
                config,
                base.payload_expected_withdrawals(),
                changed.payload_expected_withdrawals(),
            )?,
            ptc_window: Patch::diff(config, base.ptc_window(), changed.ptc_window())?,
        })
    }

    fn apply(self, base: &mut S) -> Result<(), Error> {
        self.latest_block_hash.apply(base.latest_block_hash_mut())?;
        self.builders.apply(base.builders_mut())?;
        self.next_withdrawal_builder_index
            .apply(base.next_withdrawal_builder_index_mut())?;
        self.execution_payload_availability
            .apply(base.execution_payload_availability_mut())?;
        self.builder_pending_payments
            .apply(base.builder_pending_payments_mut())?;
        self.builder_pending_withdrawals
            .apply(base.builder_pending_withdrawals_mut())?;
        self.latest_execution_payload_bid
            .apply(base.latest_execution_payload_bid_mut())?;
        self.payload_expected_withdrawals
            .apply(base.payload_expected_withdrawals_mut())?;
        self.ptc_window.apply(base.ptc_window_mut())
    }
}

#[cfg(test)]
mod tests {
    use ssz::{H256, SszHash as _, SszListMut as _, SszRead as _, SszWrite as _};
    use types::{
        capella::containers::HistoricalSummary, config::Config,
        electra::containers::PendingDeposit, gloas::containers::Builder, preset::Minimal,
    };

    use super::*;

    #[test]
    fn diff_and_apply_round_trip() {
        let base = GloasBeaconState::<Minimal>::default();
        let mut changed = base.clone();

        changed.slot = 42;
        changed
            .balances
            .extend(&mut [32_000_000_000, 31_000_000_000].into_iter())
            .expect("list is not full");
        changed
            .previous_epoch_participation
            .extend(&mut [1, 2].into_iter())
            .expect("list is not full");
        changed
            .inactivity_scores
            .extend(&mut [7, 8].into_iter())
            .expect("list is not full");
        changed
            .historical_summaries
            .push(HistoricalSummary {
                block_summary_root: H256::repeat_byte(2),
                state_summary_root: H256::repeat_byte(3),
            })
            .expect("list is not full");
        changed
            .pending_deposits
            .push(PendingDeposit::default())
            .expect("list is not full");
        *changed
            .proposer_lookahead
            .get_mut(0)
            .expect("index is within bounds") = 3;

        changed.latest_block_hash = ExecutionBlockHash::repeat_byte(1);
        changed
            .builders
            .push(Builder::default())
            .expect("list is not full");
        changed.next_withdrawal_builder_index = 5;
        changed.execution_payload_availability.set(1, true);
        *changed
            .builder_pending_payments
            .get_mut(0)
            .expect("index is within bounds") = BuilderPendingPayment {
            weight: 9,
            ..BuilderPendingPayment::default()
        };
        changed
            .builder_pending_withdrawals
            .push(BuilderPendingWithdrawal::default())
            .expect("list is not full");
        changed.latest_execution_payload_bid.value = 11;
        changed
            .payload_expected_withdrawals
            .push(Withdrawal::default())
            .expect("list is not full");
        changed
            .ptc_window
            .get_mut(0)
            .expect("index is within bounds")[0] = 13;

        let patch = GloasStatePatchV1::diff(PatchConfig::default(), &base, &changed)
            .expect("gloas patch should represent the change");

        let encoded = patch.to_ssz().expect("patch should serialize");
        let patch = GloasStatePatchV1::<Minimal>::from_ssz(&Config::minimal(), encoded)
            .expect("patch should deserialize");

        let mut applied = base;
        patch.apply(&mut applied).expect("patch should apply");

        assert_eq!(applied, changed);
        assert_eq!(applied.hash_tree_root(), changed.hash_tree_root());
    }
}
