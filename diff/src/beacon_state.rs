mod altair;
mod bellatrix;
mod capella;
mod deneb;
mod electra;
mod fulu;
mod gloas;
mod phase0;

use std::sync::Arc;

use ssz::{Hc, ReadError, Ssz, SszRead, SszSize, SszWrite, WriteError};
use types::{
    cache::Cache, combined::BeaconState as CombinedBeaconState, preset::Preset, traits::BeaconState,
};

use crate::{
    beacon_state::{
        altair::AltairStatePatchV1, bellatrix::BellatrixStatePatchV1, capella::CapellaStatePatchV1,
        deneb::DenebStatePatchV1, electra::ElectraStatePatchV1, fulu::FuluStatePatchV1,
        gloas::GloasStatePatchV1, phase0::Phase0StatePatchV1,
    },
    error::Error,
    patch::{Patch, PatchConfig},
};

#[derive(Clone, Debug, Ssz)]
#[ssz(derive_hash = false, transparent)]
pub struct BeaconStatePatch<P: Preset>(BeaconStatePatchInternal<P>);

impl<P: Preset> Patch<Arc<CombinedBeaconState<P>>> for BeaconStatePatch<P> {
    fn diff(
        config: PatchConfig,
        base: &Arc<CombinedBeaconState<P>>,
        changed: &Arc<CombinedBeaconState<P>>,
    ) -> Result<Self, Error> {
        Patch::diff(config, base, changed)
            .map(BeaconStatePatchInternal::V1)
            .map(Self)
    }

    fn apply(self, base: &mut Arc<CombinedBeaconState<P>>) -> Result<(), Error> {
        match self.0 {
            BeaconStatePatchInternal::V1(patch) => patch.apply(base),
        }
    }
}

#[derive(Clone, Debug)]
enum BeaconStatePatchInternal<P: Preset> {
    V1(BeaconStatePatchV1<P>),
}

impl<P: Preset> SszSize for BeaconStatePatchInternal<P> {
    const SIZE: ssz::Size = ssz::Size::Variable { minimum_size: 1 };
}

impl<P: Preset> SszWrite for BeaconStatePatchInternal<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::V1(patch) => {
                bytes.push(1);
                patch.write_variable(bytes)
            }
        }
    }
}

impl<P: Preset, C> SszRead<C> for BeaconStatePatchInternal<P> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (selector, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "beacon state patch is empty",
        })?;

        match selector {
            1 => SszRead::from_ssz(context, payload).map(Self::V1),
            _ => Err(ReadError::Custom {
                message: "unsupported beacon state patch selector",
            }),
        }
    }
}

#[derive(Clone, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "patches are short-lived objects, built and consumed one at a time, so the enum \
              variant difference gap is not worth an allocation"
)]
enum BeaconStatePatchV1<P: Preset> {
    Phase0(Phase0StatePatchV1<P>),
    Altair(AltairStatePatchV1<P>),
    Bellatrix(BellatrixStatePatchV1<P>),
    Capella(CapellaStatePatchV1<P>),
    Deneb(DenebStatePatchV1<P>),
    Electra(ElectraStatePatchV1<P>),
    Fulu(FuluStatePatchV1<P>),
    Gloas(GloasStatePatchV1<P>),
}

impl<P: Preset> SszSize for BeaconStatePatchV1<P> {
    const SIZE: ssz::Size = ssz::Size::Variable { minimum_size: 1 };
}

impl<P: Preset> SszWrite for BeaconStatePatchV1<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(patch) => {
                bytes.push(1);
                patch.write_variable(bytes)
            }
            Self::Altair(patch) => {
                bytes.push(2);
                patch.write_variable(bytes)
            }
            Self::Bellatrix(patch) => {
                bytes.push(3);
                patch.write_variable(bytes)
            }
            Self::Capella(patch) => {
                bytes.push(4);
                patch.write_variable(bytes)
            }
            Self::Deneb(patch) => {
                bytes.push(5);
                patch.write_variable(bytes)
            }
            Self::Electra(patch) => {
                bytes.push(6);
                patch.write_variable(bytes)
            }
            Self::Fulu(patch) => {
                bytes.push(7);
                patch.write_variable(bytes)
            }
            Self::Gloas(patch) => {
                bytes.push(8);
                patch.write_variable(bytes)
            }
        }
    }
}

impl<P: Preset, C> SszRead<C> for BeaconStatePatchV1<P> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        let (selector, payload) = bytes.split_first().ok_or(ReadError::Custom {
            message: "beacon state patch is empty",
        })?;

        match selector {
            1 => SszRead::from_ssz(context, payload).map(Self::Phase0),
            2 => SszRead::from_ssz(context, payload).map(Self::Altair),
            3 => SszRead::from_ssz(context, payload).map(Self::Bellatrix),
            4 => SszRead::from_ssz(context, payload).map(Self::Capella),
            5 => SszRead::from_ssz(context, payload).map(Self::Deneb),
            6 => SszRead::from_ssz(context, payload).map(Self::Electra),
            7 => SszRead::from_ssz(context, payload).map(Self::Fulu),
            8 => SszRead::from_ssz(context, payload).map(Self::Gloas),
            _ => Err(ReadError::Custom {
                message: "unsupported beacon state patch selector",
            }),
        }
    }
}

impl<P: Preset> Patch<Arc<CombinedBeaconState<P>>> for BeaconStatePatchV1<P> {
    fn diff(
        config: PatchConfig,
        base: &Arc<CombinedBeaconState<P>>,
        changed: &Arc<CombinedBeaconState<P>>,
    ) -> Result<Self, Error> {
        match (base.as_ref(), changed.as_ref()) {
            (CombinedBeaconState::Phase0(base), CombinedBeaconState::Phase0(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(BeaconStatePatchV1::Phase0)
            }
            (CombinedBeaconState::Altair(base), CombinedBeaconState::Altair(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(BeaconStatePatchV1::Altair)
            }
            (CombinedBeaconState::Bellatrix(base), CombinedBeaconState::Bellatrix(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref())
                    .map(BeaconStatePatchV1::Bellatrix)
            }
            (CombinedBeaconState::Capella(base), CombinedBeaconState::Capella(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref())
                    .map(BeaconStatePatchV1::Capella)
            }
            (CombinedBeaconState::Deneb(base), CombinedBeaconState::Deneb(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(BeaconStatePatchV1::Deneb)
            }
            (CombinedBeaconState::Electra(base), CombinedBeaconState::Electra(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref())
                    .map(BeaconStatePatchV1::Electra)
            }
            (CombinedBeaconState::Fulu(base), CombinedBeaconState::Fulu(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(BeaconStatePatchV1::Fulu)
            }
            (CombinedBeaconState::Gloas(base), CombinedBeaconState::Gloas(changed)) => {
                Patch::diff(config, base.as_ref(), changed.as_ref()).map(BeaconStatePatchV1::Gloas)
            }
            (_, _) => Err(Error::CrossPhaseDiff),
        }
    }

    fn apply(self, base: &mut Arc<CombinedBeaconState<P>>) -> Result<(), Error> {
        match (self, Arc::make_mut(base)) {
            (Self::Phase0(patch), CombinedBeaconState::Phase0(base)) => {
                patch.apply(reset_cache(base))
            }
            (Self::Altair(patch), CombinedBeaconState::Altair(base)) => {
                patch.apply(reset_cache(base))
            }
            (Self::Bellatrix(patch), CombinedBeaconState::Bellatrix(base)) => {
                patch.apply(reset_cache(base))
            }
            (Self::Capella(patch), CombinedBeaconState::Capella(base)) => {
                patch.apply(reset_cache(base))
            }
            (Self::Deneb(patch), CombinedBeaconState::Deneb(base)) => {
                patch.apply(reset_cache(base))
            }
            (Self::Electra(patch), CombinedBeaconState::Electra(base)) => {
                patch.apply(reset_cache(base))
            }
            (Self::Fulu(patch), CombinedBeaconState::Fulu(base)) => patch.apply(reset_cache(base)),
            (Self::Gloas(patch), CombinedBeaconState::Gloas(base)) => {
                patch.apply(reset_cache(base))
            }
            // Nothing is being diffed here: a stored patch is being applied to a base of another
            // phase, which means the chain it was read from is inconsistent.
            (_, _) => Err(Error::PatchPhaseMismatch),
        }
    }
}

fn reset_cache<P: Preset, S: BeaconState<P>>(state: &mut Hc<S>) -> &mut S {
    let state = state.as_mut();

    *state.cache_mut() = Cache::default();

    state
}

#[cfg(test)]
mod tests {
    use ssz::{H256, SszHash as _, SszRead as _, SszWrite as _};
    use std_ext::ArcExt as _;
    use types::{
        altair::beacon_state::BeaconState as AltairBeaconState,
        bellatrix::beacon_state::BeaconState as BellatrixBeaconState,
        capella::beacon_state::BeaconState as CapellaBeaconState,
        config::Config,
        deneb::beacon_state::BeaconState as DenebBeaconState,
        electra::beacon_state::BeaconState as ElectraBeaconState,
        fulu::beacon_state::BeaconState as FuluBeaconState,
        gloas::beacon_state::BeaconState as GloasBeaconState,
        phase0::{beacon_state::BeaconState as Phase0BeaconState, containers::Fork},
        preset::Minimal,
    };

    use super::*;

    type StatePair = (
        &'static str,
        Arc<CombinedBeaconState<Minimal>>,
        Arc<CombinedBeaconState<Minimal>>,
    );

    /// A pair of states of the same phase that differ in a field shared by every phase, plus a
    /// phase-specific one where the phase has any.
    fn state_pairs() -> Vec<StatePair> {
        let mut pairs = Vec::new();

        macro_rules! pair {
            ($name: literal, $variant: ident, $state: ty $(, $extra: expr)?) => {{
                let base = <$state>::default();
                let mut changed = base.clone();

                changed.slot = 42;
                changed.latest_block_header.body_root = H256::repeat_byte(2);

                $({
                    let extra: fn(&mut $state) = $extra;
                    extra(&mut changed);
                })?

                pairs.push((
                    $name,
                    Arc::new(CombinedBeaconState::$variant(base.into())),
                    Arc::new(CombinedBeaconState::$variant(changed.into())),
                ));
            }};
        }

        pair!("phase0", Phase0, Phase0BeaconState<Minimal>);
        pair!("altair", Altair, AltairBeaconState<Minimal>, |state| {
            state.current_sync_committee = Arc::default();
        });
        pair!(
            "bellatrix",
            Bellatrix,
            BellatrixBeaconState<Minimal>,
            |state| {
                state.latest_execution_payload_header.gas_limit = 7;
            }
        );
        pair!("capella", Capella, CapellaBeaconState<Minimal>, |state| {
            state.latest_execution_payload_header.gas_limit = 7;
            state.next_withdrawal_index = 3;
        });
        pair!("deneb", Deneb, DenebBeaconState<Minimal>, |state| {
            state.latest_execution_payload_header.blob_gas_used = 9;
        });
        pair!("electra", Electra, ElectraBeaconState<Minimal>, |state| {
            state.latest_execution_payload_header.blob_gas_used = 9;
            state.deposit_requests_start_index = 11;
        });
        pair!("fulu", Fulu, FuluBeaconState<Minimal>, |state| {
            state.latest_execution_payload_header.blob_gas_used = 9;
            state.deposit_requests_start_index = 11;
        });
        pair!("gloas", Gloas, GloasBeaconState<Minimal>, |state| {
            state.latest_block_hash = H256::repeat_byte(3);
            state.next_withdrawal_builder_index = 5;
        });

        pairs
    }

    #[test]
    fn every_phase_round_trips_through_the_public_patch() {
        for (name, base, changed) in state_pairs() {
            let patch = BeaconStatePatch::diff(PatchConfig::default(), &base, &changed)
                .unwrap_or_else(|error| {
                    panic!("{name} patch should represent the change: {error}")
                });

            let encoded = patch
                .to_ssz()
                .unwrap_or_else(|error| panic!("{name} patch should serialize: {error}"));

            let patch = BeaconStatePatch::<Minimal>::from_ssz(&Config::minimal(), encoded)
                .unwrap_or_else(|error| panic!("{name} patch should deserialize: {error}"));

            let mut applied = base;

            patch
                .apply(&mut applied)
                .unwrap_or_else(|error| panic!("{name} patch should apply: {error}"));

            assert_eq!(applied, changed, "{name} state should round trip");
            assert_eq!(
                applied.hash_tree_root(),
                changed.hash_tree_root(),
                "{name} state root should round trip",
            );
        }
    }

    #[test]
    fn a_change_to_a_versioning_field_is_rejected() {
        let base = Phase0BeaconState::<Minimal>::default();

        for changed in [
            Phase0BeaconState {
                genesis_validators_root: H256::repeat_byte(1),
                ..base.clone()
            },
            Phase0BeaconState {
                genesis_time: 1,
                ..base.clone()
            },
            Phase0BeaconState {
                fork: Fork {
                    epoch: 1,
                    ..Fork::default()
                },
                ..base.clone()
            },
        ] {
            let error = BeaconStatePatch::diff(
                PatchConfig::default(),
                &Arc::new(CombinedBeaconState::Phase0(base.clone().into())),
                &Arc::new(CombinedBeaconState::Phase0(changed.into())),
            )
            .expect_err("versioning fields are not part of the patch");

            assert!(matches!(error, Error::UnsupportedDiff));
        }
    }

    #[test]
    fn a_diff_across_phases_is_rejected() {
        let pairs = state_pairs();

        let phase0 = pairs[0].1.clone_arc();
        let altair = pairs[1].1.clone_arc();

        let error = BeaconStatePatch::diff(PatchConfig::default(), &phase0, &altair)
            .expect_err("states of different phases cannot be diffed");

        assert!(matches!(error, Error::CrossPhaseDiff));
    }

    #[test]
    fn a_patch_applied_to_another_phase_is_rejected() {
        let pairs = state_pairs();

        let (_, phase0_base, phase0_changed) = &pairs[0];

        let patch = BeaconStatePatch::diff(PatchConfig::default(), phase0_base, phase0_changed)
            .expect("patch should represent the change");

        let mut altair = pairs[1].1.clone_arc();

        let error = patch
            .apply(&mut altair)
            .expect_err("a phase0 patch cannot be applied to an altair state");

        assert!(matches!(error, Error::PatchPhaseMismatch));
    }

    #[test]
    fn an_empty_patch_and_an_unknown_selector_are_rejected() {
        let config = Config::minimal();

        BeaconStatePatch::<Minimal>::from_ssz(&config, [])
            .expect_err("an empty patch has no version selector");

        BeaconStatePatch::<Minimal>::from_ssz(&config, [2])
            .expect_err("2 is not a known patch version");

        BeaconStatePatch::<Minimal>::from_ssz(&config, [1])
            .expect_err("a versioned patch with no phase selector is incomplete");

        BeaconStatePatch::<Minimal>::from_ssz(&config, [1, 9])
            .expect_err("9 is not a known phase selector");
    }
}
