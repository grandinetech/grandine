use bls::SignatureBytes;
use derive_more::From;
use duplicate::duplicate_item;
use enum_iterator::Sequence as _;
use serde::{Deserialize, Serialize};
use ssz::{
    BitVector, ContiguousList, Hc, Offset, ReadError, Size, SszHash, SszRead, SszReadDefault,
    SszSize, SszWrite, WriteError, H256,
};
use static_assertions::{assert_not_impl_any, const_assert_eq};
use thiserror::Error;
use typenum::U1;
use variant_count::VariantCount;

use crate::{
    altair::{
        beacon_state::BeaconState as AltairBeaconState,
        containers::{
            BeaconBlock as AltairBeaconBlock, LightClientBootstrap as AltairLightClientBootstrap,
            LightClientFinalityUpdate as AltairLightClientFinalityUpdate,
            LightClientOptimisticUpdate as AltairLightClientOptimisticUpdate,
            SignedBeaconBlock as AltairSignedBeaconBlock,
        },
    },
    bellatrix::{
        beacon_state::BeaconState as BellatrixBeaconState,
        containers::{
            BeaconBlock as BellatrixBeaconBlock, BlindedBeaconBlock as BellatrixBlindedBeaconBlock,
            ExecutionPayload as BellatrixExecutionPayload,
            ExecutionPayloadHeader as BellatrixExecutionPayloadHeader,
            SignedBeaconBlock as BellatrixSignedBeaconBlock,
            SignedBlindedBeaconBlock as BellatrixSignedBlindedBeaconBlock,
        },
    },
    capella::{
        beacon_state::BeaconState as CapellaBeaconState,
        containers::{
            BeaconBlock as CapellaBeaconBlock, BlindedBeaconBlock as CapellaBlindedBeaconBlock,
            ExecutionPayload as CapellaExecutionPayload,
            ExecutionPayloadHeader as CapellaExecutionPayloadHeader,
            LightClientBootstrap as CapellaLightClientBootstrap,
            LightClientFinalityUpdate as CapellaLightClientFinalityUpdate,
            LightClientOptimisticUpdate as CapellaLightClientOptimisticUpdate,
            SignedBeaconBlock as CapellaSignedBeaconBlock,
            SignedBlindedBeaconBlock as CapellaSignedBlindedBeaconBlock,
        },
    },
    config::Config,
    deneb::{
        beacon_state::BeaconState as DenebBeaconState,
        containers::{
            BeaconBlock as DenebBeaconBlock, BlindedBeaconBlock as DenebBlindedBeaconBlock,
            ExecutionPayload as DenebExecutionPayload,
            ExecutionPayloadHeader as DenebExecutionPayloadHeader,
            LightClientBootstrap as DenebLightClientBootstrap,
            LightClientFinalityUpdate as DenebLightClientFinalityUpdate,
            LightClientOptimisticUpdate as DenebLightClientOptimisticUpdate,
            SignedBeaconBlock as DenebSignedBeaconBlock,
            SignedBlindedBeaconBlock as DenebSignedBlindedBeaconBlock,
        },
        primitives::{KzgCommitment, VersionedHash},
    },
    electra::{
        beacon_state::BeaconState as ElectraBeaconState,
        containers::{
            AggregateAndProof as ElectraAggregateAndProof, Attestation as ElectraAttestation,
            AttesterSlashing as ElectraAttesterSlashing, BeaconBlock as ElectraBeaconBlock,
            BlindedBeaconBlock as ElectraBlindedBeaconBlock, ExecutionRequests,
            LightClientBootstrap as ElectraLightClientBootstrap,
            LightClientFinalityUpdate as ElectraLightClientFinalityUpdate,
            LightClientOptimisticUpdate as ElectraLightClientOptimisticUpdate,
            SignedAggregateAndProof as ElectraSignedAggregateAndProof,
            SignedBeaconBlock as ElectraSignedBeaconBlock,
            SignedBlindedBeaconBlock as ElectraSignedBlindedBeaconBlock,
        },
    },
    nonstandard::Phase,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        containers::{
            AggregateAndProof as Phase0AggregateAndProof, Attestation as Phase0Attestation,
            AttestationData, AttesterSlashing as Phase0AttesterSlashing,
            BeaconBlock as Phase0BeaconBlock,
            SignedAggregateAndProof as Phase0SignedAggregateAndProof,
            SignedBeaconBlock as Phase0SignedBeaconBlock, SignedBeaconBlockHeader,
        },
        primitives::{
            DepositIndex, ExecutionBlockHash, ExecutionBlockNumber, Slot, UnixSeconds,
            ValidatorIndex,
        },
    },
    preset::{Mainnet, Preset},
    traits::{
        BeaconBlock as _, BeaconState as _, ExecutionPayload as ExecutionPayloadTrait,
        PostAltairBeaconState, PostBellatrixBeaconState, PostCapellaBeaconState,
        PostElectraBeaconState, SignedBeaconBlock as _,
    },
};

#[derive(Clone, PartialEq, Eq, Debug, From, VariantCount, Serialize)]
#[serde(bound = "", untagged)]
pub enum BeaconState<P: Preset> {
    Phase0(Hc<Phase0BeaconState<P>>),
    Altair(Hc<AltairBeaconState<P>>),
    Bellatrix(Hc<BellatrixBeaconState<P>>),
    Capella(Hc<CapellaBeaconState<P>>),
    Deneb(Hc<DenebBeaconState<P>>),
    Electra(Hc<ElectraBeaconState<P>>),
}

// This assertion will become incorrect if later phases don't modify `BeaconState`.
const_assert_eq!(BeaconState::<Mainnet>::VARIANT_COUNT, Phase::CARDINALITY);

#[duplicate_item(
    implementor;
    [Phase0BeaconState];
    [AltairBeaconState];
    [BellatrixBeaconState];
    [CapellaBeaconState];
    [DenebBeaconState];
    [ElectraBeaconState];
)]
impl<P: Preset> From<implementor<P>> for BeaconState<P> {
    fn from(state: implementor<P>) -> Self {
        Hc::from(state).into()
    }
}

impl<P: Preset> SszSize for BeaconState<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY }>([
        Phase0BeaconState::<P>::SIZE,
        AltairBeaconState::<P>::SIZE,
        BellatrixBeaconState::<P>::SIZE,
        CapellaBeaconState::<P>::SIZE,
        DenebBeaconState::<P>::SIZE,
        ElectraBeaconState::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Config> for BeaconState<P> {
    fn from_ssz_unchecked(config: &Config, bytes: &[u8]) -> Result<Self, ReadError> {
        // There are 2 fixed parts before `state.slot`:
        // - The contents of `state.genesis_time`.
        // - The contents of `state.genesis_validators_root`.
        let slot_start = UnixSeconds::SIZE.get() + H256::SIZE.get();
        let slot_end = slot_start + Slot::SIZE.get();
        let slot_bytes = ssz::subslice(bytes, slot_start..slot_end)?;
        let slot = Slot::from_ssz_default(slot_bytes)?;
        let phase = config.phase_at_slot::<P>(slot);

        let state = match phase {
            Phase::Phase0 => Self::Phase0(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Altair => Self::Altair(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Bellatrix => Self::Bellatrix(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Capella => Self::Capella(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Deneb => Self::Deneb(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
        };

        assert_eq!(slot, state.slot());

        Ok(state)
    }
}

impl<P: Preset> SszWrite for BeaconState<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(state) => state.write_variable(bytes),
            Self::Altair(state) => state.write_variable(bytes),
            Self::Bellatrix(state) => state.write_variable(bytes),
            Self::Capella(state) => state.write_variable(bytes),
            Self::Deneb(state) => state.write_variable(bytes),
            Self::Electra(state) => state.write_variable(bytes),
        }
    }
}

impl<P: Preset> SszHash for BeaconState<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Phase0(state) => state.hash_tree_root(),
            Self::Altair(state) => state.hash_tree_root(),
            Self::Bellatrix(state) => state.hash_tree_root(),
            Self::Capella(state) => state.hash_tree_root(),
            Self::Deneb(state) => state.hash_tree_root(),
            Self::Electra(state) => state.hash_tree_root(),
        }
    }
}

impl<P: Preset> BeaconState<P> {
    pub fn with_execution_payload_header(
        mut self,
        execution_payload_header: Option<ExecutionPayloadHeader<P>>,
    ) -> Result<Self, StatePhaseError> {
        let Some(execution_payload_header) = execution_payload_header else {
            return Ok(self);
        };

        match (&mut self, execution_payload_header) {
            (Self::Bellatrix(state), ExecutionPayloadHeader::Bellatrix(header)) => {
                state.latest_execution_payload_header = header;
            }
            (Self::Capella(state), ExecutionPayloadHeader::Capella(header)) => {
                state.latest_execution_payload_header = header;
            }
            (Self::Deneb(state), ExecutionPayloadHeader::Deneb(header)) => {
                state.latest_execution_payload_header = header;
            }
            (Self::Electra(state), ExecutionPayloadHeader::Deneb(header)) => {
                state.latest_execution_payload_header = header;
            }
            (_, header) => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 6);

                return Err(StatePhaseError {
                    state_phase: self.phase(),
                    payload_phase: header.phase(),
                });
            }
        }

        Ok(self)
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Phase0(_) => Phase::Phase0,
            Self::Altair(_) => Phase::Altair,
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
        }
    }

    // TODO(Grandine Team): Consider turning `BeaconState::post_*` into trait methods too.
    //                      That would make it possible to downcast trait objects when needed.
    //                      Adding the methods to the `BeaconState` trait would be tricky due to the
    //                      use of `duplicate::duplicate_item`.
    //                      Consider defining a new trait. Implement it for `*BeaconBlock` too.

    pub const fn post_altair(&self) -> Option<&dyn PostAltairBeaconState<P>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(state) => Some(state),
            Self::Bellatrix(state) => Some(state),
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
            Self::Electra(state) => Some(state),
        }
    }

    pub fn post_altair_mut(&mut self) -> Option<&mut dyn PostAltairBeaconState<P>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(state) => Some(state),
            Self::Bellatrix(state) => Some(state),
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
            Self::Electra(state) => Some(state),
        }
    }

    pub const fn post_bellatrix(&self) -> Option<&dyn PostBellatrixBeaconState<P>> {
        match self {
            Self::Phase0(_) | Self::Altair(_) => None,
            Self::Bellatrix(state) => Some(state),
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
            Self::Electra(state) => Some(state),
        }
    }

    pub fn post_bellatrix_mut(&mut self) -> Option<&mut dyn PostBellatrixBeaconState<P>> {
        match self {
            Self::Phase0(_) | Self::Altair(_) => None,
            Self::Bellatrix(state) => Some(state),
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
            Self::Electra(state) => Some(state),
        }
    }

    pub const fn post_capella(&self) -> Option<&dyn PostCapellaBeaconState<P>> {
        match self {
            Self::Phase0(_) | Self::Altair(_) | Self::Bellatrix(_) => None,
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
            Self::Electra(state) => Some(state),
        }
    }

    pub fn post_electra_mut(&mut self) -> Option<&mut dyn PostElectraBeaconState<P>> {
        match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => None,
            Self::Electra(state) => Some(state),
        }
    }

    pub fn set_cached_root(&self, root: H256) {
        match self {
            Self::Phase0(state) => state.set_cached_root(root),
            Self::Altair(state) => state.set_cached_root(root),
            Self::Bellatrix(state) => state.set_cached_root(root),
            Self::Capella(state) => state.set_cached_root(root),
            Self::Deneb(state) => state.set_cached_root(root),
            Self::Electra(state) => state.set_cached_root(root),
        }
    }

    pub fn deposit_requests_start_index(&self) -> Option<DepositIndex> {
        match self {
            Self::Phase0(_)
            | Self::Altair(_)
            | Self::Bellatrix(_)
            | Self::Capella(_)
            | Self::Deneb(_) => None,
            Self::Electra(state) => Some(state.deposit_requests_start_index),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, From, VariantCount, Deserialize, Serialize)]
#[serde(bound = "", untagged)]
pub enum SignedBeaconBlock<P: Preset> {
    Phase0(Phase0SignedBeaconBlock<P>),
    Altair(AltairSignedBeaconBlock<P>),
    Bellatrix(BellatrixSignedBeaconBlock<P>),
    Capella(CapellaSignedBeaconBlock<P>),
    Deneb(DenebSignedBeaconBlock<P>),
    Electra(ElectraSignedBeaconBlock<P>),
}

// This assertion will become incorrect if later phases don't modify `SignedBeaconBlock`.
const_assert_eq!(
    SignedBeaconBlock::<Mainnet>::VARIANT_COUNT,
    Phase::CARDINALITY,
);

impl<P: Preset> SszSize for SignedBeaconBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY }>([
        Phase0SignedBeaconBlock::<P>::SIZE,
        AltairSignedBeaconBlock::<P>::SIZE,
        BellatrixSignedBeaconBlock::<P>::SIZE,
        CapellaSignedBeaconBlock::<P>::SIZE,
        DenebSignedBeaconBlock::<P>::SIZE,
        ElectraSignedBeaconBlock::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Config> for SignedBeaconBlock<P> {
    fn from_ssz_unchecked(config: &Config, bytes: &[u8]) -> Result<Self, ReadError> {
        // There are 2 fixed parts before `block.message.slot`:
        // - The offset of `block.message`.
        // - The contents of `block.signature`.
        let slot_start = Offset::SIZE.get() + SignatureBytes::SIZE.get();
        let slot_end = slot_start + Slot::SIZE.get();
        let slot_bytes = ssz::subslice(bytes, slot_start..slot_end)?;
        let slot = Slot::from_ssz_default(slot_bytes)?;
        let phase = config.phase_at_slot::<P>(slot);

        let block = match phase {
            Phase::Phase0 => Self::Phase0(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Altair => Self::Altair(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Bellatrix => Self::Bellatrix(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Capella => Self::Capella(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Deneb => Self::Deneb(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
        };

        assert_eq!(slot, block.message().slot());

        Ok(block)
    }
}

impl<P: Preset> SszWrite for SignedBeaconBlock<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(block) => block.write_variable(bytes),
            Self::Altair(block) => block.write_variable(bytes),
            Self::Bellatrix(block) => block.write_variable(bytes),
            Self::Capella(block) => block.write_variable(bytes),
            Self::Deneb(block) => block.write_variable(bytes),
            Self::Electra(block) => block.write_variable(bytes),
        }
    }
}

impl<P: Preset> SszHash for SignedBeaconBlock<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Phase0(block) => block.hash_tree_root(),
            Self::Altair(block) => block.hash_tree_root(),
            Self::Bellatrix(block) => block.hash_tree_root(),
            Self::Capella(block) => block.hash_tree_root(),
            Self::Deneb(block) => block.hash_tree_root(),
            Self::Electra(block) => block.hash_tree_root(),
        }
    }
}

impl<P: Preset> SignedBeaconBlock<P> {
    pub fn split(self) -> (BeaconBlock<P>, SignatureBytes) {
        match self {
            Self::Phase0(block) => {
                let Phase0SignedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
            Self::Altair(block) => {
                let AltairSignedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
            Self::Bellatrix(block) => {
                let BellatrixSignedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
            Self::Capella(block) => {
                let CapellaSignedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
            Self::Deneb(block) => {
                let DenebSignedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
            Self::Electra(block) => {
                let ElectraSignedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
        }
    }

    pub fn execution_payload(self) -> Option<ExecutionPayload<P>> {
        match self {
            Self::Phase0(_) | Self::Altair(_) => None,
            Self::Bellatrix(block) => Some(ExecutionPayload::Bellatrix(
                block.message.body.execution_payload,
            )),
            Self::Capella(block) => Some(ExecutionPayload::Capella(
                block.message.body.execution_payload,
            )),
            Self::Deneb(block) => Some(ExecutionPayload::Deneb(
                block.message.body.execution_payload,
            )),
            Self::Electra(block) => Some(ExecutionPayload::Deneb(
                block.message.body.execution_payload,
            )),
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Phase0(_) => Phase::Phase0,
            Self::Altair(_) => Phase::Altair,
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
        }
    }

    pub fn execution_block_hash(&self) -> Option<ExecutionBlockHash> {
        self.message()
            .body()
            .post_bellatrix()
            .map(|body| body.execution_payload().block_hash())
    }

    pub fn to_header(&self) -> SignedBeaconBlockHeader {
        self.message().to_header().with_signature(self.signature())
    }
}

#[derive(Clone, Debug, From, VariantCount, Serialize)]
#[serde(bound = "", untagged)]
pub enum BeaconBlock<P: Preset> {
    Phase0(Phase0BeaconBlock<P>),
    Altair(AltairBeaconBlock<P>),
    Bellatrix(BellatrixBeaconBlock<P>),
    Capella(CapellaBeaconBlock<P>),
    Deneb(DenebBeaconBlock<P>),
    Electra(ElectraBeaconBlock<P>),
}

// This assertion will become incorrect if later phases don't modify `BeaconBlock`.
const_assert_eq!(BeaconBlock::<Mainnet>::VARIANT_COUNT, Phase::CARDINALITY);

impl<P: Preset> SszSize for BeaconBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY }>([
        Phase0BeaconBlock::<P>::SIZE,
        AltairBeaconBlock::<P>::SIZE,
        BellatrixBeaconBlock::<P>::SIZE,
        CapellaBeaconBlock::<P>::SIZE,
        DenebBeaconBlock::<P>::SIZE,
        ElectraBeaconBlock::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Config> for BeaconBlock<P> {
    fn from_ssz_unchecked(config: &Config, bytes: &[u8]) -> Result<Self, ReadError> {
        // The offset of `block.slot` is the first fixed part in `block`.
        let slot_start = 0;
        let slot_end = slot_start + Slot::SIZE.get();
        let slot_bytes = ssz::subslice(bytes, slot_start..slot_end)?;
        let slot = Slot::from_ssz_default(slot_bytes)?;
        let phase = config.phase_at_slot::<P>(slot);

        let block = match phase {
            Phase::Phase0 => Self::Phase0(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Altair => Self::Altair(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Bellatrix => Self::Bellatrix(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Capella => Self::Capella(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Deneb => Self::Deneb(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
        };

        assert_eq!(slot, block.slot());

        Ok(block)
    }
}

impl<P: Preset> SszWrite for BeaconBlock<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(block) => block.write_variable(bytes),
            Self::Altair(block) => block.write_variable(bytes),
            Self::Bellatrix(block) => block.write_variable(bytes),
            Self::Capella(block) => block.write_variable(bytes),
            Self::Deneb(block) => block.write_variable(bytes),
            Self::Electra(block) => block.write_variable(bytes),
        }
    }
}

impl<P: Preset> SszHash for BeaconBlock<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Phase0(block) => block.hash_tree_root(),
            Self::Altair(block) => block.hash_tree_root(),
            Self::Bellatrix(block) => block.hash_tree_root(),
            Self::Capella(block) => block.hash_tree_root(),
            Self::Deneb(block) => block.hash_tree_root(),
            Self::Electra(block) => block.hash_tree_root(),
        }
    }
}

impl<P: Preset> BeaconBlock<P> {
    pub fn with_zero_signature(self) -> SignedBeaconBlock<P> {
        self.with_signature(SignatureBytes::zero())
    }

    pub fn with_signature(self, signature: SignatureBytes) -> SignedBeaconBlock<P> {
        match self {
            Self::Phase0(message) => Phase0SignedBeaconBlock { message, signature }.into(),
            Self::Altair(message) => AltairSignedBeaconBlock { message, signature }.into(),
            Self::Bellatrix(message) => BellatrixSignedBeaconBlock { message, signature }.into(),
            Self::Capella(message) => CapellaSignedBeaconBlock { message, signature }.into(),
            Self::Deneb(message) => DenebSignedBeaconBlock { message, signature }.into(),
            Self::Electra(message) => ElectraSignedBeaconBlock { message, signature }.into(),
        }
    }

    #[must_use]
    pub fn with_state_root(mut self, state_root: H256) -> Self {
        match &mut self {
            Self::Phase0(block) => block.state_root = state_root,
            Self::Altair(block) => block.state_root = state_root,
            Self::Bellatrix(block) => block.state_root = state_root,
            Self::Capella(block) => block.state_root = state_root,
            Self::Deneb(block) => block.state_root = state_root,
            Self::Electra(block) => block.state_root = state_root,
        }

        self
    }

    pub fn with_execution_payload(
        mut self,
        execution_payload: Option<ExecutionPayload<P>>,
    ) -> Result<Self, BlockPhaseError> {
        let Some(execution_payload) = execution_payload else {
            return Ok(self);
        };

        match (&mut self, execution_payload) {
            (Self::Bellatrix(block), ExecutionPayload::Bellatrix(payload)) => {
                block.body.execution_payload = payload;
            }
            (Self::Capella(block), ExecutionPayload::Capella(payload)) => {
                block.body.execution_payload = payload;
            }
            (Self::Deneb(block), ExecutionPayload::Deneb(payload)) => {
                block.body.execution_payload = payload;
            }
            (Self::Electra(block), ExecutionPayload::Deneb(payload)) => {
                block.body.execution_payload = payload;
            }
            (_, payload) => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 6);

                return Err(BlockPhaseError {
                    block_phase: self.phase(),
                    payload_phase: payload.phase(),
                });
            }
        }

        Ok(self)
    }

    #[must_use]
    pub fn with_blob_kzg_commitments(
        mut self,
        blob_kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
    ) -> Self {
        let Some(commitments) = blob_kzg_commitments else {
            return self;
        };

        match &mut self {
            Self::Deneb(block) => block.body.blob_kzg_commitments = commitments,
            Self::Electra(block) => block.body.blob_kzg_commitments = commitments,
            _ => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 6);
            }
        }

        self
    }

    #[must_use]
    pub fn with_execution_requests(
        mut self,
        execution_requests: Option<ExecutionRequests<P>>,
    ) -> Self {
        let Some(execution_requests) = execution_requests else {
            return self;
        };

        match &mut self {
            Self::Electra(block) => block.body.execution_requests = execution_requests,
            _ => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 6);
            }
        }

        self
    }

    pub fn into_blinded(
        self,
        execution_payload_header: ExecutionPayloadHeader<P>,
        kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
        execution_requests: Option<ExecutionRequests<P>>,
    ) -> Result<BlindedBeaconBlock<P>, BlockPhaseError> {
        match (self, execution_payload_header) {
            (Self::Bellatrix(block), ExecutionPayloadHeader::Bellatrix(header)) => {
                Ok(block.with_execution_payload_header(header).into())
            }
            (Self::Capella(block), ExecutionPayloadHeader::Capella(header)) => {
                Ok(block.with_execution_payload_header(header).into())
            }
            (Self::Deneb(block), ExecutionPayloadHeader::Deneb(header)) => Ok(block
                .with_execution_payload_header_and_kzg_commitments(header, kzg_commitments)
                .into()),
            (Self::Electra(block), ExecutionPayloadHeader::Deneb(header)) => Ok(block
                .with_execution_payload_header_and_kzg_commitments(
                    header,
                    kzg_commitments,
                    execution_requests,
                )
                .into()),
            (block, header) => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 6);

                Err(BlockPhaseError {
                    block_phase: block.phase(),
                    payload_phase: header.phase(),
                })
            }
        }
    }

    pub fn execution_payload(self) -> Option<ExecutionPayload<P>> {
        match self {
            Self::Phase0(_) | Self::Altair(_) => None,
            Self::Bellatrix(block) => {
                Some(ExecutionPayload::Bellatrix(block.body.execution_payload))
            }
            Self::Capella(block) => Some(ExecutionPayload::Capella(block.body.execution_payload)),
            Self::Deneb(block) => Some(ExecutionPayload::Deneb(block.body.execution_payload)),
            Self::Electra(block) => Some(ExecutionPayload::Deneb(block.body.execution_payload)),
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Phase0(_) => Phase::Phase0,
            Self::Altair(_) => Phase::Altair,
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
        }
    }
}

impl<P: Preset> From<BeaconBlock<P>> for SignedBeaconBlock<P> {
    fn from(beacon_block: BeaconBlock<P>) -> Self {
        match beacon_block {
            BeaconBlock::Phase0(message) => Phase0SignedBeaconBlock {
                message,
                signature: SignatureBytes::default(),
            }
            .into(),
            BeaconBlock::Altair(message) => AltairSignedBeaconBlock {
                message,
                signature: SignatureBytes::default(),
            }
            .into(),
            BeaconBlock::Bellatrix(message) => BellatrixSignedBeaconBlock {
                message,
                signature: SignatureBytes::default(),
            }
            .into(),
            BeaconBlock::Capella(message) => CapellaSignedBeaconBlock {
                message,
                signature: SignatureBytes::default(),
            }
            .into(),
            BeaconBlock::Deneb(message) => DenebSignedBeaconBlock {
                message,
                signature: SignatureBytes::default(),
            }
            .into(),
            BeaconBlock::Electra(message) => ElectraSignedBeaconBlock {
                message,
                signature: SignatureBytes::default(),
            }
            .into(),
        }
    }
}

impl<P: Preset> From<SignedBeaconBlock<P>> for BeaconBlock<P> {
    fn from(signed_block: SignedBeaconBlock<P>) -> Self {
        let (message, _) = signed_block.split();
        message
    }
}

#[derive(Clone, Debug, From, Deserialize, Serialize)]
#[serde(bound = "", untagged)]
#[cfg_attr(test, derive(VariantCount))]
pub enum SignedBlindedBeaconBlock<P: Preset> {
    Bellatrix(BellatrixSignedBlindedBeaconBlock<P>),
    Capella(CapellaSignedBlindedBeaconBlock<P>),
    Deneb(DenebSignedBlindedBeaconBlock<P>),
    Electra(ElectraSignedBlindedBeaconBlock<P>),
}

impl<P: Preset> SszSize for SignedBlindedBeaconBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        BellatrixSignedBlindedBeaconBlock::<P>::SIZE,
        CapellaSignedBlindedBeaconBlock::<P>::SIZE,
        DenebSignedBlindedBeaconBlock::<P>::SIZE,
        ElectraSignedBlindedBeaconBlock::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Config> for SignedBlindedBeaconBlock<P> {
    fn from_ssz_unchecked(config: &Config, bytes: &[u8]) -> Result<Self, ReadError> {
        // There are 2 fixed parts before `block.message.slot`:
        // - The offset of `block.message`.
        // - The contents of `block.signature`.
        let slot_start = Offset::SIZE.get() + SignatureBytes::SIZE.get();
        let slot_end = slot_start + Slot::SIZE.get();
        let slot_bytes = ssz::subslice(bytes, slot_start..slot_end)?;
        let slot = Slot::from_ssz_default(slot_bytes)?;
        let phase = config.phase_at_slot::<P>(slot);

        let block = match phase {
            Phase::Phase0 => {
                return Err(ReadError::Custom {
                    message: "blinded block has slot in Phase 0",
                });
            }
            Phase::Altair => {
                return Err(ReadError::Custom {
                    message: "blinded block has slot in Altair",
                });
            }
            Phase::Bellatrix => Self::Bellatrix(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Capella => Self::Capella(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Deneb => Self::Deneb(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
        };

        assert_eq!(slot, block.message().slot());

        Ok(block)
    }
}

impl<P: Preset> SignedBlindedBeaconBlock<P> {
    pub fn split(self) -> (BlindedBeaconBlock<P>, SignatureBytes) {
        match self {
            Self::Bellatrix(block) => {
                let BellatrixSignedBlindedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
            Self::Capella(block) => {
                let CapellaSignedBlindedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
            Self::Deneb(block) => {
                let DenebSignedBlindedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
            Self::Electra(block) => {
                let ElectraSignedBlindedBeaconBlock { message, signature } = block;
                (message.into(), signature)
            }
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
        }
    }

    // This could be decomposed like the old `SignedBeaconBlock::body_post_*` methods,
    // but that may require new traits for `BlindedBeaconBlock` and `BlindedBeaconBlockBody`.
    #[must_use]
    pub fn execution_payload_header(&self) -> &dyn ExecutionPayloadTrait<P> {
        match self {
            Self::Bellatrix(block) => &block.message.body.execution_payload_header,
            Self::Capella(block) => &block.message.body.execution_payload_header,
            Self::Deneb(block) => &block.message.body.execution_payload_header,
            Self::Electra(block) => &block.message.body.execution_payload_header,
        }
    }
}

#[derive(Debug, Clone, From, Deserialize, Serialize)]
#[serde(bound = "", untagged)]
#[cfg_attr(test, derive(VariantCount))]
pub enum BlindedBeaconBlock<P: Preset> {
    Bellatrix(BellatrixBlindedBeaconBlock<P>),
    Capella(CapellaBlindedBeaconBlock<P>),
    Deneb(DenebBlindedBeaconBlock<P>),
    Electra(ElectraBlindedBeaconBlock<P>),
}

impl<P: Preset> SszSize for BlindedBeaconBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        BellatrixBlindedBeaconBlock::<P>::SIZE,
        CapellaBlindedBeaconBlock::<P>::SIZE,
        DenebSignedBlindedBeaconBlock::<P>::SIZE,
        ElectraSignedBlindedBeaconBlock::<P>::SIZE,
    ]);
}

impl<P: Preset> SszWrite for BlindedBeaconBlock<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Bellatrix(block) => block.write_variable(bytes),
            Self::Capella(block) => block.write_variable(bytes),
            Self::Deneb(block) => block.write_variable(bytes),
            Self::Electra(block) => block.write_variable(bytes),
        }
    }
}

impl<P: Preset> SszHash for BlindedBeaconBlock<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Bellatrix(block) => block.hash_tree_root(),
            Self::Capella(block) => block.hash_tree_root(),
            Self::Deneb(block) => block.hash_tree_root(),
            Self::Electra(block) => block.hash_tree_root(),
        }
    }
}

impl<P: Preset> BlindedBeaconBlock<P> {
    pub fn with_signature(self, signature: SignatureBytes) -> SignedBlindedBeaconBlock<P> {
        match self {
            Self::Bellatrix(message) => {
                BellatrixSignedBlindedBeaconBlock { message, signature }.into()
            }
            Self::Capella(message) => CapellaSignedBlindedBeaconBlock { message, signature }.into(),
            Self::Deneb(message) => DenebSignedBlindedBeaconBlock { message, signature }.into(),
            Self::Electra(message) => ElectraSignedBlindedBeaconBlock { message, signature }.into(),
        }
    }

    #[must_use]
    pub fn with_state_root(mut self, state_root: H256) -> Self {
        match &mut self {
            Self::Bellatrix(block) => block.state_root = state_root,
            Self::Capella(block) => block.state_root = state_root,
            Self::Deneb(block) => block.state_root = state_root,
            Self::Electra(block) => block.state_root = state_root,
        }

        self
    }

    pub fn with_execution_payload(
        self,
        execution_payload: ExecutionPayload<P>,
    ) -> Result<BeaconBlock<P>, BlockPhaseError> {
        match (self, execution_payload) {
            (Self::Bellatrix(block), ExecutionPayload::Bellatrix(payload)) => {
                Ok(block.with_execution_payload(payload).into())
            }
            (Self::Capella(block), ExecutionPayload::Capella(payload)) => {
                Ok(block.with_execution_payload(payload).into())
            }
            (Self::Deneb(block), ExecutionPayload::Deneb(payload)) => {
                Ok(block.with_execution_payload(payload).into())
            }
            (Self::Electra(block), ExecutionPayload::Deneb(payload)) => {
                Ok(block.with_execution_payload(payload).into())
            }
            (block, payload) => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 6);

                Err(BlockPhaseError {
                    block_phase: block.phase(),
                    payload_phase: payload.phase(),
                })
            }
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, From, Deserialize, Serialize)]
#[serde(
    bound = "",
    deny_unknown_fields,
    rename_all = "lowercase",
    tag = "version",
    content = "data"
)]
pub enum ExecutionPayload<P: Preset> {
    Bellatrix(BellatrixExecutionPayload<P>),
    Capella(CapellaExecutionPayload<P>),
    Deneb(DenebExecutionPayload<P>),
}

impl<P: Preset> SszHash for ExecutionPayload<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Bellatrix(payload) => payload.hash_tree_root(),
            Self::Capella(payload) => payload.hash_tree_root(),
            Self::Deneb(payload) => payload.hash_tree_root(),
        }
    }
}

impl<P: Preset> ExecutionPayload<P> {
    pub const fn phase(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
        }
    }

    pub const fn block_number(&self) -> ExecutionBlockNumber {
        match self {
            Self::Bellatrix(payload) => payload.block_number,
            Self::Capella(payload) => payload.block_number,
            Self::Deneb(payload) => payload.block_number,
        }
    }

    pub const fn block_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Bellatrix(payload) => payload.block_hash,
            Self::Capella(payload) => payload.block_hash,
            Self::Deneb(payload) => payload.block_hash,
        }
    }
}

#[derive(From, Deserialize)]
#[serde(bound = "", untagged)]
pub enum ExecutionPayloadHeader<P: Preset> {
    Bellatrix(BellatrixExecutionPayloadHeader<P>),
    Capella(CapellaExecutionPayloadHeader<P>),
    Deneb(DenebExecutionPayloadHeader<P>),
}

impl<P: Preset> ExecutionPayloadHeader<P> {
    pub const fn phase(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
        }
    }
}

// TODO(feature/deneb): `ExecutionPayloadParams` seems to correspond to `NewPayloadRequest` from
//                      `consensus-specs`. Try redesigning to match it exactly or remove this type
//                      entirely. Is this module the right place for it? See:
//                      - <https://github.com/ethereum/consensus-specs/releases/tag/v1.4.0-alpha.0>
//                      - <https://github.com/ethereum/consensus-specs/pull/3359>
#[derive(Serialize)]
pub enum ExecutionPayloadParams<P: Preset> {
    Deneb {
        versioned_hashes: Vec<VersionedHash>,
        parent_beacon_block_root: H256,
    },
    Electra {
        versioned_hashes: Vec<VersionedHash>,
        parent_beacon_block_root: H256,
        execution_requests: ExecutionRequests<P>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LightClientBootstrap<P: Preset> {
    Altair(Box<AltairLightClientBootstrap<P>>),
    Capella(Box<CapellaLightClientBootstrap<P>>),
    Deneb(Box<DenebLightClientBootstrap<P>>),
    Electra(Box<ElectraLightClientBootstrap<P>>),
}

impl<P: Preset> LightClientBootstrap<P> {
    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self {
            Self::Altair(_) => Phase::Altair,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
        }
    }

    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Altair(bootstrap) => bootstrap.header.beacon.slot,
            Self::Capella(bootstrap) => bootstrap.header.beacon.slot,
            Self::Deneb(bootstrap) => bootstrap.header.beacon.slot,
            Self::Electra(bootstrap) => bootstrap.header.beacon.slot,
        }
    }
}

impl<P: Preset> SszSize for LightClientBootstrap<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        AltairLightClientBootstrap::<P>::SIZE,
        CapellaLightClientBootstrap::<P>::SIZE,
        DenebLightClientBootstrap::<P>::SIZE,
        ElectraLightClientBootstrap::<P>::SIZE,
    ]);
}

impl<P: Preset> SszWrite for LightClientBootstrap<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Altair(update) => {
                let length_before = bytes.len();
                let length_after = length_before + AltairLightClientBootstrap::<P>::SIZE.get();

                bytes.resize(length_after, 0);
                update.write_fixed(&mut bytes[length_before..]);

                Ok(())
            }
            Self::Capella(update) => update.write_variable(bytes),
            Self::Deneb(update) => update.write_variable(bytes),
            Self::Electra(update) => update.write_variable(bytes),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LightClientFinalityUpdate<P: Preset> {
    // Boxed to pass `clippy::large_enum_variant`.
    Altair(Box<AltairLightClientFinalityUpdate<P>>),
    Capella(Box<CapellaLightClientFinalityUpdate<P>>),
    Deneb(Box<DenebLightClientFinalityUpdate<P>>),
    Electra(Box<ElectraLightClientFinalityUpdate<P>>),
}

// It is difficult to implement `SszRead` for the combined `LightClientFinalityUpdate`.
// `attested_header` starts with a slot, but `LightClientHeader` becomes variable-size in Capella.
// It is possible to distinguish variants of `LightClientFinalityUpdate` by length as of Capella,
// but it becomes more difficult in Deneb and may become impossible in later phases.
assert_not_impl_any!(LightClientFinalityUpdate<Mainnet>: SszRead<Config>);

impl<P: Preset> SszSize for LightClientFinalityUpdate<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        AltairLightClientFinalityUpdate::<P>::SIZE,
        CapellaLightClientFinalityUpdate::<P>::SIZE,
        DenebLightClientFinalityUpdate::<P>::SIZE,
        ElectraLightClientFinalityUpdate::<P>::SIZE,
    ]);
}

impl<P: Preset> SszWrite for LightClientFinalityUpdate<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Altair(update) => {
                let length_before = bytes.len();
                let length_after = length_before + AltairLightClientFinalityUpdate::<P>::SIZE.get();

                bytes.resize(length_after, 0);
                update.write_fixed(&mut bytes[length_before..]);

                Ok(())
            }
            Self::Capella(update) => update.write_variable(bytes),
            Self::Deneb(update) => update.write_variable(bytes),
            Self::Electra(update) => update.write_variable(bytes),
        }
    }
}

impl<P: Preset> LightClientFinalityUpdate<P> {
    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self {
            Self::Altair(_) => Phase::Altair,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
        }
    }

    #[must_use]
    pub const fn signature_slot(&self) -> Slot {
        match self {
            Self::Altair(update) => update.signature_slot,
            Self::Capella(update) => update.signature_slot,
            Self::Deneb(update) => update.signature_slot,
            Self::Electra(update) => update.signature_slot,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LightClientOptimisticUpdate<P: Preset> {
    // Boxed to pass `clippy::large_enum_variant`.
    Altair(Box<AltairLightClientOptimisticUpdate<P>>),
    Capella(Box<CapellaLightClientOptimisticUpdate<P>>),
    Deneb(Box<DenebLightClientOptimisticUpdate<P>>),
    Electra(Box<ElectraLightClientOptimisticUpdate<P>>),
}

// It is difficult to implement `SszRead` for the combined `LightClientOptimisticUpdate`.
// `attested_header` starts with a slot, but `LightClientHeader` becomes variable-size in Capella.
// It is possible to distinguish variants of `LightClientOptimisticUpdate` by length as of Capella,
// but it becomes more difficult in Deneb and may become impossible in later phases.
assert_not_impl_any!(LightClientOptimisticUpdate<Mainnet>: SszRead<Config>);

impl<P: Preset> SszSize for LightClientOptimisticUpdate<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        AltairLightClientOptimisticUpdate::<P>::SIZE,
        CapellaLightClientOptimisticUpdate::<P>::SIZE,
        DenebLightClientOptimisticUpdate::<P>::SIZE,
        ElectraLightClientOptimisticUpdate::<P>::SIZE,
    ]);
}

impl<P: Preset> SszWrite for LightClientOptimisticUpdate<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Altair(update) => {
                let size = AltairLightClientOptimisticUpdate::<P>::SIZE.get();
                let length_before = bytes.len();
                let length_after = length_before + size;

                bytes.resize(length_after, 0);
                update.write_fixed(&mut bytes[length_before..]);

                Ok(())
            }
            Self::Capella(update) => update.write_variable(bytes),
            Self::Deneb(update) => update.write_variable(bytes),
            Self::Electra(update) => update.write_variable(bytes),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, From, Deserialize, Serialize)]
#[serde(bound = "", untagged)]
pub enum AggregateAndProof<P: Preset> {
    Phase0(Phase0AggregateAndProof<P>),
    Electra(ElectraAggregateAndProof<P>),
}

impl<P: Preset> AggregateAndProof<P> {
    pub const fn aggregator_index(&self) -> ValidatorIndex {
        match self {
            Self::Phase0(aggregate_and_proof) => aggregate_and_proof.aggregator_index,
            Self::Electra(aggregate_and_proof) => aggregate_and_proof.aggregator_index,
        }
    }

    pub const fn selection_proof(&self) -> SignatureBytes {
        match self {
            Self::Phase0(aggregate_and_proof) => aggregate_and_proof.selection_proof,
            Self::Electra(aggregate_and_proof) => aggregate_and_proof.selection_proof,
        }
    }

    pub const fn slot(&self) -> Slot {
        match self {
            Self::Phase0(aggregate_and_proof) => aggregate_and_proof.aggregate.data.slot,
            Self::Electra(aggregate_and_proof) => aggregate_and_proof.aggregate.data.slot,
        }
    }

    // TODO(feature/electra): eliminate clone
    pub fn aggregate(&self) -> Attestation<P> {
        match self {
            Self::Phase0(aggregate_and_proof) => aggregate_and_proof.aggregate.clone().into(),
            Self::Electra(aggregate_and_proof) => aggregate_and_proof.aggregate.clone().into(),
        }
    }
}

impl<P: Preset> SszHash for AggregateAndProof<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Phase0(aggregate_and_proof) => aggregate_and_proof.hash_tree_root(),
            Self::Electra(aggregate_and_proof) => aggregate_and_proof.hash_tree_root(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, From, Deserialize, Serialize)]
#[serde(bound = "", untagged)]
pub enum SignedAggregateAndProof<P: Preset> {
    Phase0(Phase0SignedAggregateAndProof<P>),
    Electra(ElectraSignedAggregateAndProof<P>),
}

impl<P: Preset> SszSize for SignedAggregateAndProof<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 4 }>([
        Phase0SignedAggregateAndProof::<P>::SIZE,
        ElectraSignedAggregateAndProof::<P>::SIZE,
    ]);
}

impl<P: Preset> SszWrite for SignedAggregateAndProof<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(signed_aggregate_and_proof) => {
                signed_aggregate_and_proof.write_variable(bytes)
            }
            Self::Electra(signed_aggregate_and_proof) => {
                signed_aggregate_and_proof.write_variable(bytes)
            }
        }
    }
}

impl<P: Preset> SignedAggregateAndProof<P> {
    pub const fn aggregator_index(&self) -> ValidatorIndex {
        match self {
            Self::Phase0(aggregate_and_proof) => aggregate_and_proof.message.aggregator_index,
            Self::Electra(aggregate_and_proof) => aggregate_and_proof.message.aggregator_index,
        }
    }

    pub const fn signature(&self) -> SignatureBytes {
        match self {
            Self::Phase0(signed_aggregate_and_proof) => signed_aggregate_and_proof.signature,
            Self::Electra(signed_aggregate_and_proof) => signed_aggregate_and_proof.signature,
        }
    }

    pub const fn slot(&self) -> Slot {
        match self {
            Self::Phase0(aggregate_and_proof) => aggregate_and_proof.message.aggregate.data.slot,
            Self::Electra(aggregate_and_proof) => aggregate_and_proof.message.aggregate.data.slot,
        }
    }

    pub fn aggregate(&self) -> Attestation<P> {
        match self {
            Self::Phase0(aggregate_and_proof) => {
                Attestation::from(aggregate_and_proof.message.aggregate.clone())
            }
            Self::Electra(aggregate_and_proof) => {
                Attestation::from(aggregate_and_proof.message.aggregate.clone())
            }
        }
    }

    // TODO(feature/electra): avoid clone
    pub fn message(&self) -> AggregateAndProof<P> {
        match self {
            Self::Phase0(signed_aggregate_and_proof) => {
                AggregateAndProof::Phase0(signed_aggregate_and_proof.message.clone())
            }
            Self::Electra(signed_aggregate_and_proof) => {
                AggregateAndProof::Electra(signed_aggregate_and_proof.message.clone())
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(bound = "", untagged)]
pub enum AttestingIndices<P: Preset> {
    Phase0(ContiguousList<ValidatorIndex, P::MaxValidatorsPerCommittee>),
    Electra(ContiguousList<ValidatorIndex, P::MaxAggregatorsPerSlot>),
}

impl<'list, P: Preset> IntoIterator for &'list AttestingIndices<P> {
    type Item = &'list ValidatorIndex;
    type IntoIter = <&'list [ValidatorIndex] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            AttestingIndices::Phase0(list) => list.iter(),
            AttestingIndices::Electra(list) => list.iter(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, From, Deserialize, Serialize)]
#[serde(bound = "", untagged)]
pub enum Attestation<P: Preset> {
    Phase0(Phase0Attestation<P>),
    Electra(ElectraAttestation<P>),
}

impl<P: Preset> SszSize for Attestation<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 4 }>([
        Phase0Attestation::<P>::SIZE,
        ElectraAttestation::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Config> for Attestation<P> {
    fn from_ssz_unchecked(config: &Config, bytes: &[u8]) -> Result<Self, ReadError> {
        // There is 1 fixed part before `attestation.data.slot`:
        // - The offset of `attestation.aggregation_bits`.
        let slot_start = Offset::SIZE.get();
        let slot_end = slot_start + Slot::SIZE.get();
        let slot_bytes = ssz::subslice(bytes, slot_start..slot_end)?;
        let slot = Slot::from_ssz_default(slot_bytes)?;
        let phase = config.phase_at_slot::<P>(slot);

        let attestation = match phase {
            Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella | Phase::Deneb => {
                Self::Phase0(SszReadDefault::from_ssz_default(bytes)?)
            }
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
        };

        assert_eq!(slot, attestation.data().slot);

        Ok(attestation)
    }
}

impl<P: Preset> SszWrite for Attestation<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(attestation) => attestation.write_variable(bytes),
            Self::Electra(attestation) => attestation.write_variable(bytes),
        }
    }
}

impl<P: Preset> SszHash for Attestation<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::Phase0(attestation) => attestation.hash_tree_root(),
            Self::Electra(attestation) => attestation.hash_tree_root(),
        }
    }
}

impl<P: Preset> Attestation<P> {
    pub const fn data(&self) -> AttestationData {
        match self {
            Self::Phase0(attestation) => attestation.data,
            Self::Electra(attestation) => attestation.data,
        }
    }

    pub const fn committee_bits(&self) -> Option<&BitVector<P::MaxCommitteesPerSlot>> {
        match self {
            Self::Phase0(_) => None,
            Self::Electra(attestation) => Some(&attestation.committee_bits),
        }
    }

    pub fn count_aggregation_bits(&self) -> usize {
        match self {
            Self::Phase0(attestation) => attestation.aggregation_bits.count_ones(),
            Self::Electra(attestation) => attestation.aggregation_bits.count_ones(),
        }
    }

    #[cfg(test)]
    pub const fn phase(&self) -> Phase {
        match self {
            Self::Phase0(_) => Phase::Phase0,
            Self::Electra(_) => Phase::Electra,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, From, Deserialize, Serialize)]
#[serde(bound = "", untagged)]
pub enum AttesterSlashing<P: Preset> {
    Phase0(Phase0AttesterSlashing<P>),
    Electra(ElectraAttesterSlashing<P>),
}

// It appears to be impossible to implement `SszRead` for the combined `AttesterSlashing`.
// `AttesterSlashing` does not contain any field that can be used to determine its phase.
// The attestations inside `AttesterSlashing` may be from a different phase.
assert_not_impl_any!(AttesterSlashing<Mainnet>: SszRead<Config>);

impl<P: Preset> SszSize for AttesterSlashing<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 4 }>([
        Phase0AttesterSlashing::<P>::SIZE,
        ElectraAttesterSlashing::<P>::SIZE,
    ]);
}

impl<P: Preset> SszWrite for AttesterSlashing<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Phase0(attester_slashing) => attester_slashing.write_variable(bytes),
            Self::Electra(attester_slashing) => attester_slashing.write_variable(bytes),
        }
    }
}

impl<P: Preset> AttesterSlashing<P> {
    #[must_use]
    pub fn pre_electra(self) -> Option<Phase0AttesterSlashing<P>> {
        match self {
            Self::Phase0(attester_slashing) => Some(attester_slashing),
            Self::Electra(_) => None,
        }
    }

    #[must_use]
    pub fn post_electra(self) -> Option<ElectraAttesterSlashing<P>> {
        match self {
            Self::Phase0(_) => None,
            Self::Electra(attester_slashing) => Some(attester_slashing),
        }
    }
}

impl<P: Preset> LightClientOptimisticUpdate<P> {
    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self {
            Self::Altair(_) => Phase::Altair,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
            Self::Electra(_) => Phase::Electra,
        }
    }

    #[must_use]
    pub const fn signature_slot(&self) -> Slot {
        match self {
            Self::Altair(update) => update.signature_slot,
            Self::Capella(update) => update.signature_slot,
            Self::Deneb(update) => update.signature_slot,
            Self::Electra(update) => update.signature_slot,
        }
    }
}

#[derive(Debug, Error)]
#[error("state and payload phases do not match (state: {state_phase}, payload: {payload_phase})")]
pub struct StatePhaseError {
    state_phase: Phase,
    payload_phase: Phase,
}

#[derive(Debug, Error)]
#[error("block and payload phases do not match (block: {block_phase}, payload: {payload_phase})")]
pub struct BlockPhaseError {
    block_phase: Phase,
    payload_phase: Phase,
}

#[cfg(test)]
mod spec_tests {
    use spec_test_utils::Case;
    use test_generator::test_resources;

    use crate::preset::{Mainnet, Minimal};

    use super::*;

    #[duplicate_item(
        glob                                                                              function_name                           combined_type       preset    test_phase;
        ["consensus-spec-tests/tests/mainnet/phase0/ssz_static/BeaconState/*/*"]          [phase0_mainnet_beacon_state]           [BeaconState]       [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/ssz_static/BeaconState/*/*"]          [phase0_minimal_beacon_state]           [BeaconState]       [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/phase0/ssz_static/SignedBeaconBlock/*/*"]    [phase0_mainnet_signed_beacon_block]    [SignedBeaconBlock] [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/ssz_static/SignedBeaconBlock/*/*"]    [phase0_minimal_signed_beacon_block]    [SignedBeaconBlock] [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/phase0/ssz_static/Attestation/*/*"]          [phase0_mainnet_attestation]            [Attestation]       [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/ssz_static/Attestation/*/*"]          [phase0_minimal_attestation]            [Attestation]       [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/BeaconState/*/*"]          [altair_mainnet_beacon_state]           [BeaconState]       [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/BeaconState/*/*"]          [altair_minimal_beacon_state]           [BeaconState]       [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/SignedBeaconBlock/*/*"]    [altair_mainnet_signed_beacon_block]    [SignedBeaconBlock] [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/SignedBeaconBlock/*/*"]    [altair_minimal_signed_beacon_block]    [SignedBeaconBlock] [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/Attestation/*/*"]          [altair_mainnet_attestation]            [Attestation]       [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/Attestation/*/*"]          [altair_minimal_attestation]            [Attestation]       [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/BeaconState/*/*"]       [bellatrix_mainnet_beacon_state]        [BeaconState]       [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/BeaconState/*/*"]       [bellatrix_minimal_beacon_state]        [BeaconState]       [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/SignedBeaconBlock/*/*"] [bellatrix_mainnet_signed_beacon_block] [SignedBeaconBlock] [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/SignedBeaconBlock/*/*"] [bellatrix_minimal_signed_beacon_block] [SignedBeaconBlock] [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/Attestation/*/*"]       [bellatrix_mainnet_attestation]         [Attestation]       [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/Attestation/*/*"]       [bellatrix_minimal_attestation]         [Attestation]       [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/BeaconState/*/*"]         [capella_mainnet_beacon_state]          [BeaconState]       [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/BeaconState/*/*"]         [capella_minimal_beacon_state]          [BeaconState]       [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/SignedBeaconBlock/*/*"]   [capella_mainnet_signed_beacon_block]   [SignedBeaconBlock] [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/SignedBeaconBlock/*/*"]   [capella_minimal_signed_beacon_block]   [SignedBeaconBlock] [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/Attestation/*/*"]         [capella_mainnet_attestation]           [Attestation]       [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/Attestation/*/*"]         [capella_minimal_attestation]           [Attestation]       [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/BeaconState/*/*"]           [deneb_mainnet_beacon_state]            [BeaconState]       [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/BeaconState/*/*"]           [deneb_minimal_beacon_state]            [BeaconState]       [Minimal] [Deneb];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/SignedBeaconBlock/*/*"]     [deneb_mainnet_signed_beacon_block]     [SignedBeaconBlock] [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/SignedBeaconBlock/*/*"]     [deneb_minimal_signed_beacon_block]     [SignedBeaconBlock] [Minimal] [Deneb];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/Attestation/*/*"]           [deneb_mainnet_attestation]             [Attestation]       [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/Attestation/*/*"]           [deneb_minimal_attestation]             [Attestation]       [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/electra/ssz_static/BeaconState/*/*"]         [electra_mainnet_beacon_state]          [BeaconState]       [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/ssz_static/BeaconState/*/*"]         [electra_minimal_beacon_state]          [BeaconState]       [Minimal] [Electra];
        ["consensus-spec-tests/tests/mainnet/electra/ssz_static/SignedBeaconBlock/*/*"]   [electra_mainnet_signed_beacon_block]   [SignedBeaconBlock] [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/ssz_static/SignedBeaconBlock/*/*"]   [electra_minimal_signed_beacon_block]   [SignedBeaconBlock] [Minimal] [Electra];
        ["consensus-spec-tests/tests/mainnet/electra/ssz_static/Attestation/*/*"]         [electra_mainnet_attestation]           [Attestation]       [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/ssz_static/Attestation/*/*"]         [electra_minimal_attestation]           [Attestation]       [Minimal] [Electra];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let config = preset::default_config().start_and_stay_in(Phase::test_phase);
        let expected_ssz_bytes = case.bytes("serialized.ssz_snappy");

        let value = combined_type::<preset>::from_ssz(&config, expected_ssz_bytes.as_slice())
            .expect("SSZ decoding should succeed");

        let actual_ssz_bytes = value.to_ssz().expect("SSZ encoding should succeed");

        assert_eq!(actual_ssz_bytes, expected_ssz_bytes);
        assert_eq!(value.phase(), Phase::test_phase);
    }

    #[duplicate_item(
        glob                                                                                        function_name                         combined_type                 preset    phase;
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/LightClientBootstrap/*/*"]           [altair_mainnet_boostrap]             [LightClientBootstrap]        [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/LightClientBootstrap/*/*"]           [altair_minimal_bootstrap]            [LightClientBootstrap]        [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/LightClientFinalityUpdate/*/*"]      [altair_mainnet_finality_update]      [LightClientFinalityUpdate]   [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/LightClientFinalityUpdate/*/*"]      [altair_minimal_finality_update]      [LightClientFinalityUpdate]   [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/LightClientOptimisticUpdate/*/*"]    [altair_mainnet_optimistic_update]    [LightClientOptimisticUpdate] [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/LightClientOptimisticUpdate/*/*"]    [altair_minimal_optimistic_update]    [LightClientOptimisticUpdate] [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/LightClientBootstrap/*/*"]        [bellatrix_mainnet_bootstrap]         [LightClientBootstrap]        [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/LightClientBootstrap/*/*"]        [bellatrix_minimal_bootstrap]         [LightClientBootstrap]        [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/LightClientFinalityUpdate/*/*"]   [bellatrix_mainnet_finality_update]   [LightClientFinalityUpdate]   [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/LightClientFinalityUpdate/*/*"]   [bellatrix_minimal_finality_update]   [LightClientFinalityUpdate]   [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/LightClientOptimisticUpdate/*/*"] [bellatrix_mainnet_optimistic_update] [LightClientOptimisticUpdate] [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/LightClientOptimisticUpdate/*/*"] [bellatrix_minimal_optimistic_update] [LightClientOptimisticUpdate] [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/LightClientBootstrap/*/*"]          [capella_mainnet_bootstrap]           [LightClientBootstrap]        [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/LightClientBootstrap/*/*"]          [capella_minimal_bootstrap]           [LightClientBootstrap]        [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/LightClientFinalityUpdate/*/*"]     [capella_mainnet_finality_update]     [LightClientFinalityUpdate]   [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/LightClientFinalityUpdate/*/*"]     [capella_minimal_finality_update]     [LightClientFinalityUpdate]   [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/LightClientOptimisticUpdate/*/*"]   [capella_mainnet_optimistic_update]   [LightClientOptimisticUpdate] [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/LightClientOptimisticUpdate/*/*"]   [capella_minimal_optimistic_update]   [LightClientOptimisticUpdate] [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/LightClientBootstrap/*/*"]            [deneb_mainnet_bootstrap]             [LightClientBootstrap]        [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/LightClientBootstrap/*/*"]            [deneb_minimal_bootstrap]             [LightClientBootstrap]        [Minimal] [Deneb];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/LightClientFinalityUpdate/*/*"]       [deneb_mainnet_finality_update]       [LightClientFinalityUpdate]   [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/LightClientFinalityUpdate/*/*"]       [deneb_minimal_finality_update]       [LightClientFinalityUpdate]   [Minimal] [Deneb];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/LightClientOptimisticUpdate/*/*"]     [deneb_mainnet_optimistic_update]     [LightClientOptimisticUpdate] [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/LightClientOptimisticUpdate/*/*"]     [deneb_minimal_optimistic_update]     [LightClientOptimisticUpdate] [Minimal] [Deneb];
        ["consensus-spec-tests/tests/mainnet/electra/ssz_static/LightClientBootstrap/*/*"]          [electra_mainnet_bootstrap]           [LightClientBootstrap]        [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/ssz_static/LightClientBootstrap/*/*"]          [electra_minimal_bootstrap]           [LightClientBootstrap]        [Minimal] [Electra];
        ["consensus-spec-tests/tests/mainnet/electra/ssz_static/LightClientFinalityUpdate/*/*"]     [electra_mainnet_finality_update]     [LightClientFinalityUpdate]   [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/ssz_static/LightClientFinalityUpdate/*/*"]     [electra_minimal_finality_update]     [LightClientFinalityUpdate]   [Minimal] [Electra];
        ["consensus-spec-tests/tests/mainnet/electra/ssz_static/LightClientOptimisticUpdate/*/*"]   [electra_mainnet_optimistic_update]   [LightClientOptimisticUpdate] [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/ssz_static/LightClientOptimisticUpdate/*/*"]   [electra_minimal_optimistic_update]   [LightClientOptimisticUpdate] [Minimal] [Electra];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let expected_ssz_bytes = case.bytes("serialized.ssz_snappy");

        let phase_specific_value = SszReadDefault::from_ssz_default(expected_ssz_bytes.as_slice())
            .expect("SSZ decoding should succeed");

        let combined_value = combined_type::<preset>::phase(Box::new(phase_specific_value));

        let actual_ssz_bytes = combined_value
            .to_ssz()
            .expect("SSZ encoding should succeed");

        assert_eq!(actual_ssz_bytes, expected_ssz_bytes);
    }

    #[duplicate_item(
        glob                                                                             function_name                         preset    phase;
        ["consensus-spec-tests/tests/mainnet/phase0/ssz_static/AttesterSlashing/*/*"]    [phase0_mainnet_attester_slashing]    [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/phase0/ssz_static/AttesterSlashing/*/*"]    [phase0_minimal_attester_slashing]    [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/AttesterSlashing/*/*"]    [altair_mainnet_attester_slashing]    [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/AttesterSlashing/*/*"]    [altair_minimal_attester_slashing]    [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/AttesterSlashing/*/*"] [bellatrix_mainnet_attester_slashing] [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/AttesterSlashing/*/*"] [bellatrix_minimal_attester_slashing] [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/AttesterSlashing/*/*"]   [capella_mainnet_attester_slashing]   [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/AttesterSlashing/*/*"]   [capella_minimal_attester_slashing]   [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/AttesterSlashing/*/*"]     [deneb_mainnet_attester_slashing]     [Mainnet] [Phase0];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/AttesterSlashing/*/*"]     [deneb_minimal_attester_slashing]     [Minimal] [Phase0];
        ["consensus-spec-tests/tests/mainnet/electra/ssz_static/AttesterSlashing/*/*"]   [electra_mainnet_attester_slashing]   [Mainnet] [Electra];
        ["consensus-spec-tests/tests/minimal/electra/ssz_static/AttesterSlashing/*/*"]   [electra_minimal_attester_slashing]   [Minimal] [Electra];
    )]
    #[test_resources(glob)]
    fn function_name(case: Case) {
        let expected_ssz_bytes = case.bytes("serialized.ssz_snappy");

        let phase_specific_value = SszReadDefault::from_ssz_default(expected_ssz_bytes.as_slice())
            .expect("SSZ decoding should succeed");

        let combined_value = AttesterSlashing::<preset>::phase(phase_specific_value);

        let actual_ssz_bytes = combined_value
            .to_ssz()
            .expect("SSZ encoding should succeed");

        assert_eq!(actual_ssz_bytes, expected_ssz_bytes);
    }
}

#[cfg(test)]
mod extra_tests {
    use serde_json::{json, Result, Value};
    use test_case::test_case;

    use crate::preset::Mainnet;

    use super::*;

    #[test_case(
        json!({
            "version": "bellatrix",
            "data": {
                "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "block_number": "1",
                "gas_limit": "1",
                "gas_used": "1",
                "timestamp": "1",
                "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "base_fee_per_gas": "1",
                "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "transactions": [
                    "0x02f878831469668303f51d843b9ac9f9843b9aca0082520894c93269b73096998db66be0441e836d873535cb9c8894a19041886f000080c001a031cc29234036afbf9a1fb9476b463367cb1f957ac0b919b69bbc798436e604aaa018c4e9c3914eb27aadd0b91e10b18655739fcf8c1fc398763a9f1beecb8ddc86",
                ],
            },
        }),
        Phase::Bellatrix;
        "https://github.com/ethereum/builder-specs/blob/v0.3.0/examples/bellatrix/execution_payload.json"
    )]
    #[test_case(
        json!({
            "version": "capella",
            "data": {
                "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "block_number": "1",
                "gas_limit": "1",
                "gas_used": "1",
                "timestamp": "1",
                "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "base_fee_per_gas": "1",
                "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                "transactions": [
                    "0x02f878831469668303f51d843b9ac9f9843b9aca0082520894c93269b73096998db66be0441e836d873535cb9c8894a19041886f000080c001a031cc29234036afbf9a1fb9476b463367cb1f957ac0b919b69bbc798436e604aaa018c4e9c3914eb27aadd0b91e10b18655739fcf8c1fc398763a9f1beecb8ddc86",
                ],
                "withdrawals": [
                    {
                        "index": "1",
                        "validator_index": "1",
                        "address": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
                        "amount": "32000000000",
                    },
                ],
            },
        }),
        Phase::Capella;
        "https://github.com/ethereum/builder-specs/blob/v0.3.0/examples/capella/execution_payload.json"
    )]
    fn deserializes_execution_payload_example(json: Value, expected_phase: Phase) -> Result<()> {
        let response = serde_json::from_value::<ExecutionPayload<Mainnet>>(json)?;
        assert_eq!(response.phase(), expected_phase);
        Ok(())
    }
}
