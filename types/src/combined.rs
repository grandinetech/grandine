use bls::SignatureBytes;
use derive_more::From;
use duplicate::duplicate_item;
use enum_iterator::Sequence as _;
use serde::{Deserialize, Serialize};
use ssz::{
    ContiguousList, Hc, Offset, ReadError, Size, SszHash, SszRead, SszReadDefault, SszSize,
    SszWrite, WriteError, H256,
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
    nonstandard::Phase,
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        containers::{
            BeaconBlock as Phase0BeaconBlock, SignedBeaconBlock as Phase0SignedBeaconBlock,
            SignedBeaconBlockHeader,
        },
        primitives::{ExecutionBlockHash, ExecutionBlockNumber, Slot, UnixSeconds},
    },
    preset::{Mainnet, Preset},
    traits::{
        BeaconBlock as _, BeaconState as _, ExecutionPayload as ExecutionPayloadTrait,
        PostAltairBeaconState, PostBellatrixBeaconState, PostCapellaBeaconState,
        SignedBeaconBlock as _,
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
            (_, header) => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 5);

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
        }
    }

    pub fn post_altair_mut(&mut self) -> Option<&mut dyn PostAltairBeaconState<P>> {
        match self {
            Self::Phase0(_) => None,
            Self::Altair(state) => Some(state),
            Self::Bellatrix(state) => Some(state),
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
        }
    }

    pub const fn post_bellatrix(&self) -> Option<&dyn PostBellatrixBeaconState<P>> {
        match self {
            Self::Phase0(_) | Self::Altair(_) => None,
            Self::Bellatrix(state) => Some(state),
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
        }
    }

    pub fn post_bellatrix_mut(&mut self) -> Option<&mut dyn PostBellatrixBeaconState<P>> {
        match self {
            Self::Phase0(_) | Self::Altair(_) => None,
            Self::Bellatrix(state) => Some(state),
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
        }
    }

    pub const fn post_capella(&self) -> Option<&dyn PostCapellaBeaconState<P>> {
        match self {
            Self::Phase0(_) | Self::Altair(_) | Self::Bellatrix(_) => None,
            Self::Capella(state) => Some(state),
            Self::Deneb(state) => Some(state),
        }
    }

    pub fn set_cached_root(&self, root: H256) {
        match self {
            Self::Phase0(state) => state.set_cached_root(root),
            Self::Altair(state) => state.set_cached_root(root),
            Self::Bellatrix(state) => state.set_cached_root(root),
            Self::Capella(state) => state.set_cached_root(root),
            Self::Deneb(state) => state.set_cached_root(root),
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
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Phase0(_) => Phase::Phase0,
            Self::Altair(_) => Phase::Altair,
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
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
            (_, payload) => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 5);

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
            _ => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 5);
            }
        }

        self
    }

    pub fn into_blinded(
        self,
        execution_payload_header: ExecutionPayloadHeader<P>,
        kzg_commitments: Option<ContiguousList<KzgCommitment, P::MaxBlobCommitmentsPerBlock>>,
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
            (block, header) => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 5);

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
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Phase0(_) => Phase::Phase0,
            Self::Altair(_) => Phase::Altair,
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
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
}

impl<P: Preset> SszSize for SignedBlindedBeaconBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        BellatrixSignedBlindedBeaconBlock::<P>::SIZE,
        CapellaSignedBlindedBeaconBlock::<P>::SIZE,
        DenebSignedBlindedBeaconBlock::<P>::SIZE,
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
        }
    }

    pub const fn phase(&self) -> Phase {
        match self {
            Self::Bellatrix(_) => Phase::Bellatrix,
            Self::Capella(_) => Phase::Capella,
            Self::Deneb(_) => Phase::Deneb,
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
}

impl<P: Preset> SszSize for BlindedBeaconBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        BellatrixBlindedBeaconBlock::<P>::SIZE,
        CapellaBlindedBeaconBlock::<P>::SIZE,
        DenebSignedBlindedBeaconBlock::<P>::SIZE,
    ]);
}

impl<P: Preset> SszWrite for BlindedBeaconBlock<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Bellatrix(block) => block.write_variable(bytes),
            Self::Capella(block) => block.write_variable(bytes),
            Self::Deneb(block) => block.write_variable(bytes),
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
        }
    }

    #[must_use]
    pub fn with_state_root(mut self, state_root: H256) -> Self {
        match &mut self {
            Self::Bellatrix(block) => block.state_root = state_root,
            Self::Capella(block) => block.state_root = state_root,
            Self::Deneb(block) => block.state_root = state_root,
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
            (block, payload) => {
                // This match arm will silently match any new phases.
                // Cause a compilation error if a new phase is added.
                const_assert_eq!(Phase::CARDINALITY, 5);

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
pub enum ExecutionPayloadParams {
    Deneb {
        versioned_hashes: Vec<VersionedHash>,
        parent_beacon_block_root: H256,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LightClientBootstrap<P: Preset> {
    Altair(Box<AltairLightClientBootstrap<P>>),
    Capella(Box<CapellaLightClientBootstrap<P>>),
    Deneb(Box<DenebLightClientBootstrap<P>>),
}

impl<P: Preset> SszSize for LightClientBootstrap<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 2 }>([
        AltairLightClientBootstrap::<P>::SIZE,
        CapellaLightClientBootstrap::<P>::SIZE,
        DenebLightClientBootstrap::<P>::SIZE,
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
        }
    }
}

impl<P: Preset> LightClientBootstrap<P> {
    #[must_use]
    pub fn slot(&self) -> Slot {
        match self {
            Self::Altair(bootstrap) => bootstrap.header.beacon.slot,
            Self::Capella(bootstrap) => bootstrap.header.beacon.slot,
            Self::Deneb(bootstrap) => bootstrap.header.beacon.slot,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LightClientFinalityUpdate<P: Preset> {
    // Boxed to pass `clippy::large_enum_variant`.
    Altair(Box<AltairLightClientFinalityUpdate<P>>),
    Capella(Box<CapellaLightClientFinalityUpdate<P>>),
    Deneb(Box<DenebLightClientFinalityUpdate<P>>),
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
        }
    }
}

impl<P: Preset> LightClientFinalityUpdate<P> {
    #[must_use]
    pub fn signature_slot(&self) -> Slot {
        match self {
            Self::Altair(update) => update.signature_slot,
            Self::Capella(update) => update.signature_slot,
            Self::Deneb(update) => update.signature_slot,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LightClientOptimisticUpdate<P: Preset> {
    // Boxed to pass `clippy::large_enum_variant`.
    Altair(Box<AltairLightClientOptimisticUpdate<P>>),
    Capella(Box<CapellaLightClientOptimisticUpdate<P>>),
    Deneb(Box<DenebLightClientOptimisticUpdate<P>>),
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
        }
    }
}

impl<P: Preset> LightClientOptimisticUpdate<P> {
    #[must_use]
    pub fn signature_slot(&self) -> Slot {
        match self {
            Self::Altair(update) => update.signature_slot,
            Self::Capella(update) => update.signature_slot,
            Self::Deneb(update) => update.signature_slot,
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
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/BeaconState/*/*"]          [altair_mainnet_beacon_state]           [BeaconState]       [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/BeaconState/*/*"]          [altair_minimal_beacon_state]           [BeaconState]       [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/altair/ssz_static/SignedBeaconBlock/*/*"]    [altair_mainnet_signed_beacon_block]    [SignedBeaconBlock] [Mainnet] [Altair];
        ["consensus-spec-tests/tests/minimal/altair/ssz_static/SignedBeaconBlock/*/*"]    [altair_minimal_signed_beacon_block]    [SignedBeaconBlock] [Minimal] [Altair];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/BeaconState/*/*"]       [bellatrix_mainnet_beacon_state]        [BeaconState]       [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/BeaconState/*/*"]       [bellatrix_minimal_beacon_state]        [BeaconState]       [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/bellatrix/ssz_static/SignedBeaconBlock/*/*"] [bellatrix_mainnet_signed_beacon_block] [SignedBeaconBlock] [Mainnet] [Bellatrix];
        ["consensus-spec-tests/tests/minimal/bellatrix/ssz_static/SignedBeaconBlock/*/*"] [bellatrix_minimal_signed_beacon_block] [SignedBeaconBlock] [Minimal] [Bellatrix];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/BeaconState/*/*"]         [capella_mainnet_beacon_state]          [BeaconState]       [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/BeaconState/*/*"]         [capella_minimal_beacon_state]          [BeaconState]       [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/capella/ssz_static/SignedBeaconBlock/*/*"]   [capella_mainnet_signed_beacon_block]   [SignedBeaconBlock] [Mainnet] [Capella];
        ["consensus-spec-tests/tests/minimal/capella/ssz_static/SignedBeaconBlock/*/*"]   [capella_minimal_signed_beacon_block]   [SignedBeaconBlock] [Minimal] [Capella];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/BeaconState/*/*"]           [deneb_mainnet_beacon_state]            [BeaconState]       [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/BeaconState/*/*"]           [deneb_minimal_beacon_state]            [BeaconState]       [Minimal] [Deneb];
        ["consensus-spec-tests/tests/mainnet/deneb/ssz_static/SignedBeaconBlock/*/*"]     [deneb_mainnet_signed_beacon_block]     [SignedBeaconBlock] [Mainnet] [Deneb];
        ["consensus-spec-tests/tests/minimal/deneb/ssz_static/SignedBeaconBlock/*/*"]     [deneb_minimal_signed_beacon_block]     [SignedBeaconBlock] [Minimal] [Deneb];
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
