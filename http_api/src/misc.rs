use core::sync::atomic::{AtomicBool, Ordering};

use block_producer::ValidatorBlindedBlock;
use enum_iterator::Sequence as _;
use serde::{Deserialize, Serialize};
use ssz::{
    ContiguousList, ReadError, Size, Ssz, SszHash, SszRead, SszReadDefault, SszSize, SszWrite,
    WriteError,
};
use types::{
    altair::containers::SignedBeaconBlock as AltairSignedBeaconBlock,
    bellatrix::containers::SignedBeaconBlock as BellatrixSignedBeaconBlock,
    capella::containers::SignedBeaconBlock as CapellaSignedBeaconBlock,
    combined::{Attestation, BeaconBlock, SignedBeaconBlock},
    deneb::{
        containers::SignedBeaconBlock as DenebSignedBeaconBlock,
        primitives::{Blob, KzgProofs},
    },
    electra::containers::{SignedBeaconBlock as ElectraSignedBeaconBlock, SingleAttestation},
    fulu::containers::SignedBeaconBlock as FuluSignedBeaconBlock,
    nonstandard::{Phase, WithBlobsAndMev},
    phase0::containers::{
        Attestation as Phase0Attestation, SignedBeaconBlock as Phase0SignedBeaconBlock,
    },
    preset::Preset,
};

#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use ::{
    crossbeam_utils::sync::WaitGroup,
    eth1_api::ApiController,
    futures::{channel::mpsc::UnboundedReceiver, lock::Mutex},
};

const ORDERING: Ordering = Ordering::SeqCst;

#[cfg(test)]
pub type TestApiController<P> = ApiController<P, WaitGroup>;

#[cfg(test)]
pub type SpyReceiver<T> = Arc<Mutex<UnboundedReceiver<T>>>;

#[derive(Default)]
pub struct SyncedStatus(AtomicBool);

impl SyncedStatus {
    pub const fn new(value: bool) -> Self {
        Self(AtomicBool::new(value))
    }

    pub fn get(&self) -> bool {
        self.0.load(ORDERING)
    }

    pub fn set(&self, value: bool) {
        self.0.store(value, ORDERING);
    }
}

pub type SignedBeaconBlockWithBlobsAndProofs<P> = (
    SignedBeaconBlock<P>,
    KzgProofs<P>,
    ContiguousList<Blob<P>, <P as Preset>::MaxBlobCommitmentsPerBlock>,
);

#[derive(Deserialize, Ssz)]
#[serde(bound = "")]
pub struct SignedDenebBlockWithBlobs<P: Preset> {
    pub signed_block: DenebSignedBeaconBlock<P>,
    pub kzg_proofs: KzgProofs<P>,
    pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

#[derive(Deserialize, Ssz)]
#[serde(bound = "")]
pub struct SignedElectraBlockWithBlobs<P: Preset> {
    pub signed_block: ElectraSignedBeaconBlock<P>,
    pub kzg_proofs: KzgProofs<P>,
    pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

#[derive(Deserialize, Ssz)]
#[serde(bound = "")]
pub struct SignedFuluBlockWithBlobs<P: Preset> {
    pub signed_block: FuluSignedBeaconBlock<P>,
    pub kzg_proofs: KzgProofs<P>,
    pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

#[derive(Serialize, Ssz)]
#[serde(bound = "")]
#[ssz(derive_read = false, derive_hash = false)]
pub struct BlockWithBlobs<B: Serialize + SszWrite, P: Preset> {
    pub block: B,
    pub kzg_proofs: KzgProofs<P>,
    pub blobs: ContiguousList<Blob<P>, P::MaxBlobCommitmentsPerBlock>,
}

#[derive(Serialize)]
#[serde(bound = "", untagged)]
pub enum APIBlock<B: Serialize + SszWrite, P: Preset> {
    Other(B),
    WithBlobs(BlockWithBlobs<B, P>),
}

impl<B: Serialize + SszWrite, P: Preset> SszSize for APIBlock<B, P> {
    const SIZE: Size = BlockWithBlobs::<B, P>::SIZE;
}

impl<B: Serialize + SszWrite + SszHash, P: Preset> SszWrite for APIBlock<B, P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::Other(block) => block.write_variable(bytes),
            Self::WithBlobs(block) => block.write_variable(bytes),
        }
    }
}

impl<P: Preset> From<WithBlobsAndMev<BeaconBlock<P>, P>> for APIBlock<BeaconBlock<P>, P> {
    fn from(block: WithBlobsAndMev<BeaconBlock<P>, P>) -> Self {
        let WithBlobsAndMev {
            value: combined_block,
            proofs,
            blobs,
            ..
        } = block;

        match combined_block {
            BeaconBlock::Phase0(block) => Self::Other(block.into()),
            BeaconBlock::Altair(block) => Self::Other(block.into()),
            BeaconBlock::Bellatrix(block) => Self::Other(block.into()),
            BeaconBlock::Capella(block) => Self::Other(block.into()),
            BeaconBlock::Deneb(block) => Self::WithBlobs(BlockWithBlobs {
                block: block.into(),
                kzg_proofs: proofs.unwrap_or_default(),
                blobs: blobs.unwrap_or_default(),
            }),
            BeaconBlock::Electra(block) => Self::WithBlobs(BlockWithBlobs {
                block: block.into(),
                kzg_proofs: proofs.unwrap_or_default(),
                blobs: blobs.unwrap_or_default(),
            }),
            BeaconBlock::Fulu(block) => Self::WithBlobs(BlockWithBlobs {
                block: block.into(),
                kzg_proofs: proofs.unwrap_or_default(),
                blobs: blobs.unwrap_or_default(),
            }),
        }
    }
}

impl<P: Preset> From<WithBlobsAndMev<ValidatorBlindedBlock<P>, P>>
    for APIBlock<ValidatorBlindedBlock<P>, P>
{
    fn from(block: WithBlobsAndMev<ValidatorBlindedBlock<P>, P>) -> Self {
        let WithBlobsAndMev {
            value: validator_blinded_block,
            proofs,
            blobs,
            ..
        } = block;

        match validator_blinded_block {
            ValidatorBlindedBlock::BlindedBeaconBlock {
                blinded_block,
                execution_payload,
            } => Self::Other(ValidatorBlindedBlock::BlindedBeaconBlock {
                blinded_block,
                execution_payload,
            }),
            ValidatorBlindedBlock::BeaconBlock(combined_block) => match combined_block {
                BeaconBlock::Phase0(block) => {
                    Self::Other(ValidatorBlindedBlock::BeaconBlock(block.into()))
                }
                BeaconBlock::Altair(block) => {
                    Self::Other(ValidatorBlindedBlock::BeaconBlock(block.into()))
                }
                BeaconBlock::Bellatrix(block) => {
                    Self::Other(ValidatorBlindedBlock::BeaconBlock(block.into()))
                }
                BeaconBlock::Capella(block) => {
                    Self::Other(ValidatorBlindedBlock::BeaconBlock(block.into()))
                }
                BeaconBlock::Deneb(block) => Self::WithBlobs(BlockWithBlobs {
                    block: ValidatorBlindedBlock::BeaconBlock(block.into()),
                    kzg_proofs: proofs.unwrap_or_default(),
                    blobs: blobs.unwrap_or_default(),
                }),
                BeaconBlock::Electra(block) => Self::WithBlobs(BlockWithBlobs {
                    block: ValidatorBlindedBlock::BeaconBlock(block.into()),
                    kzg_proofs: proofs.unwrap_or_default(),
                    blobs: blobs.unwrap_or_default(),
                }),
                BeaconBlock::Fulu(block) => Self::WithBlobs(BlockWithBlobs {
                    block: ValidatorBlindedBlock::BeaconBlock(block.into()),
                    kzg_proofs: proofs.unwrap_or_default(),
                    blobs: blobs.unwrap_or_default(),
                }),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(bound = "", untagged)]
pub enum SingleApiAttestation<P: Preset> {
    Phase0(Phase0Attestation<P>),
    Electra(SingleAttestation),
}

impl<P: Preset> SszSize for SingleApiAttestation<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY - 4 }>([
        Phase0Attestation::<P>::SIZE,
        SingleAttestation::SIZE,
    ]);
}

impl<P: Preset> SszRead<Phase> for SingleApiAttestation<P> {
    fn from_ssz_unchecked(phase: &Phase, bytes: &[u8]) -> Result<Self, ReadError> {
        let api_attestation = match phase {
            Phase::Phase0 | Phase::Altair | Phase::Bellatrix | Phase::Capella | Phase::Deneb => {
                Self::Phase0(SszReadDefault::from_ssz_default(bytes)?)
            }
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
        };

        Ok(api_attestation)
    }
}

impl<P: Preset> From<SingleApiAttestation<P>> for Attestation<P> {
    fn from(single_api_attestation: SingleApiAttestation<P>) -> Self {
        match single_api_attestation {
            SingleApiAttestation::Phase0(attestation) => Self::Phase0(attestation),
            SingleApiAttestation::Electra(attestation) => Self::Single(attestation),
        }
    }
}

#[derive(Deserialize)]
#[serde(bound = "", untagged)]
pub enum SignedAPIBlock<P: Preset> {
    Phase0(Phase0SignedBeaconBlock<P>),
    Altair(AltairSignedBeaconBlock<P>),
    Bellatrix(BellatrixSignedBeaconBlock<P>),
    Capella(CapellaSignedBeaconBlock<P>),
    Deneb(SignedDenebBlockWithBlobs<P>),
    Electra(SignedElectraBlockWithBlobs<P>),
    Fulu(SignedFuluBlockWithBlobs<P>),
}

impl<P: Preset> SignedAPIBlock<P> {
    pub fn split(self) -> SignedBeaconBlockWithBlobsAndProofs<P> {
        match self {
            Self::Phase0(block) => (
                block.into(),
                ContiguousList::default(),
                ContiguousList::default(),
            ),
            Self::Altair(block) => (
                block.into(),
                ContiguousList::default(),
                ContiguousList::default(),
            ),
            Self::Bellatrix(block) => (
                block.into(),
                ContiguousList::default(),
                ContiguousList::default(),
            ),
            Self::Capella(block) => (
                block.into(),
                ContiguousList::default(),
                ContiguousList::default(),
            ),
            Self::Deneb(block) => {
                let SignedDenebBlockWithBlobs {
                    signed_block,
                    kzg_proofs,
                    blobs,
                } = block;

                (signed_block.into(), kzg_proofs, blobs)
            }
            Self::Electra(block) => {
                let SignedElectraBlockWithBlobs {
                    signed_block,
                    kzg_proofs,
                    blobs,
                } = block;

                (signed_block.into(), kzg_proofs, blobs)
            }
            Self::Fulu(block) => {
                let SignedFuluBlockWithBlobs {
                    signed_block,
                    kzg_proofs,
                    blobs,
                } = block;

                (signed_block.into(), kzg_proofs, blobs)
            }
        }
    }
}

impl<P: Preset> SszSize for SignedAPIBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size = Size::for_untagged_union::<{ Phase::CARDINALITY }>([
        Phase0SignedBeaconBlock::<P>::SIZE,
        AltairSignedBeaconBlock::<P>::SIZE,
        BellatrixSignedBeaconBlock::<P>::SIZE,
        CapellaSignedBeaconBlock::<P>::SIZE,
        SignedDenebBlockWithBlobs::<P>::SIZE,
        SignedElectraBlockWithBlobs::<P>::SIZE,
        SignedFuluBlockWithBlobs::<P>::SIZE,
    ]);
}

impl<P: Preset> SszRead<Phase> for SignedAPIBlock<P> {
    fn from_ssz_unchecked(phase: &Phase, bytes: &[u8]) -> Result<Self, ReadError> {
        let api_block = match phase {
            Phase::Phase0 => Self::Phase0(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Altair => Self::Altair(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Bellatrix => Self::Bellatrix(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Capella => Self::Capella(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Deneb => Self::Deneb(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Electra => Self::Electra(SszReadDefault::from_ssz_default(bytes)?),
            Phase::Fulu => Self::Fulu(SszReadDefault::from_ssz_default(bytes)?),
        };

        Ok(api_block)
    }
}

#[derive(PartialEq, Eq, Default, Deserialize)]
#[serde(bound = "", rename_all = "snake_case")]
pub enum BroadcastValidation {
    #[default]
    Gossip,
    Consensus,
    ConsensusAndEquivocation,
}
