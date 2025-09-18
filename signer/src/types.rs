use core::marker::PhantomData;

use bls::PublicKeyBytes;
use builder_api::unphased::containers::ValidatorRegistrationV1;
use serde::Serialize;
use types::{
    altair::containers::{
        BeaconBlock as AltairBeaconBlock, ContributionAndProof, SyncAggregatorSelectionData,
    },
    bellatrix::containers::BeaconBlock as BellatrixBeaconBlock,
    capella::containers::BeaconBlock as CapellaBeaconBlock,
    combined::{
        AggregateAndProof, BeaconBlock as CombinedBeaconBlock,
        BlindedBeaconBlock as CombinedBlindedBeaconBlock,
    },
    deneb::containers::{
        BeaconBlock as DenebBeaconBlock, BlindedBeaconBlock as DenebBlindedBeaconBlock,
    },
    electra::containers::{
        BeaconBlock as ElectraBeaconBlock, BlindedBeaconBlock as ElectraBlindedBeaconBlock,
    },
    fulu::containers::{
        BeaconBlock as FuluBeaconBlock, BlindedBeaconBlock as FuluBlindedBeaconBlock,
    },
    gloas::containers::BeaconBlock as GloasBeaconBlock,
    phase0::{
        containers::{
            AttestationData, BeaconBlock as Phase0BeaconBlock, BeaconBlockHeader, Fork,
            VoluntaryExit,
        },
        primitives::{Epoch, Slot, H256},
    },
    preset::Preset,
    traits::{BeaconBlock as _, BeaconState},
};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ForkInfo<P: Preset> {
    pub fork: Fork,
    pub genesis_validators_root: H256,
    #[serde(skip)]
    pub phantom: PhantomData<P>,
}

impl<P: Preset, BS: BeaconState<P>> From<&BS> for ForkInfo<P> {
    fn from(state: &BS) -> Self {
        Self {
            fork: state.fork(),
            genesis_validators_root: state.genesis_validators_root(),
            phantom: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct SigningTriple<'block, P: Preset> {
    pub message: SigningMessage<'block, P>,
    pub signing_root: H256,
    pub public_key: PublicKeyBytes,
}

#[derive(Debug, Serialize)]
#[serde(bound = "", rename_all = "snake_case")]
pub enum SigningMessage<'block, P: Preset> {
    AggregationSlot {
        #[serde(with = "serde_utils::string_or_native")]
        slot: Slot,
    },
    AggregateAndProof(Box<AggregateAndProof<P>>),
    Attestation(AttestationData),
    BeaconBlock(SigningBlock<'block, P>),
    RandaoReveal {
        #[serde(with = "serde_utils::string_or_native")]
        epoch: Epoch,
    },
    SyncCommitteeMessage {
        beacon_block_root: H256,
        #[serde(with = "serde_utils::string_or_native")]
        slot: Slot,
    },
    SyncAggregatorSelectionData(SyncAggregatorSelectionData),
    ContributionAndProof(ContributionAndProof<P>),
    ValidatorRegistration(ValidatorRegistrationV1),
    VoluntaryExit(VoluntaryExit),
}

impl<'block, P: Preset> From<&'block Phase0BeaconBlock<P>> for SigningMessage<'block, P> {
    fn from(block: &'block Phase0BeaconBlock<P>) -> Self {
        Self::BeaconBlock(SigningBlock::Phase0 { block })
    }
}

impl<'block, P: Preset> From<&'block AltairBeaconBlock<P>> for SigningMessage<'block, P> {
    fn from(block: &'block AltairBeaconBlock<P>) -> Self {
        Self::BeaconBlock(SigningBlock::Altair { block })
    }
}

impl<P: Preset> From<&BellatrixBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(block: &BellatrixBeaconBlock<P>) -> Self {
        let block_header = block.to_header();
        Self::BeaconBlock(SigningBlock::Bellatrix { block_header })
    }
}

impl<P: Preset> From<&CapellaBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(block: &CapellaBeaconBlock<P>) -> Self {
        let block_header = block.to_header();
        Self::BeaconBlock(SigningBlock::Capella { block_header })
    }
}

impl<P: Preset> From<&DenebBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(block: &DenebBeaconBlock<P>) -> Self {
        let block_header = block.to_header();
        Self::BeaconBlock(SigningBlock::Deneb { block_header })
    }
}

impl<P: Preset> From<&DenebBlindedBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(blinded_block: &DenebBlindedBeaconBlock<P>) -> Self {
        let block_header = blinded_block.to_header();
        Self::BeaconBlock(SigningBlock::Deneb { block_header })
    }
}

impl<P: Preset> From<&ElectraBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(block: &ElectraBeaconBlock<P>) -> Self {
        let block_header = block.to_header();
        Self::BeaconBlock(SigningBlock::Electra { block_header })
    }
}

impl<P: Preset> From<&ElectraBlindedBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(blinded_block: &ElectraBlindedBeaconBlock<P>) -> Self {
        let block_header = blinded_block.to_header();
        Self::BeaconBlock(SigningBlock::Electra { block_header })
    }
}

impl<P: Preset> From<&FuluBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(block: &FuluBeaconBlock<P>) -> Self {
        let block_header = block.to_header();
        Self::BeaconBlock(SigningBlock::Fulu { block_header })
    }
}

impl<P: Preset> From<&FuluBlindedBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(blinded_block: &FuluBlindedBeaconBlock<P>) -> Self {
        let block_header = blinded_block.to_header();
        Self::BeaconBlock(SigningBlock::Fulu { block_header })
    }
}

impl<P: Preset> From<&GloasBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(block: &GloasBeaconBlock<P>) -> Self {
        let block_header = block.to_header();
        Self::BeaconBlock(SigningBlock::Gloas { block_header })
    }
}

impl<'block, P: Preset> From<&'block CombinedBeaconBlock<P>> for SigningMessage<'block, P> {
    fn from(block: &'block CombinedBeaconBlock<P>) -> Self {
        match block {
            CombinedBeaconBlock::Phase0(block) => block.into(),
            CombinedBeaconBlock::Altair(block) => block.into(),
            CombinedBeaconBlock::Bellatrix(block) => block.into(),
            CombinedBeaconBlock::Capella(block) => block.into(),
            CombinedBeaconBlock::Deneb(block) => block.into(),
            CombinedBeaconBlock::Electra(block) => block.into(),
            CombinedBeaconBlock::Fulu(block) => block.into(),
            CombinedBeaconBlock::Gloas(block) => block.into(),
        }
    }
}

impl<P: Preset> From<&CombinedBlindedBeaconBlock<P>> for SigningMessage<'_, P> {
    fn from(blinded_block: &CombinedBlindedBeaconBlock<P>) -> Self {
        match blinded_block {
            CombinedBlindedBeaconBlock::Bellatrix(blinded_block) => {
                let block_header = blinded_block.to_header();
                Self::BeaconBlock(SigningBlock::Bellatrix { block_header })
            }
            CombinedBlindedBeaconBlock::Capella(blinded_block) => {
                let block_header = blinded_block.to_header();
                Self::BeaconBlock(SigningBlock::Capella { block_header })
            }
            CombinedBlindedBeaconBlock::Deneb(blinded_block) => {
                let block_header = blinded_block.to_header();
                Self::BeaconBlock(SigningBlock::Deneb { block_header })
            }
            CombinedBlindedBeaconBlock::Electra(blinded_block) => {
                let block_header = blinded_block.to_header();
                Self::BeaconBlock(SigningBlock::Electra { block_header })
            }
            CombinedBlindedBeaconBlock::Fulu(blinded_block) => {
                let block_header = blinded_block.to_header();
                Self::BeaconBlock(SigningBlock::Fulu { block_header })
            }
        }
    }
}

// Web3Signer expects signing requests for Bellatrix and later phases to contain a `block_header`
// field instead of `block`. See:
// - <https://github.com/ConsenSys/web3signer/pull/547>
// - <https://github.com/ConsenSys/web3signer/blob/23.8.1/core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/signing/eth2/json/BlockRequestDeserializer.java#L58-L66>
// - <https://consensys.github.io/web3signer/web3signer-eth2.html?version=23.8.1#tag/Signing/operation/ETH2_SIGN>
#[derive(Debug, Serialize)]
#[serde(bound = "", rename_all = "UPPERCASE", tag = "version")]
pub enum SigningBlock<'block, P: Preset> {
    Phase0 { block: &'block Phase0BeaconBlock<P> },
    Altair { block: &'block AltairBeaconBlock<P> },
    Bellatrix { block_header: BeaconBlockHeader },
    Capella { block_header: BeaconBlockHeader },
    Deneb { block_header: BeaconBlockHeader },
    Electra { block_header: BeaconBlockHeader },
    Fulu { block_header: BeaconBlockHeader },
    Gloas { block_header: BeaconBlockHeader },
}

impl<P: Preset> SigningBlock<'_, P> {
    pub const fn slot(&self) -> Slot {
        match self {
            SigningBlock::Phase0 { block } => block.slot,
            SigningBlock::Altair { block } => block.slot,
            SigningBlock::Bellatrix { block_header }
            | SigningBlock::Capella { block_header }
            | SigningBlock::Deneb { block_header }
            | SigningBlock::Electra { block_header }
            | SigningBlock::Fulu { block_header }
            | SigningBlock::Gloas { block_header } => block_header.slot,
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;
    use types::preset::Minimal;

    use super::*;

    #[test]
    fn test_altair_block_serialization() -> Result<()> {
        let altair_block = AltairBeaconBlock::<Minimal>::default();
        let message = SigningMessage::from(&altair_block);

        assert_eq!(
            serde_json::to_value(&message)?,
            json!({
                "beacon_block": {
                    "version": "ALTAIR",
                    "block": {
                        "slot": "0",
                        "proposer_index": "0",
                        "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "body": {
                            "randao_reveal":
                                "0x00000000000000000000000000000000000000000000000000000000000000\
                                00000000000000000000000000000000000000000000000000000000000000000\
                                00000000000000000000000000000000000000000000000000000000000000000",
                            "eth1_data": {
                                "deposit_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                                "deposit_count": "0",
                                "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000"
                            },
                            "graffiti":
                            "0x0000000000000000000000000000000000000000000000000000000000000000",
                            "proposer_slashings": [],
                            "attester_slashings": [],
                            "attestations": [],
                            "deposits": [],
                            "voluntary_exits": [],
                            "sync_aggregate": {
                                "sync_committee_bits": "0x00000000",
                                "sync_committee_signature":
                                    "0x00000000000000000000000000000000000000000000000000000000000000\
                                    00000000000000000000000000000000000000000000000000000000000000000\
                                    00000000000000000000000000000000000000000000000000000000000000000",
                            },
                        },
                    },
                },
            }),
        );

        Ok(())
    }

    #[test]
    fn test_bellatrix_block_serialization() -> Result<()> {
        let bellatrix_block = BellatrixBeaconBlock::<Minimal>::default();
        let message = SigningMessage::from(&bellatrix_block);

        assert_eq!(
            serde_json::to_value(&message)?,
            json!({
                "beacon_block": {
                    "version": "BELLATRIX",
                    "block_header": {
                        "slot": "0",
                        "proposer_index": "0",
                        "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                        "body_root": "0x75851d2575738753ff630d9d443e725e1229ff5f21c2052bbc6cee3585bad895",
                    },
                },
            }),
        );

        Ok(())
    }
}
