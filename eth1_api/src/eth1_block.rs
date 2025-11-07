use anyhow::{Error as AnyhowError, Result, bail};
use ssz::{ContiguousList, Ssz};
use thiserror::Error;
use typenum::U4294967296;
use types::{
    bellatrix::{containers::PowBlock, primitives::Difficulty},
    nonstandard::TimedPowBlock,
    phase0::primitives::{
        ExecutionBlockHash, ExecutionBlockNumber, ExecutionTransactionHash, UnixSeconds,
    },
};
use web3::types::{Block, U64};

use crate::DepositEvent;

type MaxDepositEvents = U4294967296;

#[derive(Debug, Error)]
enum Error {
    #[error("RPC returned block without hash: {block:?}")]
    MissingHash {
        block: Block<ExecutionTransactionHash>,
    },
    #[error("RPC returned block without number: {block:?}")]
    MissingNumber {
        block: Block<ExecutionTransactionHash>,
    },
}

#[derive(Default, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct Eth1Block {
    pub hash: ExecutionBlockHash,
    pub parent_hash: ExecutionBlockHash,
    pub number: ExecutionBlockNumber,
    pub timestamp: UnixSeconds,
    pub total_difficulty: Difficulty,
    pub deposit_events: ContiguousList<DepositEvent, MaxDepositEvents>,
}

impl TryFrom<Block<ExecutionTransactionHash>> for Eth1Block {
    type Error = AnyhowError;

    fn try_from(block: Block<ExecutionTransactionHash>) -> Result<Self, Self::Error> {
        let Block {
            hash,
            parent_hash,
            number,
            timestamp,
            total_difficulty,
            ..
        } = block;

        let Some(hash) = hash else {
            bail!(Error::MissingHash { block });
        };

        let Some(number) = number.as_ref().map(U64::as_u64) else {
            bail!(Error::MissingNumber { block });
        };

        // `<U256 as TryInto<UnixSeconds>>::Error` is `&'static str`.
        let timestamp = timestamp.try_into().map_err(AnyhowError::msg)?;

        let total_difficulty = match total_difficulty {
            Some(total_difficulty) => total_difficulty.into(),
            None => Difficulty::ZERO,
        };

        Ok(Self {
            hash,
            parent_hash,
            number,
            timestamp,
            total_difficulty,
            deposit_events: ContiguousList::default(),
        })
    }
}

impl From<Eth1Block> for TimedPowBlock {
    fn from(eth1_block: Eth1Block) -> Self {
        let Eth1Block {
            hash,
            parent_hash,
            timestamp,
            total_difficulty,
            ..
        } = eth1_block;

        Self {
            pow_block: PowBlock {
                block_hash: hash,
                parent_hash,
                total_difficulty,
            },
            timestamp,
        }
    }
}
