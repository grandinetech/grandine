use std::sync::Mutex;

use anyhow::Result;
use database::Database;
use deposit_tree::DepositTree;
use eth1_api::{DepositEvent, Eth1Block};
use itertools::Itertools as _;
use ssz::{SszReadDefault, SszWrite as _};
use types::phase0::primitives::ExecutionBlockNumber;

const BLOCK_KEY_PREFIX: &str = "bk";
const DEPOSIT_TREE_KEY: &str = "deposit_tree";

pub struct Eth1Cache {
    database: Database,
    deposit_tree: Mutex<DepositTree>,
}

impl Eth1Cache {
    pub fn new(database: Database, default_deposit_tree: Option<DepositTree>) -> Result<Self> {
        let default_deposit_tree = default_deposit_tree.unwrap_or_default();

        let deposit_tree = if let Some(tree) = get(&database, DEPOSIT_TREE_KEY)? {
            tree
        } else {
            put_deposit_tree(&database, &default_deposit_tree)?;
            default_deposit_tree
        };

        Ok(Self {
            database,
            deposit_tree: Mutex::new(deposit_tree),
        })
    }

    pub fn add_deposits(
        &self,
        mut deposit_events: Vec<&DepositEvent>,
        block_number: ExecutionBlockNumber,
    ) -> Result<()> {
        deposit_events.sort_by_key(|deposit_event| deposit_event.index);

        let mut deposit_tree = self
            .deposit_tree
            .lock()
            .expect("deposit tree mutex is poisoned");

        for event in deposit_events {
            if deposit_tree.deposit_count <= event.index {
                deposit_tree.push(event.index, event.data)?;
            }
        }

        deposit_tree.last_added_block_number = block_number;

        self.put_deposit_tree(&deposit_tree)
    }

    pub fn get_blocks_from(
        &self,
        block_number: ExecutionBlockNumber,
        max_batch_size: usize,
    ) -> Result<Vec<Eth1Block>> {
        let results = self
            .database
            .iterator_ascending(block_key(block_number)..)?;

        itertools::process_results(results, |pairs| {
            pairs
                .take_while(|(key_bytes, _)| valid_block_key_bytes(key_bytes))
                .take(max_batch_size)
                .map(|(_, value_bytes)| Eth1Block::from_ssz_default(value_bytes))
                .try_collect()
                .map_err(Into::into)
        })?
    }

    pub fn get_deposit_tree(&self) -> Result<Option<DepositTree>> {
        get(&self.database, DEPOSIT_TREE_KEY)
    }

    pub fn get_latest_block(&self) -> Result<Option<Eth1Block>> {
        self.database
            .prev(block_key(ExecutionBlockNumber::MAX))?
            .filter(|(key_bytes, _)| valid_block_key_bytes(key_bytes))
            .map(|(_, value_bytes)| Eth1Block::from_ssz_default(value_bytes))
            .transpose()
            .map_err(Into::into)
    }

    pub fn put_blocks(&self, blocks: impl IntoIterator<Item = Eth1Block>) -> Result<()> {
        let results = blocks.into_iter().map(|block| {
            let key_string = block_key(block.number);
            let value_bytes = block.to_ssz()?;
            Ok((key_string, value_bytes))
        });

        itertools::process_results(results, |pairs| self.database.put_batch(pairs))
            .and_then(core::convert::identity)
    }

    pub fn put_deposit_tree(&self, deposit_tree: &DepositTree) -> Result<()> {
        put_deposit_tree(&self.database, deposit_tree)
    }
}

fn block_key(block_number: ExecutionBlockNumber) -> String {
    format!("{BLOCK_KEY_PREFIX}{block_number:020}")
}

fn get<V: SszReadDefault>(database: &Database, key: impl AsRef<[u8]>) -> Result<Option<V>> {
    let value = match database.get(key)? {
        Some(bytes) => V::from_ssz_default(bytes.as_slice())?,
        None => return Ok(None),
    };

    Ok(Some(value))
}

fn put_deposit_tree(database: &Database, deposit_tree: &DepositTree) -> Result<()> {
    database.put(DEPOSIT_TREE_KEY, deposit_tree.to_ssz()?)
}

fn valid_block_key_bytes(key_bytes: &[u8]) -> bool {
    key_bytes.starts_with(BLOCK_KEY_PREFIX.as_bytes())
}
