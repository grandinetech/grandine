// Local recomputation of the execution block hash from an `ExecutionPayload`.
// Backs `EXECUTION_ENGINE.is_valid_block_hash` without calling the execution layer.
//
// The header layout follows the execution layer (Amsterdam):
// - <https://eips.ethereum.org/EIPS/eip-4895> (withdrawals_root)
// - <https://eips.ethereum.org/EIPS/eip-4844> (blob gas)
// - <https://eips.ethereum.org/EIPS/eip-4788> (parent_beacon_block_root)
// - <https://eips.ethereum.org/EIPS/eip-7685> (requests_hash)
// - <https://eips.ethereum.org/EIPS/eip-7928> (block_access_list_hash)
// - <https://eips.ethereum.org/EIPS/eip-7843> (slot_number)

use ethereum_types::H64;
use hex_literal::hex;
use keccak_hasher::KeccakHasher;
use rlp::RlpStream;
use sha2::{Digest as _, Sha256};
use ssz::{ProgressiveByteList, SszWrite as _, WriteError};
use tiny_keccak::{Hasher as _, Keccak};
use types::{
    capella::containers::Withdrawal,
    gloas::containers::{ExecutionPayload, ExecutionRequests},
    phase0::primitives::{ExecutionBlockHash, H256},
    preset::Preset,
};

use crate::RequestType;

// Keccak-256 of an empty RLP list. Post-merge blocks have no ommers.
const EMPTY_OMMERS_HASH: H256 = H256(hex!(
    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
));

const HEADER_FIELD_COUNT: usize = 23;

pub fn compute_block_hash<P: Preset>(
    payload: &ExecutionPayload<P>,
    parent_beacon_block_root: H256,
    execution_requests: &ExecutionRequests<P>,
) -> Result<ExecutionBlockHash, WriteError> {
    let ExecutionPayload {
        parent_hash,
        fee_recipient,
        state_root,
        receipts_root,
        ref logs_bloom,
        prev_randao,
        block_number,
        gas_limit,
        gas_used,
        timestamp,
        ref extra_data,
        base_fee_per_gas,
        block_hash: _,
        ref transactions,
        ref withdrawals,
        blob_gas_used,
        excess_blob_gas,
        ref block_access_list,
        slot_number,
    } = *payload;

    let transactions_root =
        ordered_trie_root(transactions.iter().map(ProgressiveByteList::as_bytes));
    let withdrawals_root = ordered_trie_root(withdrawals.into_iter().map(withdrawal_rlp));
    let requests_hash = requests_hash(execution_requests)?;

    // The payload carries the access list already RLP-encoded.
    let block_access_list_hash = keccak256(block_access_list.as_bytes());

    let mut stream = RlpStream::new_list(HEADER_FIELD_COUNT);

    stream
        .append(&parent_hash)
        .append(&EMPTY_OMMERS_HASH)
        .append(&fee_recipient)
        .append(&state_root)
        .append(&transactions_root)
        .append(&receipts_root)
        .append(&logs_bloom.as_bytes())
        // difficulty
        .append(&0_u8)
        .append(&block_number)
        .append(&gas_limit)
        .append(&gas_used)
        .append(&timestamp)
        .append(&extra_data.as_bytes())
        .append(&prev_randao)
        // nonce
        .append(&H64::zero())
        .append(&base_fee_per_gas.into_raw())
        .append(&withdrawals_root)
        .append(&blob_gas_used)
        .append(&excess_blob_gas)
        .append(&parent_beacon_block_root)
        .append(&requests_hash)
        .append(&block_access_list_hash)
        .append(&slot_number);

    Ok(keccak256(stream.as_raw()))
}

// `patriciaTrie(rlp(index) => item)` as used for transactions and withdrawals.
fn ordered_trie_root<I: AsRef<[u8]>>(items: impl IntoIterator<Item = I>) -> H256 {
    H256(triehash::ordered_trie_root::<KeccakHasher, _>(items))
}

fn withdrawal_rlp(withdrawal: &Withdrawal) -> Vec<u8> {
    let Withdrawal {
        index,
        validator_index,
        address,
        amount,
    } = *withdrawal;

    let mut stream = RlpStream::new_list(4);

    stream
        .append(&index)
        .append(&validator_index)
        .append(&address)
        .append(&amount);

    stream.out().to_vec()
}

// `get_execution_requests_list` followed by the EIP-7685 commitment.
// Empty request lists are omitted from both.
fn requests_hash<P: Preset>(execution_requests: &ExecutionRequests<P>) -> Result<H256, WriteError> {
    let ExecutionRequests {
        deposits,
        withdrawals,
        consolidations,
        builder_deposits,
        builder_exits,
        phantom: _,
    } = execution_requests;

    // Request types have fixed-size SSZ encodings.
    // An empty list is exactly an empty encoding.
    let requests = [
        (RequestType::Deposits, deposits.to_ssz()?),
        (RequestType::Withdrawals, withdrawals.to_ssz()?),
        (RequestType::Consolidations, consolidations.to_ssz()?),
        (RequestType::BuilderDeposits, builder_deposits.to_ssz()?),
        (RequestType::BuilderExits, builder_exits.to_ssz()?),
    ];

    let mut hasher = Sha256::new();

    for (request_type, request_data) in requests {
        if request_data.is_empty() {
            continue;
        }

        let request_hash = Sha256::new()
            .chain_update([request_type.request_type_byte()])
            .chain_update(request_data)
            .finalize();

        hasher.update(request_hash);
    }

    Ok(H256(hasher.finalize().into()))
}

fn keccak256(bytes: &[u8]) -> H256 {
    let mut hasher = Keccak::v256();
    let mut output = H256::zero();
    hasher.update(bytes);
    hasher.finalize(output.as_bytes_mut());
    output
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::Result;
    use types::{
        electra::containers::DepositRequest,
        gloas::containers::{BuilderExitRequest, ExecutionPayloadEnvelope},
        preset::{Mainnet, Minimal},
    };

    use super::*;

    // Block 568326 (slot 653401) of glamsterdam-devnet-8, from `/eth/v1/beacon/execution_payload_envelopes`.
    // Its `block_hash` matches the hash `eth_getBlockByNumber` reports for the same block.
    // It has transactions (including a blob transaction), withdrawals,
    // a builder deposit request and a non-empty block access list.
    const DEVNET_ENVELOPE: &str =
        include_str!("fixtures/glamsterdam_devnet_8_slot_653401_envelope.json");

    #[test]
    fn block_hash_matches_devnet_block() -> Result<()> {
        let envelope = serde_json::from_str::<ExecutionPayloadEnvelope<Mainnet>>(DEVNET_ENVELOPE)?;

        let ExecutionPayloadEnvelope {
            payload,
            execution_requests,
            parent_beacon_block_root,
            ..
        } = envelope;

        assert!(!payload.transactions.is_empty());
        assert!(!payload.withdrawals.is_empty());
        assert!(!payload.block_access_list.as_bytes().is_empty());
        assert!(!execution_requests.builder_deposits.is_empty());

        // Header fields reported by `eth_getBlockByNumber` for the same block.
        // They pin the parts separately, so a mismatch points at the broken one.
        assert_eq!(
            ordered_trie_root(
                payload
                    .transactions
                    .iter()
                    .map(ProgressiveByteList::as_bytes)
            ),
            H256(hex!(
                "cf87a52162bfd02ce9a9938739ac68925ae017e997e18cb84bb31e81f7c76e22"
            )),
        );

        assert_eq!(
            ordered_trie_root(payload.withdrawals.iter().map(withdrawal_rlp)),
            H256(hex!(
                "17d182f80e526f42ba8964d65310b58940f2988d37a6aa960b3892fa0047b667"
            )),
        );

        assert_eq!(
            requests_hash(&execution_requests)?,
            H256(hex!(
                "737e865b174797788efa7ec0fadb0e25e5bc2e01877ba5db18cc87ab083dbdc5"
            )),
        );

        // The access list is hashed as is, not wrapped in another RLP string.
        assert_eq!(
            keccak256(payload.block_access_list.as_bytes()),
            H256(hex!(
                "efa5604e8650c056d6d2e686d258cf3f3b73aa4d7ccf41f567f761d118226db1"
            )),
        );

        assert_eq!(
            compute_block_hash(&payload, parent_beacon_block_root, &execution_requests)?,
            payload.block_hash,
        );

        Ok(())
    }

    // EIP-7685: requests are committed in ascending type order.
    // The fixture above has only one request type, so it cannot catch a wrong order.
    #[test]
    fn requests_hash_orders_requests_by_type() -> Result<()> {
        let execution_requests = ExecutionRequests::<Minimal> {
            deposits: vec![DepositRequest::default()].try_into()?,
            builder_exits: vec![BuilderExitRequest::default()].try_into()?,
            ..ExecutionRequests::default()
        };

        let type_hash = |request_type: RequestType, data: Vec<u8>| {
            Sha256::new()
                .chain_update([request_type.request_type_byte()])
                .chain_update(data)
                .finalize()
        };

        let expected = Sha256::new()
            .chain_update(type_hash(
                RequestType::Deposits,
                execution_requests.deposits.to_ssz()?,
            ))
            .chain_update(type_hash(
                RequestType::BuilderExits,
                execution_requests.builder_exits.to_ssz()?,
            ))
            .finalize();

        assert_eq!(requests_hash(&execution_requests)?, H256(expected.into()));

        Ok(())
    }

    #[test]
    fn empty_ommers_hash_is_keccak_of_empty_rlp_list() {
        assert_eq!(keccak256(&rlp::EMPTY_LIST_RLP), EMPTY_OMMERS_HASH);
    }

    #[test]
    fn empty_trie_root_matches_execution_layer() {
        assert_eq!(
            ordered_trie_root(core::iter::empty::<&[u8]>()),
            H256(hex!(
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
            )),
        );
    }

    // EIP-7685: no requests hash to `sha256(b"")`.
    #[test]
    fn empty_requests_hash_matches_eip_7685() -> Result<()> {
        assert_eq!(
            requests_hash(&ExecutionRequests::<Minimal>::default())?,
            H256(hex!(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )),
        );

        Ok(())
    }

    // A builder must not be able to swap anything in the envelope under the committed hash.
    #[test]
    fn block_hash_commits_to_envelope_contents() -> Result<()> {
        let payload = ExecutionPayload::<Minimal>::default();
        let requests = ExecutionRequests::<Minimal>::default();
        let parent_beacon_block_root = H256::repeat_byte(1);

        let original = compute_block_hash(&payload, parent_beacon_block_root, &requests)?;

        let with_transaction = ExecutionPayload {
            transactions: Arc::new(vec![vec![2].try_into()?].try_into()?),
            ..payload.clone()
        };

        let with_block_access_list = ExecutionPayload {
            block_access_list: Arc::new(vec![3].try_into()?),
            ..payload.clone()
        };

        let with_slot_number = ExecutionPayload {
            slot_number: 4,
            ..payload.clone()
        };

        let with_deposit = ExecutionRequests {
            deposits: vec![DepositRequest::default()].try_into()?,
            ..requests.clone()
        };

        let hashes = [
            compute_block_hash(&with_transaction, parent_beacon_block_root, &requests)?,
            compute_block_hash(&with_block_access_list, parent_beacon_block_root, &requests)?,
            compute_block_hash(&with_slot_number, parent_beacon_block_root, &requests)?,
            compute_block_hash(&payload, parent_beacon_block_root, &with_deposit)?,
            compute_block_hash(&payload, H256::repeat_byte(5), &requests)?,
        ];

        for hash in hashes {
            assert_ne!(hash, original);
        }

        Ok(())
    }
}
