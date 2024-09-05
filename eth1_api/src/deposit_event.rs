// This is how `DepositEvent` logs are laid out (each line is an EVM word in hexadecimal):
// ```text
// 00000000000000000000000000000000000000000000000000000000000000a0 pubkey                 offset
// 0000000000000000000000000000000000000000000000000000000000000100 withdrawal_credentials offset
// 0000000000000000000000000000000000000000000000000000000000000140 amount                 offset
// 0000000000000000000000000000000000000000000000000000000000000180 signature              offset
// 0000000000000000000000000000000000000000000000000000000000000200 index                  offset
// 0000000000000000000000000000000000000000000000000000000000000030 pubkey                 length
// ................................................................ pubkey
// ................................00000000000000000000000000000000 pubkey
// 0000000000000000000000000000000000000000000000000000000000000020 withdrawal_credentials length
// ................................................................ withdrawal_credentials
// 0000000000000000000000000000000000000000000000000000000000000008 amount                 length
// ................000000000000000000000000000000000000000000000000 amount
// 0000000000000000000000000000000000000000000000000000000000000060 signature              length
// ................................................................ signature
// ................................................................ signature
// ................................................................ signature
// 0000000000000000000000000000000000000000000000000000000000000008 index                  length
// ................000000000000000000000000000000000000000000000000 index
// ```
//
// The deposit contract encodes all values as dynamic arrays (`bytes`) despite all of them being
// fixed in size and some of them being small enough to fit in 32 bytes, which results in some
// wasted space. This is most likely done for compatibility with previous versions of the contract,
// which were written in Vyper.
//
// `ethabi-derive` combined with `ethabi-contract` can generate code for decoding logs based on an
// ABI specification in JSON, but for whatever reason the generated code treats `DepositEvent` as if
// wrapped in a tuple and thus fails to decode logs produced by the deposit contract.
//
// SSZ is compatible with this format (perhaps intentionally), so we could abuse `SszReadDefault` to
// decode `DepositEvent`s at the cost of some unnecessary copying. In fact, we used SSZ to implement
// decoding in the past.
//
// `bincode` is also compatible with this format but requires `serde` with `serde-big-array`.
//
// Crates for safe transmutation (`bytemuck`, `safe_transmute`, `typic`, `zerocopy`) require the
// types involved to have compatible alignments. `RawDepositEvent` contains types aliased to `u64`,
// which must be aligned to 8 bytes. On top of that, `safe_transmute` cannot handle arrays of size
// 48 and 96.
//
// See:
// - <https://github.com/ethereum/consensus-specs/blob/fab27d17f0dd289a6abbb99acae39387ac2320cf/solidity_deposit_contract/deposit_contract.sol>
// - <https://docs.soliditylang.org/en/v0.8.2/abi-spec.html>

use anyhow::{ensure, Error as AnyhowError};
use bls::{PublicKeyBytes, SignatureBytes};
use hex_literal::hex;
use memoffset::span_of;
use serde::{Deserialize, Serialize};
use ssz::Ssz;
use static_assertions::assert_eq_size;
use thiserror::Error;
use types::phase0::{
    containers::DepositData,
    primitives::{DepositIndex, Gwei, H256},
};
use web3::types::Log;

#[derive(Debug, Error)]
enum Error {
    #[error("log has unexpected topics: {log:?}")]
    UnexpectedTopics { log: Log },
    #[error("log has been removed: {log:?}")]
    Removed { log: Log },
    #[error("log data has the wrong length: {log:?}")]
    WrongLength { log: Log },
}

type EvmWord = [u8; 32];

#[repr(C)]
struct RawDepositEvent {
    _pubkey_offset: EvmWord,
    _withdrawal_credentials_offset: EvmWord,
    _amount_offset: EvmWord,
    _signature_offset: EvmWord,
    _index_offset: EvmWord,
    _pubkey_length: EvmWord,
    pubkey: PublicKeyBytes,
    _pubkey_padding: [u8; 16],
    _withdrawal_credentials_length: EvmWord,
    withdrawal_credentials: H256,
    _amount_length: EvmWord,
    amount: Gwei,
    _amount_padding: [u8; 24],
    _signature_length: EvmWord,
    signature: SignatureBytes,
    _index_length: EvmWord,
    index: DepositIndex,
    _index_padding: [u8; 24],
}

assert_eq_size!(RawDepositEvent, [EvmWord; 18]);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Ssz)]
#[cfg_attr(test, derive(PartialEq, Eq, Default))]
#[ssz(derive_hash = false)]
pub struct DepositEvent {
    pub data: DepositData,
    pub index: DepositIndex,
}

impl TryFrom<Log> for DepositEvent {
    type Error = AnyhowError;

    fn try_from(log: Log) -> Result<Self, Self::Error> {
        ensure!(log.topics == [Self::TOPIC], Error::UnexpectedTopics { log });

        ensure!(!log.is_removed(), Error::Removed { log });

        let log_data = log.data.0.as_slice();

        ensure!(log_data.len() == Self::LENGTH, Error::WrongLength { log });

        // `core::mem::offset_of!` was stabilized in Rust 1.77.0,
        // but there is no equivalent to `memoffset::span_of!` in the standard library.
        let (
            pubkey_range,
            withdrawal_credentials_range,
            amount_range,
            signature_range,
            index_range,
        ) = (
            span_of!(RawDepositEvent, pubkey),
            span_of!(RawDepositEvent, withdrawal_credentials),
            span_of!(RawDepositEvent, amount),
            span_of!(RawDepositEvent, signature),
            span_of!(RawDepositEvent, index),
        );

        let pubkey = PublicKeyBytes::from_slice(&log_data[pubkey_range]);

        let withdrawal_credentials = H256::from_slice(&log_data[withdrawal_credentials_range]);

        let amount = Gwei::from_le_bytes(
            log_data[amount_range]
                .try_into()
                .expect("length is checked above"),
        );

        let signature = SignatureBytes::from_slice(&log_data[signature_range]);

        let index = DepositIndex::from_le_bytes(
            log_data[index_range]
                .try_into()
                .expect("length is checked above"),
        );

        Ok(Self {
            data: DepositData {
                pubkey,
                withdrawal_credentials,
                amount,
                signature,
            },
            index,
        })
    }
}

impl DepositEvent {
    /// Keccak-256 hash of `DepositEvent(bytes,bytes,bytes,bytes,bytes)`.
    pub const TOPIC: H256 = H256(hex!(
        "649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"
    ));

    const LENGTH: usize = size_of::<RawDepositEvent>();
}

#[allow(clippy::default_trait_access)]
#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test]
    fn try_from_decodes_default() {
        assert_eq!(
            DepositEvent::try_from(deposit_event_log()).expect("decoding should succeed"),
            DepositEvent::default(),
        );
    }

    #[test_case(
        Log { topics: vec![], ..deposit_event_log() };
        "log with no topics"
    )]
    #[test_case(
        Log { data: vec![0; DepositEvent::LENGTH - 1].into(), ..deposit_event_log() };
        "log with too little data"
    )]
    #[test_case(
        Log { data: vec![0; DepositEvent::LENGTH + 1].into(), ..deposit_event_log() };
        "log with too much data"
    )]
    #[test_case(
        Log { removed: Some(true), ..deposit_event_log() };
        "removed log"
    )]
    fn try_from_fails_on(log: Log) {
        DepositEvent::try_from(log).expect_err("decoding should fail");
    }

    fn deposit_event_log() -> Log {
        Log {
            topics: vec![DepositEvent::TOPIC],
            data: vec![0; DepositEvent::LENGTH].into(),
            ..mined_log()
        }
    }

    fn mined_log() -> Log {
        Log {
            block_hash: Some(Default::default()),
            block_number: Some(Default::default()),
            transaction_hash: Some(Default::default()),
            transaction_index: Some(Default::default()),
            log_index: Some(Default::default()),
            transaction_log_index: Some(Default::default()),
            ..default_log()
        }
    }

    // Some of the types in the `web3` crate don't have `Default` implementations even though they
    // could be derived.
    fn default_log() -> Log {
        Log {
            address: Default::default(),
            topics: Default::default(),
            data: Default::default(),
            block_hash: Default::default(),
            block_number: Default::default(),
            transaction_hash: Default::default(),
            transaction_index: Default::default(),
            log_index: Default::default(),
            transaction_log_index: Default::default(),
            log_type: Default::default(),
            removed: Default::default(),
        }
    }
}
