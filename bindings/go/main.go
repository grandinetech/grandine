package grandine

/*
#cgo LDFLAGS: -L${SRCDIR}/lib -lc_grandine -lm -lz -ldl -lstdc++
#include "./lib/c_grandine.h"
#include <stdbool.h>

typedef uint8_t *H256;

typedef CResult_u64 (*go_eth_block_number_callback)(void);
typedef CResult_COption_CEth1Block (*go_eth_get_block_by_hash_callback)(uint8_t *hash);
typedef CResult_COption_CEth1Block (*go_eth_get_block_by_number_callback)(uint64_t number);
typedef CResult_COption_CEth1Block (*go_eth_get_block_finalized_callback)(void);
typedef CResult_COption_CEth1Block (*go_eth_get_block_safe_callback)(void);
typedef CResult_COption_CEth1Block (*go_eth_get_block_latest_callback)(void);
typedef CResult_COption_CEth1Block (*go_eth_get_block_earliest_callback)(void);
typedef CResult_COption_CEth1Block (*go_eth_get_block_pending_callback)(void);
typedef CResult_CLogs (*go_eth_logs_callback)(CFilter filter);
typedef CResult_CPayloadStatusV1 (*go_engine_new_payload_v1_callback)(CExecutionPayloadV1 payload);
typedef CResult_CPayloadStatusV1 (*go_engine_new_payload_v2_callback)(CExecutionPayloadV2 payload);
typedef CResult_CPayloadStatusV1 (*go_engine_new_payload_v3_callback)(CExecutionPayloadV3 payload, const uint8_t (*versioned_hashes)[32], uint64_t versioned_hashes_len, uint8_t parent_beacon_block_root[32]);
typedef CResult_CPayloadStatusV1 (*go_engine_new_payload_v4_callback)(CExecutionPayloadV3 payload, const uint8_t (*versioned_hashes)[32], uint64_t versioned_hashes_len, uint8_t parent_beacon_block_root[32], CExecutionRequests execution_requests);
typedef CResult_CForkChoiceUpdatedResponse (*go_engine_forkchoice_updated_v1_callback)(CForkChoiceStateV1 state, COption_CPayloadAttributesV1 payload);
typedef CResult_CForkChoiceUpdatedResponse (*go_engine_forkchoice_updated_v2_callback)(CForkChoiceStateV1 state, COption_CPayloadAttributesV2 payload);
typedef CResult_CForkChoiceUpdatedResponse (*go_engine_forkchoice_updated_v3_callback)(CForkChoiceStateV1 state, COption_CPayloadAttributesV3 payload);
typedef CResult_CExecutionPayloadV1 (*go_engine_get_payload_v1_callback)(uint8_t *payload_id);
typedef CResult_CEngineGetPayloadV2Response (*go_engine_get_payload_v2_callback)(uint8_t *payload_id);
typedef CResult_CEngineGetPayloadV3Response (*go_engine_get_payload_v3_callback)(uint8_t *payload_id);
typedef CResult_CEngineGetPayloadV4Response (*go_engine_get_payload_v4_callback)(uint8_t *payload_id);

CResult_u64 go_eth_block_number(void);
CResult_COption_CEth1Block go_eth_get_block_by_hash(uint8_t *hash);
CResult_COption_CEth1Block go_eth_get_block_by_number(uint64_t number);
CResult_COption_CEth1Block go_eth_get_block_finalized(void);
CResult_COption_CEth1Block go_eth_get_block_safe(void);
CResult_COption_CEth1Block go_eth_get_block_latest(void);
CResult_COption_CEth1Block go_eth_get_block_earliest(void);
CResult_COption_CEth1Block go_eth_get_block_pending(void);
CResult_CPayloadStatusV1 go_engine_new_payload_v1(CExecutionPayloadV1 payload);
CResult_CPayloadStatusV1 go_engine_new_payload_v2(CExecutionPayloadV2 payload);
CResult_CPayloadStatusV1 go_engine_new_payload_v3(CExecutionPayloadV3 payload, const uint8_t (*versioned_hashes)[32], uint64_t versioned_hashes_len, uint8_t parent_beacon_block_root[32]);
CResult_CPayloadStatusV1 go_engine_new_payload_v4(CExecutionPayloadV3 payload, const uint8_t (*versioned_hashes)[32], uint64_t versioned_hashes_len, uint8_t parent_beacon_block_root[32], CExecutionRequests execution_requests);
CResult_CForkChoiceUpdatedResponse go_engine_forkchoice_updated_v1(CForkChoiceStateV1 state, COption_CPayloadAttributesV1 payload);
CResult_CForkChoiceUpdatedResponse go_engine_forkchoice_updated_v2(CForkChoiceStateV1 state, COption_CPayloadAttributesV2 payload);
CResult_CForkChoiceUpdatedResponse go_engine_forkchoice_updated_v3(CForkChoiceStateV1 state, COption_CPayloadAttributesV3 payload);
CResult_CExecutionPayloadV1 go_engine_get_payload_v1(uint8_t *payload_id);
CResult_CEngineGetPayloadV2Response go_engine_get_payload_v2(uint8_t *payload_id);
CResult_CEngineGetPayloadV3Response go_engine_get_payload_v3(uint8_t *payload_id);
CResult_CEngineGetPayloadV4Response go_engine_get_payload_v4(uint8_t *payload_id);
CResult_CLogs go_eth_logs(CFilter filter);
*/
import "C"
import (
	"unsafe"
)

func RunGrandine(args []string) {
	cargs := C.malloc(C.size_t(len(args)) * C.size_t(unsafe.Sizeof(uintptr(0))))

	a := (*[1<<30 - 1]*C.char)(cargs)

	for idx, arg := range args {
		a[idx] = C.CString(arg)
		defer C.free(unsafe.Pointer(a[idx]))
	}

	C.grandine_run(C.ulong(len(args)), (**C.char)(cargs))
}

type Eth1Block struct {
	Hash            [32]byte
	ParentHash      [32]byte
	Number          uint64
	Timestamp       uint64
	TotalDifficulty [32]byte
}

type WithdrawalV1 struct {
	Index          uint64
	ValidatorIndex uint64
	Address        [20]byte
	Amount         uint64
}

type ExecutionPayloadV1 struct {
	ParentHash    [32]byte
	FeeRecipient  [20]byte
	StateRoot     [32]byte
	ReceiptsRoot  [32]byte
	LogsBloom     []byte
	PrevRandao    [32]byte
	BlockNumber   uint64
	GasLimit      uint64
	GasUsed       uint64
	Timestamp     uint64
	ExtraData     []byte
	BaseFeePerGas [32]byte
	BlockHash     [32]byte
	Transactions  [][]byte
}

type ExecutionPayloadV2 struct {
	ParentHash    [32]byte
	FeeRecipient  [20]byte
	StateRoot     [32]byte
	ReceiptsRoot  [32]byte
	LogsBloom     []byte
	PrevRandao    [32]byte
	BlockNumber   uint64
	GasLimit      uint64
	GasUsed       uint64
	Timestamp     uint64
	ExtraData     []byte
	BaseFeePerGas [32]byte
	BlockHash     [32]byte
	Transactions  [][]byte
	Withdrawals   []WithdrawalV1
}

type ExecutionPayloadV3 struct {
	ParentHash    [32]byte
	FeeRecipient  [20]byte
	StateRoot     [32]byte
	ReceiptsRoot  [32]byte
	LogsBloom     []byte
	PrevRandao    [32]byte
	BlockNumber   uint64
	GasLimit      uint64
	GasUsed       uint64
	Timestamp     uint64
	ExtraData     []byte
	BaseFeePerGas [32]byte
	BlockHash     [32]byte
	Transactions  [][]byte
	Withdrawals   []WithdrawalV1
	BlobGasUsed   uint64
	ExcessBlobGas uint64
}

type PayloadValidationStatus = uint8

const (
	Valid PayloadValidationStatus = iota
	Invalid
	Syncing
	Accepted
	InvalidBlockHash
)

type PayloadStatusV1 struct {
	Status          PayloadValidationStatus
	LatestValidHash *[32]byte
}

type ForkChoiceStateV1 struct {
	HeadBlockHash      [32]byte
	SafeBlockHash      [32]byte
	FinalizedBlockHash [32]byte
}

type PayloadAttributesV1 struct {
	Timestamp             uint64
	PrevRandao            [32]byte
	SuggestedFeeRecipient [20]byte
}

type PayloadAttributesV2 struct {
	Timestamp             uint64
	PrevRandao            [32]byte
	SuggestedFeeRecipient [20]byte
	Withdrawals           []WithdrawalV1
}

type PayloadAttributesV3 struct {
	Timestamp             uint64
	PrevRandao            [32]byte
	SuggestedFeeRecipient [20]byte
	Withdrawals           []WithdrawalV1
	ParentBeaconBlockRoot [32]byte
}

type ForkChoiceUpdatedResponse struct {
	PayloadStatus PayloadStatusV1
	PayloadId     *[8]byte
}

type EngineGetPayloadV2Response struct {
	ExecutionPayload ExecutionPayloadV2
	BlockValue       [32]byte
}

type BlobsBundleV1 struct {
	Commitments [][48]byte
	Proofs      [][48]byte
	Blobs       [][]byte
}

type EngineGetPayloadV3Response struct {
	ExecutionPayload      ExecutionPayloadV3
	BlockValue            [32]byte
	BlobsBundle           BlobsBundleV1
	ShouldOverrideBuilder bool
}

type EngineGetPayloadV4Response struct {
	ExecutionPayload      ExecutionPayloadV3
	BlockValue            [32]byte
	BlobsBundle           BlobsBundleV1
	ShouldOverrideBuilder bool
	ExecutionRequests     [][]byte
}

type Filter struct {
	FromBlock *uint64
	ToBlock   *uint64
	Addresses [][20]byte
	Topics    [][][32]byte
	Limit     *uint64
}

type Log struct {
	Address             [20]byte
	Topics              [][32]byte
	Data                []byte
	BlockHash           *[32]byte
	BlockNumber         *uint64
	TransactionHash     *[32]byte
	TransactionIndex    *uint64
	LogIndex            *[32]byte
	TransactionLogIndex *[32]byte
	LogType             *string
	Removed             *bool
}

type ELAdapter interface {
	EthBlockNumber() uint64
	EthGetBlockByHash([32]byte) *Eth1Block
	EthGetBlockByNumber(uint64) *Eth1Block
	EthGetBlockFinalized() *Eth1Block
	EthGetBlockSafe() *Eth1Block
	EthGetBlockLatest() *Eth1Block
	EthGetBlockEarliest() *Eth1Block
	EthGetBlockPending() *Eth1Block
	EthLogs(Filter) []Log
	EngineNewPayloadV1(ExecutionPayloadV1) PayloadStatusV1
	EngineNewPayloadV2(ExecutionPayloadV2) PayloadStatusV1
	EngineNewPayloadV3(ExecutionPayloadV3, [][32]byte, [32]byte) PayloadStatusV1
	EngineNewPayloadV4(ExecutionPayloadV3, [][32]byte, [32]byte, [][]byte) PayloadStatusV1
	EngineForkChoiceUpdatedV1(ForkChoiceStateV1, *PayloadAttributesV1) ForkChoiceUpdatedResponse
	EngineForkChoiceUpdatedV2(ForkChoiceStateV1, *PayloadAttributesV2) ForkChoiceUpdatedResponse
	EngineForkChoiceUpdatedV3(ForkChoiceStateV1, *PayloadAttributesV3) ForkChoiceUpdatedResponse
	EngineGetPayloadV1([8]byte) ExecutionPayloadV1
	EngineGetPayloadV2([8]byte) EngineGetPayloadV2Response
	EngineGetPayloadV3([8]byte) EngineGetPayloadV3Response
	EngineGetPayloadV4([8]byte) EngineGetPayloadV4Response
}

var globalAdapter *ELAdapter = nil

func goBlockToCBlock(block *Eth1Block) C.COption_CEth1Block {
	if block == nil {
		return C.COption_CEth1Block{is_something: false, value: C.CEth1Block{}}
	}

	return C.COption_CEth1Block{
		is_something: true,
		value: C.CEth1Block{
			hash:             *(*[32]C.uint8_t)(unsafe.Pointer(&block.Hash)),
			parent_hash:      *(*[32]C.uint8_t)(unsafe.Pointer(&block.ParentHash)),
			number:           C.uint64_t(block.Number),
			timestamp:        C.uint64_t(block.Timestamp),
			total_difficulty: *(*[32]C.uint8_t)(unsafe.Pointer(&block.TotalDifficulty)),
		},
	}
}

func goPayloadStatusV1ToC(status PayloadStatusV1) C.CPayloadStatusV1 {
	var latest_valid_hash C.COption_CH256

	if status.LatestValidHash != nil {
		latest_valid_hash = C.COption_CH256{
			is_something: true,
			value:        C.CH256{_0: *(*[32]C.uint8_t)(unsafe.Pointer(status.LatestValidHash))},
		}
	} else {
		latest_valid_hash = C.COption_CH256{
			is_something: false,
		}
	}

	return C.CPayloadStatusV1{
		status:            C.uint8_t(status.Status),
		latest_valid_hash: latest_valid_hash,
	}
}

//export GoEthBlockNumber
func GoEthBlockNumber() C.CResult_u64 {
	if globalAdapter != nil {
		number := (*globalAdapter).EthBlockNumber()

		return C.CResult_u64{value: C.uint64_t(number), error: 0}
	}

	return C.CResult_u64{error: 1}
}

//export GoEthGetBlockByHash
func GoEthGetBlockByHash(hash C.H256) C.CResult_COption_CEth1Block {
	if globalAdapter != nil {
		hash_bytes := *(*[32]byte)(unsafe.Pointer(hash))

		block := (*globalAdapter).EthGetBlockByHash(hash_bytes)

		return C.CResult_COption_CEth1Block{value: goBlockToCBlock(block), error: 0}
	}

	return C.CResult_COption_CEth1Block{error: 1}
}

//export GoEthGetBlockByNumber
func GoEthGetBlockByNumber(number C.uint64_t) C.CResult_COption_CEth1Block {
	if globalAdapter != nil {
		block := (*globalAdapter).EthGetBlockByNumber(uint64(number))

		return C.CResult_COption_CEth1Block{value: goBlockToCBlock(block), error: 0}
	}

	return C.CResult_COption_CEth1Block{error: 1}
}

//export GoEthGetBlockFinalized
func GoEthGetBlockFinalized() C.CResult_COption_CEth1Block {
	if globalAdapter != nil {
		block := (*globalAdapter).EthGetBlockFinalized()

		return C.CResult_COption_CEth1Block{value: goBlockToCBlock(block), error: 0}
	}

	return C.CResult_COption_CEth1Block{error: 1}
}

//export GoEthGetBlockSafe
func GoEthGetBlockSafe() C.CResult_COption_CEth1Block {
	if globalAdapter != nil {
		block := (*globalAdapter).EthGetBlockSafe()

		return C.CResult_COption_CEth1Block{value: goBlockToCBlock(block), error: 0}
	}

	return C.CResult_COption_CEth1Block{error: 1}
}

//export GoEthGetBlockLatest
func GoEthGetBlockLatest() C.CResult_COption_CEth1Block {
	if globalAdapter != nil {
		block := (*globalAdapter).EthGetBlockLatest()

		return C.CResult_COption_CEth1Block{value: goBlockToCBlock(block), error: 0}
	}

	return C.CResult_COption_CEth1Block{error: 1}
}

//export GoEthGetBlockEarliest
func GoEthGetBlockEarliest() C.CResult_COption_CEth1Block {
	if globalAdapter != nil {
		block := (*globalAdapter).EthGetBlockEarliest()

		return C.CResult_COption_CEth1Block{value: goBlockToCBlock(block), error: 0}
	}

	return C.CResult_COption_CEth1Block{error: 1}
}

//export GoEthGetBlockPending
func GoEthGetBlockPending() C.CResult_COption_CEth1Block {
	if globalAdapter != nil {
		block := (*globalAdapter).EthGetBlockPending()

		return C.CResult_COption_CEth1Block{value: goBlockToCBlock(block), error: 0}
	}

	return C.CResult_COption_CEth1Block{error: 1}
}

//export GoEthLogs
func GoEthLogs(filter C.CFilter) C.CResult_CLogs {
	if globalAdapter != nil {
		var fromBlock *uint64 = nil
		if filter.from_block.is_something {
			block := uint64(filter.from_block.value)
			fromBlock = &block
		}

		var toBlock *uint64 = nil
		if filter.to_block.is_something {
			block := uint64(filter.to_block.value)
			toBlock = &block
		}

		var address [][20]byte
		if filter.address.is_something {
			raw_address := unsafe.Slice(filter.address.value.data, filter.address.value.data_len)
			address := make([][20]byte, 0, filter.address.value.data_len)
			for _, addr := range raw_address {
				address = append(address, *(*[20]byte)(unsafe.Pointer(&addr._0)))
			}
		} else {
			address = make([][20]byte, 0)
		}

		var topics [][][32]byte
		if filter.topics.is_something {
			raw_topics := unsafe.Slice(filter.topics.value.data, filter.topics.value.data_len)
			topics := make([][][32]byte, 0, filter.topics.value.data_len)
			for _, topic := range raw_topics {
				if topic.is_something {
					raw_row := unsafe.Slice(topic.value.data, topic.value.data_len)
					go_row := make([][32]byte, 0, topic.value.data_len)

					for _, row := range raw_row {
						go_row = append(go_row, *(*[32]byte)(unsafe.Pointer(&row._0)))
					}
					topics = append(topics, go_row)
				}
			}
		} else {
			topics = make([][][32]byte, 0)
		}

		var limit *uint64 = nil
		if filter.limit.is_something {
			limit = (*uint64)(&filter.limit.value)
		}

		goFilter := Filter{
			FromBlock: fromBlock,
			ToBlock:   toBlock,
			Addresses: address,
			Topics:    topics,
			Limit:     limit,
		}

		logs := (*globalAdapter).EthLogs(goFilter)

		c_logs := make([]C.CLog, 0, len(logs))
		for _, log := range logs {
			topics := make([]C.CH256, 0, len(log.Topics))

			for _, topic := range log.Topics {
				topics = append(topics, C.CH256{_0: *(*[32]C.uint8_t)(unsafe.Pointer(&topic))})
			}

			var blockHash C.COption_CH256
			if log.BlockHash != nil {
				blockHash = C.COption_CH256{is_something: true, value: C.CH256{_0: *(*[32]C.uint8_t)(unsafe.Pointer(log.BlockHash))}}
			} else {
				blockHash = C.COption_CH256{is_something: false}
			}
			var blockNumber C.COption_u64
			if log.BlockNumber != nil {
				blockNumber = C.COption_u64{is_something: true, value: (C.uint64_t)(*log.BlockNumber)}
			} else {
				blockNumber = C.COption_u64{is_something: false}
			}

			var transactionHash C.COption_CH256
			if log.TransactionHash != nil {
				transactionHash = C.COption_CH256{is_something: true, value: C.CH256{_0: *(*[32]C.uint8_t)(unsafe.Pointer(log.TransactionHash))}}
			} else {
				transactionHash = C.COption_CH256{is_something: false}
			}
			var transactionIndex C.COption_u64
			if log.TransactionIndex != nil {
				transactionIndex = C.COption_u64{is_something: true, value: (C.uint64_t)(*log.TransactionIndex)}
			} else {
				transactionIndex = C.COption_u64{is_something: false}
			}

			var logIndex C.COption_CH256
			if log.LogIndex != nil {
				logIndex = C.COption_CH256{is_something: true, value: C.CH256{_0: *(*[32]C.uint8_t)(unsafe.Pointer(log.LogIndex))}}
			} else {
				logIndex = C.COption_CH256{is_something: false}
			}

			var logType C.COption______c_char
			if log.LogType != nil {
				logType = C.COption______c_char{is_something: true, value: C.CString(*log.LogType)}
			} else {
				logType = C.COption______c_char{is_something: false}
			}

			var transactionLogIndex C.COption_CH256
			if log.TransactionLogIndex != nil {
				transactionLogIndex = C.COption_CH256{is_something: true, value: C.CH256{_0: *(*[32]C.uint8_t)(unsafe.Pointer(log.TransactionLogIndex))}}
			} else {
				transactionLogIndex = C.COption_CH256{is_something: false}
			}

			var removed C.COption_bool
			if log.Removed != nil {
				removed = C.COption_bool{is_something: true, value: C.bool(*log.Removed)}
			} else {
				removed = C.COption_bool{is_something: false}
			}

			c_logs = append(c_logs, C.CLog{
				address: *(*[20]C.uint8_t)(unsafe.Pointer(&log.Address)),
				topics: C.CVec_CH256{
					data:     *(**C.CH256)(unsafe.Pointer(&topics)),
					data_len: C.uint64_t(len(topics)),
				},
				data: C.CVec_u8{
					data:     *(**C.uint8_t)(unsafe.Pointer(&log.Data)),
					data_len: C.uint64_t(len(log.Data)),
				},
				block_hash:            blockHash,
				block_number:          blockNumber,
				transaction_hash:      transactionHash,
				transaction_index:     transactionIndex,
				log_index:             logIndex,
				log_type:              logType,
				transaction_log_index: transactionLogIndex,
				removed:               removed,
			})
		}

		return C.CResult_CLogs{error: 0}
	}

	return C.CResult_CLogs{error: 1}
}

//export GoEngineNewPayloadV1
func GoEngineNewPayloadV1(payload C.CExecutionPayloadV1) C.CResult_CPayloadStatusV1 {
	if globalAdapter != nil {
		transactions := make([][]byte, 0, payload.transactions_len)
		raw_transactions := unsafe.Slice(payload.transactions, payload.transactions_len)
		for i := uint64(0); i < uint64(payload.transactions_len); i++ {
			transactions = append(transactions, C.GoBytes(unsafe.Pointer(raw_transactions[i].bytes), (C.int)(raw_transactions[i].bytes_len)))
		}

		payload_status := (*globalAdapter).EngineNewPayloadV1(ExecutionPayloadV1{
			ParentHash:    *(*[32]byte)(unsafe.Pointer(&payload.parent_hash)),
			FeeRecipient:  *(*[20]byte)(unsafe.Pointer(&payload.fee_recipient)),
			StateRoot:     *(*[32]byte)(unsafe.Pointer(&payload.state_root)),
			ReceiptsRoot:  *(*[32]byte)(unsafe.Pointer(&payload.receipts_root)),
			LogsBloom:     C.GoBytes(unsafe.Pointer(payload.logs_bloom), (C.int)(payload.logs_bloom_len)),
			PrevRandao:    *(*[32]byte)(unsafe.Pointer(&payload.prev_randao)),
			BlockNumber:   uint64(payload.block_number),
			GasLimit:      uint64(payload.gas_limit),
			GasUsed:       uint64(payload.gas_used),
			Timestamp:     uint64(payload.timestamp),
			ExtraData:     C.GoBytes(unsafe.Pointer(payload.extra_data), (C.int)(payload.extra_data_len)),
			BaseFeePerGas: *(*[32]byte)(unsafe.Pointer(&payload.base_fee_per_gas)),
			BlockHash:     *(*[32]byte)(unsafe.Pointer(&payload.block_hash)),
			Transactions:  transactions,
		})

		return C.CResult_CPayloadStatusV1{value: goPayloadStatusV1ToC(payload_status), error: 0}
	}

	return C.CResult_CPayloadStatusV1{error: 1}
}

//export GoEngineNewPayloadV2
func GoEngineNewPayloadV2(payload C.CExecutionPayloadV2) C.CResult_CPayloadStatusV1 {
	if globalAdapter != nil {
		transactions := make([][]byte, 0, payload.transactions_len)
		raw_transactions := unsafe.Slice(payload.transactions, payload.transactions_len)
		for i := uint64(0); i < uint64(payload.transactions_len); i++ {
			transactions = append(transactions, C.GoBytes(unsafe.Pointer(raw_transactions[i].bytes), (C.int)(raw_transactions[i].bytes_len)))
		}

		withdrawals := make([]WithdrawalV1, 0, payload.withdrawals_len)
		raw_withdrawals := unsafe.Slice(payload.withdrawals, payload.withdrawals_len)
		for i := uint64(0); i < uint64(payload.withdrawals_len); i++ {
			withdrawals = append(withdrawals, WithdrawalV1{
				Index:          uint64(raw_withdrawals[i].index),
				ValidatorIndex: uint64(raw_withdrawals[i].validator_index),
				Address:        *(*[20]byte)(unsafe.Pointer(&raw_withdrawals[i].address)),
				Amount:         uint64(raw_withdrawals[i].amount),
			})
		}

		payload_status := (*globalAdapter).EngineNewPayloadV2(ExecutionPayloadV2{
			ParentHash:    *(*[32]byte)(unsafe.Pointer(&payload.parent_hash)),
			FeeRecipient:  *(*[20]byte)(unsafe.Pointer(&payload.fee_recipient)),
			StateRoot:     *(*[32]byte)(unsafe.Pointer(&payload.state_root)),
			ReceiptsRoot:  *(*[32]byte)(unsafe.Pointer(&payload.receipts_root)),
			LogsBloom:     C.GoBytes(unsafe.Pointer(payload.logs_bloom), (C.int)(payload.logs_bloom_len)),
			PrevRandao:    *(*[32]byte)(unsafe.Pointer(&payload.prev_randao)),
			BlockNumber:   uint64(payload.block_number),
			GasLimit:      uint64(payload.gas_limit),
			GasUsed:       uint64(payload.gas_used),
			Timestamp:     uint64(payload.timestamp),
			ExtraData:     C.GoBytes(unsafe.Pointer(payload.extra_data), (C.int)(payload.extra_data_len)),
			BaseFeePerGas: *(*[32]byte)(unsafe.Pointer(&payload.base_fee_per_gas)),
			BlockHash:     *(*[32]byte)(unsafe.Pointer(&payload.block_hash)),
			Transactions:  transactions,
			Withdrawals:   withdrawals,
		})

		return C.CResult_CPayloadStatusV1{value: goPayloadStatusV1ToC(payload_status), error: 0}
	}

	return C.CResult_CPayloadStatusV1{error: 1}
}

//export GoEngineNewPayloadV3
func GoEngineNewPayloadV3(payload C.CExecutionPayloadV3, versioned_hashes **C.uint8_t, versioned_hashes_len C.uint64_t, parent_beacon_block_root *C.uint8_t) C.CResult_CPayloadStatusV1 {
	if globalAdapter != nil {
		transactions := make([][]byte, 0, payload.transactions_len)
		raw_transactions := unsafe.Slice(payload.transactions, payload.transactions_len)
		for i := uint64(0); i < uint64(payload.transactions_len); i++ {
			transactions = append(transactions, C.GoBytes(unsafe.Pointer(raw_transactions[i].bytes), (C.int)(raw_transactions[i].bytes_len)))
		}

		withdrawals := make([]WithdrawalV1, 0, payload.withdrawals_len)
		raw_withdrawals := unsafe.Slice(payload.withdrawals, payload.withdrawals_len)
		for i := uint64(0); i < uint64(payload.withdrawals_len); i++ {
			withdrawals = append(withdrawals, WithdrawalV1{
				Index:          uint64(raw_withdrawals[i].index),
				ValidatorIndex: uint64(raw_withdrawals[i].validator_index),
				Address:        *(*[20]byte)(unsafe.Pointer(&raw_withdrawals[i].address)),
				Amount:         uint64(raw_withdrawals[i].amount),
			})
		}

		raw_versioned_hashes := unsafe.Slice(versioned_hashes, versioned_hashes_len)
		versioned_hashes_slice := make([][32]byte, 0, versioned_hashes_len)
		for i := uint64(0); i < uint64(versioned_hashes_len); i++ {
			versioned_hashes_slice = append(versioned_hashes_slice, *(*[32]byte)(C.GoBytes(unsafe.Pointer(raw_versioned_hashes[i]), 32)))
		}

		payload_status := (*globalAdapter).EngineNewPayloadV3(ExecutionPayloadV3{
			ParentHash:    *(*[32]byte)(unsafe.Pointer(&payload.parent_hash)),
			FeeRecipient:  *(*[20]byte)(unsafe.Pointer(&payload.fee_recipient)),
			StateRoot:     *(*[32]byte)(unsafe.Pointer(&payload.state_root)),
			ReceiptsRoot:  *(*[32]byte)(unsafe.Pointer(&payload.receipts_root)),
			LogsBloom:     C.GoBytes(unsafe.Pointer(payload.logs_bloom), (C.int)(payload.logs_bloom_len)),
			PrevRandao:    *(*[32]byte)(unsafe.Pointer(&payload.prev_randao)),
			BlockNumber:   uint64(payload.block_number),
			GasLimit:      uint64(payload.gas_limit),
			GasUsed:       uint64(payload.gas_used),
			Timestamp:     uint64(payload.timestamp),
			ExtraData:     C.GoBytes(unsafe.Pointer(payload.extra_data), (C.int)(payload.extra_data_len)),
			BaseFeePerGas: *(*[32]byte)(unsafe.Pointer(&payload.base_fee_per_gas)),
			BlockHash:     *(*[32]byte)(unsafe.Pointer(&payload.block_hash)),
			Transactions:  transactions,
			Withdrawals:   withdrawals,
			BlobGasUsed:   uint64(payload.blob_gas_used),
			ExcessBlobGas: uint64(payload.excess_blob_gas),
		}, versioned_hashes_slice, *(*[32]byte)(unsafe.Pointer(parent_beacon_block_root)))

		return C.CResult_CPayloadStatusV1{value: goPayloadStatusV1ToC(payload_status), error: 0}
	}

	return C.CResult_CPayloadStatusV1{error: 1}
}

//export GoEngineNewPayloadV4
func GoEngineNewPayloadV4(payload C.CExecutionPayloadV3, versioned_hashes **C.uint8_t, versioned_hashes_len C.uint64_t, parent_beacon_block_root *C.uint8_t, execution_requests C.CExecutionRequests) C.CResult_CPayloadStatusV1 {
	if globalAdapter != nil {
		transactions := make([][]byte, 0, payload.transactions_len)
		raw_transactions := unsafe.Slice(payload.transactions, payload.transactions_len)
		for i := uint64(0); i < uint64(payload.transactions_len); i++ {
			transactions = append(transactions, C.GoBytes(unsafe.Pointer(raw_transactions[i].bytes), (C.int)(raw_transactions[i].bytes_len)))
		}

		withdrawals := make([]WithdrawalV1, 0, payload.withdrawals_len)
		raw_withdrawals := unsafe.Slice(payload.withdrawals, payload.withdrawals_len)
		for i := uint64(0); i < uint64(payload.withdrawals_len); i++ {
			withdrawals = append(withdrawals, WithdrawalV1{
				Index:          uint64(raw_withdrawals[i].index),
				ValidatorIndex: uint64(raw_withdrawals[i].validator_index),
				Address:        *(*[20]byte)(unsafe.Pointer(&raw_withdrawals[i].address)),
				Amount:         uint64(raw_withdrawals[i].amount),
			})
		}

		raw_versioned_hashes := unsafe.Slice(versioned_hashes, versioned_hashes_len)
		versioned_hashes_slice := make([][32]byte, 0, versioned_hashes_len)
		for i := uint64(0); i < uint64(versioned_hashes_len); i++ {
			versioned_hashes_slice = append(versioned_hashes_slice, *(*[32]byte)(C.GoBytes(unsafe.Pointer(raw_versioned_hashes[i]), 32)))
		}

		raw_requests := unsafe.Slice(execution_requests.requests, execution_requests.requests_len)
		requests := make([][]byte, 0, execution_requests.requests_len)
		for _, request := range raw_requests {
			requests = append(requests, C.GoBytes(unsafe.Pointer(request.bytes), C.int(request.bytes_len)))
		}

		payload_status := (*globalAdapter).EngineNewPayloadV4(ExecutionPayloadV3{
			ParentHash:    *(*[32]byte)(unsafe.Pointer(&payload.parent_hash)),
			FeeRecipient:  *(*[20]byte)(unsafe.Pointer(&payload.fee_recipient)),
			StateRoot:     *(*[32]byte)(unsafe.Pointer(&payload.state_root)),
			ReceiptsRoot:  *(*[32]byte)(unsafe.Pointer(&payload.receipts_root)),
			LogsBloom:     C.GoBytes(unsafe.Pointer(payload.logs_bloom), (C.int)(payload.logs_bloom_len)),
			PrevRandao:    *(*[32]byte)(unsafe.Pointer(&payload.prev_randao)),
			BlockNumber:   uint64(payload.block_number),
			GasLimit:      uint64(payload.gas_limit),
			GasUsed:       uint64(payload.gas_used),
			Timestamp:     uint64(payload.timestamp),
			ExtraData:     C.GoBytes(unsafe.Pointer(payload.extra_data), (C.int)(payload.extra_data_len)),
			BaseFeePerGas: *(*[32]byte)(unsafe.Pointer(&payload.base_fee_per_gas)),
			BlockHash:     *(*[32]byte)(unsafe.Pointer(&payload.block_hash)),
			Transactions:  transactions,
			Withdrawals:   withdrawals,
			BlobGasUsed:   uint64(payload.blob_gas_used),
			ExcessBlobGas: uint64(payload.excess_blob_gas),
		}, versioned_hashes_slice, *(*[32]byte)(unsafe.Pointer(parent_beacon_block_root)), requests)

		return C.CResult_CPayloadStatusV1{value: goPayloadStatusV1ToC(payload_status), error: 0}
	}

	return C.CResult_CPayloadStatusV1{error: 1}
}

//export GoEngineForkchoiceUpdatedV1
func GoEngineForkchoiceUpdatedV1(state C.CForkChoiceStateV1, payload C.COption_CPayloadAttributesV1) C.CResult_CForkChoiceUpdatedResponse {
	if globalAdapter != nil {
		go_state := ForkChoiceStateV1{
			HeadBlockHash:      *(*[32]byte)(unsafe.Pointer(&state.head_block_hash)),
			SafeBlockHash:      *(*[32]byte)(unsafe.Pointer(&state.safe_block_hash)),
			FinalizedBlockHash: *(*[32]byte)(unsafe.Pointer(&state.finalized_block_hash)),
		}

		var go_payload *PayloadAttributesV1 = nil

		if payload.is_something {
			go_payload = &PayloadAttributesV1{
				Timestamp:             uint64(payload.value.timestamp),
				PrevRandao:            *(*[32]byte)(unsafe.Pointer(&payload.value.prev_randao)),
				SuggestedFeeRecipient: *(*[20]byte)(unsafe.Pointer(&payload.value.suggested_fee_recipient)),
			}
		}

		response := (*globalAdapter).EngineForkChoiceUpdatedV1(go_state, go_payload)

		var payloadId C.COption_CH64

		if response.PayloadId != nil {
			payloadId = C.COption_CH64{
				is_something: true,
				value:        C.CH64{_0: *(*[8]C.uint8_t)(unsafe.Pointer(response.PayloadId))},
			}
		} else {
			payloadId = C.COption_CH64{
				is_something: false,
			}
		}

		return C.CResult_CForkChoiceUpdatedResponse{value: C.CForkChoiceUpdatedResponse{
			payload_status: goPayloadStatusV1ToC(response.PayloadStatus),
			payload_id:     payloadId,
		}, error: 0}
	}

	return C.CResult_CForkChoiceUpdatedResponse{error: 1}
}

//export GoEngineForkchoiceUpdatedV2
func GoEngineForkchoiceUpdatedV2(state C.CForkChoiceStateV1, payload C.COption_CPayloadAttributesV2) C.CResult_CForkChoiceUpdatedResponse {
	if globalAdapter != nil {
		go_state := ForkChoiceStateV1{
			HeadBlockHash:      *(*[32]byte)(unsafe.Pointer(&state.head_block_hash)),
			SafeBlockHash:      *(*[32]byte)(unsafe.Pointer(&state.safe_block_hash)),
			FinalizedBlockHash: *(*[32]byte)(unsafe.Pointer(&state.finalized_block_hash)),
		}

		var go_payload *PayloadAttributesV2 = nil

		if payload.is_something {
			withdrawals := make([]WithdrawalV1, 0, payload.value.withdrawals_len)
			raw_withdrawals := unsafe.Slice(payload.value.withdrawals, payload.value.withdrawals_len)
			for i := uint64(0); i < uint64(payload.value.withdrawals_len); i++ {
				withdrawals = append(withdrawals, WithdrawalV1{
					Index:          uint64(raw_withdrawals[i].index),
					ValidatorIndex: uint64(raw_withdrawals[i].validator_index),
					Address:        *(*[20]byte)(unsafe.Pointer(&raw_withdrawals[i].address)),
					Amount:         uint64(raw_withdrawals[i].amount),
				})
			}

			go_payload = &PayloadAttributesV2{
				Timestamp:             uint64(payload.value.timestamp),
				PrevRandao:            *(*[32]byte)(unsafe.Pointer(&payload.value.prev_randao)),
				SuggestedFeeRecipient: *(*[20]byte)(unsafe.Pointer(&payload.value.suggested_fee_recipient)),
				Withdrawals:           withdrawals,
			}
		}

		response := (*globalAdapter).EngineForkChoiceUpdatedV2(go_state, go_payload)

		var payloadId C.COption_CH64

		if response.PayloadId != nil {
			payloadId = C.COption_CH64{
				is_something: true,
				value:        C.CH64{_0: *(*[8]C.uint8_t)(unsafe.Pointer(response.PayloadId))},
			}
		} else {
			payloadId = C.COption_CH64{
				is_something: false,
			}
		}

		return C.CResult_CForkChoiceUpdatedResponse{value: C.CForkChoiceUpdatedResponse{
			payload_status: goPayloadStatusV1ToC(response.PayloadStatus),
			payload_id:     payloadId,
		}, error: 0}
	}

	return C.CResult_CForkChoiceUpdatedResponse{error: 1}
}

//export GoEngineForkchoiceUpdatedV3
func GoEngineForkchoiceUpdatedV3(state C.CForkChoiceStateV1, payload C.COption_CPayloadAttributesV3) C.CResult_CForkChoiceUpdatedResponse {
	if globalAdapter != nil {
		go_state := ForkChoiceStateV1{
			HeadBlockHash:      *(*[32]byte)(unsafe.Pointer(&state.head_block_hash)),
			SafeBlockHash:      *(*[32]byte)(unsafe.Pointer(&state.safe_block_hash)),
			FinalizedBlockHash: *(*[32]byte)(unsafe.Pointer(&state.finalized_block_hash)),
		}

		var go_payload *PayloadAttributesV3 = nil

		if payload.is_something {
			withdrawals := make([]WithdrawalV1, 0, payload.value.withdrawals_len)
			raw_withdrawals := unsafe.Slice(payload.value.withdrawals, payload.value.withdrawals_len)
			for i := uint64(0); i < uint64(payload.value.withdrawals_len); i++ {
				withdrawals = append(withdrawals, WithdrawalV1{
					Index:          uint64(raw_withdrawals[i].index),
					ValidatorIndex: uint64(raw_withdrawals[i].validator_index),
					Address:        *(*[20]byte)(unsafe.Pointer(&raw_withdrawals[i].address)),
					Amount:         uint64(raw_withdrawals[i].amount),
				})
			}

			go_payload = &PayloadAttributesV3{
				Timestamp:             uint64(payload.value.timestamp),
				PrevRandao:            *(*[32]byte)(unsafe.Pointer(&payload.value.prev_randao)),
				SuggestedFeeRecipient: *(*[20]byte)(unsafe.Pointer(&payload.value.suggested_fee_recipient)),
				Withdrawals:           withdrawals,
				ParentBeaconBlockRoot: *(*[32]byte)(unsafe.Pointer(&payload.value.parent_beacon_block_root)),
			}
		}

		response := (*globalAdapter).EngineForkChoiceUpdatedV3(go_state, go_payload)

		var payloadId C.COption_CH64

		if response.PayloadId != nil {
			payloadId = C.COption_CH64{
				is_something: true,
				value:        C.CH64{_0: *(*[8]C.uint8_t)(unsafe.Pointer(response.PayloadId))},
			}
		} else {
			payloadId = C.COption_CH64{
				is_something: false,
			}
		}

		return C.CResult_CForkChoiceUpdatedResponse{value: C.CForkChoiceUpdatedResponse{
			payload_status: goPayloadStatusV1ToC(response.PayloadStatus),
			payload_id:     payloadId,
		}, error: 0}
	}

	return C.CResult_CForkChoiceUpdatedResponse{error: 1}
}

//export GoEngineGetPayloadV1
func GoEngineGetPayloadV1(payload_id *C.uint8_t) C.CResult_CExecutionPayloadV1 {
	if globalAdapter != nil {
		payloadId := *(*[8]byte)(unsafe.Pointer(payload_id))

		payload := (*globalAdapter).EngineGetPayloadV1(payloadId)

		transactions := make([]C.CTransaction, 0, len(payload.Transactions))

		for _, transaction := range payload.Transactions {
			transactions = append(transactions, C.CTransaction{
				bytes:     *(**C.uint8_t)(unsafe.Pointer(&transaction)),
				bytes_len: C.uint64_t(len(transaction)),
			})
		}

		return C.CResult_CExecutionPayloadV1{value: C.CExecutionPayloadV1{
			parent_hash:      *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ParentHash)),
			fee_recipient:    *(*[20]C.uint8_t)(unsafe.Pointer(&payload.FeeRecipient)),
			state_root:       *(*[32]C.uint8_t)(unsafe.Pointer(&payload.StateRoot)),
			receipts_root:    *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ReceiptsRoot)),
			logs_bloom:       *(**C.uint8_t)(unsafe.Pointer(&payload.LogsBloom)),
			logs_bloom_len:   C.uint64_t(len(payload.LogsBloom)),
			prev_randao:      *(*[32]C.uint8_t)(unsafe.Pointer(&payload.PrevRandao)),
			block_number:     C.uint64_t(payload.BlockNumber),
			gas_limit:        C.uint64_t(payload.GasLimit),
			gas_used:         C.uint64_t(payload.GasUsed),
			timestamp:        C.uint64_t(payload.Timestamp),
			extra_data:       *(**C.uint8_t)(unsafe.Pointer(&payload.ExtraData)),
			extra_data_len:   C.uint64_t(len(payload.ExtraData)),
			base_fee_per_gas: *(*[32]C.uint8_t)(unsafe.Pointer(&payload.BaseFeePerGas)),
			block_hash:       *(*[32]C.uint8_t)(unsafe.Pointer(&payload.BlockHash)),
			transactions:     *(**C.CTransaction)(unsafe.Pointer(&transactions)),
			transactions_len: C.uint64_t(len(transactions)),
		}, error: 0}
	}

	return C.CResult_CExecutionPayloadV1{error: 1}
}

//export GoEngineGetPayloadV2
func GoEngineGetPayloadV2(payload_id *C.uint8_t) C.CResult_CEngineGetPayloadV2Response {
	if globalAdapter != nil {
		payloadId := *(*[8]byte)(unsafe.Pointer(payload_id))

		payload := (*globalAdapter).EngineGetPayloadV2(payloadId)

		transactions := make([]C.CTransaction, 0, len(payload.ExecutionPayload.Transactions))
		for _, transaction := range payload.ExecutionPayload.Transactions {
			transactions = append(transactions, C.CTransaction{
				bytes:     *(**C.uint8_t)(unsafe.Pointer(&transaction)),
				bytes_len: C.uint64_t(len(transaction)),
			})
		}

		withdrawals := make([]C.CWithdrawalV1, 0, len(payload.ExecutionPayload.Withdrawals))
		for _, withdrawal := range payload.ExecutionPayload.Withdrawals {
			withdrawals = append(withdrawals, C.CWithdrawalV1{
				index:           C.uint64_t(withdrawal.Index),
				validator_index: C.uint64_t(withdrawal.ValidatorIndex),
				address:         *(*[20]C.uint8_t)(unsafe.Pointer(&withdrawal.Address)),
				amount:          C.uint64_t(withdrawal.Amount),
			})
		}

		return C.CResult_CEngineGetPayloadV2Response{value: C.CEngineGetPayloadV2Response{
			execution_payload: C.CExecutionPayloadV2{
				parent_hash:      *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ParentHash)),
				fee_recipient:    *(*[20]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.FeeRecipient)),
				state_root:       *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.StateRoot)),
				receipts_root:    *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ReceiptsRoot)),
				logs_bloom:       *(**C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.LogsBloom)),
				logs_bloom_len:   C.uint64_t(len(payload.ExecutionPayload.LogsBloom)),
				prev_randao:      *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.PrevRandao)),
				block_number:     C.uint64_t(payload.ExecutionPayload.BlockNumber),
				gas_limit:        C.uint64_t(payload.ExecutionPayload.GasLimit),
				gas_used:         C.uint64_t(payload.ExecutionPayload.GasUsed),
				timestamp:        C.uint64_t(payload.ExecutionPayload.Timestamp),
				extra_data:       *(**C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ExtraData)),
				extra_data_len:   C.uint64_t(len(payload.ExecutionPayload.ExtraData)),
				base_fee_per_gas: *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.BaseFeePerGas)),
				block_hash:       *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.BlockHash)),
				transactions:     *(**C.CTransaction)(unsafe.Pointer(&transactions)),
				transactions_len: C.uint64_t(len(transactions)),
				withdrawals:      *(**C.CWithdrawalV1)(unsafe.Pointer(&withdrawals)),
				withdrawals_len:  C.uint64_t(len(withdrawals)),
			},
			block_value: *(*[32]C.uint8_t)(unsafe.Pointer(&payload.BlockValue)),
		}, error: 0}
	}

	return C.CResult_CEngineGetPayloadV2Response{error: 1}
}

//export GoEngineGetPayloadV3
func GoEngineGetPayloadV3(payload_id *C.uint8_t) C.CResult_CEngineGetPayloadV3Response {
	if globalAdapter != nil {
		payloadId := *(*[8]byte)(unsafe.Pointer(payload_id))

		payload := (*globalAdapter).EngineGetPayloadV3(payloadId)

		transactions := make([]C.CTransaction, 0, len(payload.ExecutionPayload.Transactions))
		for _, transaction := range payload.ExecutionPayload.Transactions {
			transactions = append(transactions, C.CTransaction{
				bytes:     *(**C.uint8_t)(unsafe.Pointer(&transaction)),
				bytes_len: C.uint64_t(len(transaction)),
			})
		}

		withdrawals := make([]C.CWithdrawalV1, 0, len(payload.ExecutionPayload.Withdrawals))
		for _, withdrawal := range payload.ExecutionPayload.Withdrawals {
			withdrawals = append(withdrawals, C.CWithdrawalV1{
				index:           C.uint64_t(withdrawal.Index),
				validator_index: C.uint64_t(withdrawal.ValidatorIndex),
				address:         *(*[20]C.uint8_t)(unsafe.Pointer(&withdrawal.Address)),
				amount:          C.uint64_t(withdrawal.Amount),
			})
		}

		commitments := make([][48]C.uint8_t, 0, len(payload.BlobsBundle.Commitments))
		for _, commitment := range payload.BlobsBundle.Commitments {
			commitments = append(commitments, *(*[48]C.uint8_t)(unsafe.Pointer(&commitment)))
		}

		proofs := make([][48]C.uint8_t, 0, len(payload.BlobsBundle.Proofs))
		for _, proof := range payload.BlobsBundle.Proofs {
			proofs = append(proofs, *(*[48]C.uint8_t)(unsafe.Pointer(&proof)))
		}

		blobs := make([]*C.uint8_t, 0, len(payload.BlobsBundle.Blobs))
		for _, blob := range payload.BlobsBundle.Blobs {
			blobs = append(blobs, *(**C.uint8_t)(unsafe.Pointer(&blob)))
		}

		return C.CResult_CEngineGetPayloadV3Response{value: C.CEngineGetPayloadV3Response{
			execution_payload: C.CExecutionPayloadV3{
				parent_hash:      *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ParentHash)),
				fee_recipient:    *(*[20]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.FeeRecipient)),
				state_root:       *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.StateRoot)),
				receipts_root:    *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ReceiptsRoot)),
				logs_bloom:       *(**C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.LogsBloom)),
				logs_bloom_len:   C.uint64_t(len(payload.ExecutionPayload.LogsBloom)),
				prev_randao:      *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.PrevRandao)),
				block_number:     C.uint64_t(payload.ExecutionPayload.BlockNumber),
				gas_limit:        C.uint64_t(payload.ExecutionPayload.GasLimit),
				gas_used:         C.uint64_t(payload.ExecutionPayload.GasUsed),
				timestamp:        C.uint64_t(payload.ExecutionPayload.Timestamp),
				extra_data:       *(**C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ExtraData)),
				extra_data_len:   C.uint64_t(len(payload.ExecutionPayload.ExtraData)),
				base_fee_per_gas: *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.BaseFeePerGas)),
				block_hash:       *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.BlockHash)),
				transactions:     *(**C.CTransaction)(unsafe.Pointer(&transactions)),
				transactions_len: C.uint64_t(len(transactions)),
				withdrawals:      *(**C.CWithdrawalV1)(unsafe.Pointer(&withdrawals)),
				withdrawals_len:  C.uint64_t(len(withdrawals)),
				blob_gas_used:    C.uint64_t(payload.ExecutionPayload.BlobGasUsed),
				excess_blob_gas:  C.uint64_t(payload.ExecutionPayload.ExcessBlobGas),
			},
			block_value: *(*[32]C.uint8_t)(unsafe.Pointer(&payload.BlockValue)),
			blobs_bundle: C.CBlobsBundleV1{
				commitments:     *(**[48]C.uint8_t)(unsafe.Pointer(&commitments)),
				commitments_len: C.uint64_t(len(commitments)),
				proofs:          *(**[48]C.uint8_t)(unsafe.Pointer(&proofs)),
				proofs_len:      C.uint64_t(len(proofs)),
				blobs:           *(***C.uint8_t)(unsafe.Pointer(&blobs)),
				blobs_len:       C.uint64_t(len(blobs)),
			},
			should_override_builder: C.bool(payload.ShouldOverrideBuilder),
		}, error: 0}
	}

	return C.CResult_CEngineGetPayloadV3Response{error: 1}
}

//export GoEngineGetPayloadV4
func GoEngineGetPayloadV4(payload_id *C.uint8_t) C.CResult_CEngineGetPayloadV4Response {
	if globalAdapter != nil {
		payloadId := *(*[8]byte)(unsafe.Pointer(payload_id))

		payload := (*globalAdapter).EngineGetPayloadV4(payloadId)

		transactions := make([]C.CTransaction, 0, len(payload.ExecutionPayload.Transactions))
		for _, transaction := range payload.ExecutionPayload.Transactions {
			transactions = append(transactions, C.CTransaction{
				bytes:     *(**C.uint8_t)(unsafe.Pointer(&transaction)),
				bytes_len: C.uint64_t(len(transaction)),
			})
		}

		withdrawals := make([]C.CWithdrawalV1, 0, len(payload.ExecutionPayload.Withdrawals))
		for _, withdrawal := range payload.ExecutionPayload.Withdrawals {
			withdrawals = append(withdrawals, C.CWithdrawalV1{
				index:           C.uint64_t(withdrawal.Index),
				validator_index: C.uint64_t(withdrawal.ValidatorIndex),
				address:         *(*[20]C.uint8_t)(unsafe.Pointer(&withdrawal.Address)),
				amount:          C.uint64_t(withdrawal.Amount),
			})
		}

		commitments := make([][48]C.uint8_t, 0, len(payload.BlobsBundle.Commitments))
		for _, commitment := range payload.BlobsBundle.Commitments {
			commitments = append(commitments, *(*[48]C.uint8_t)(unsafe.Pointer(&commitment)))
		}

		proofs := make([][48]C.uint8_t, 0, len(payload.BlobsBundle.Proofs))
		for _, proof := range payload.BlobsBundle.Proofs {
			proofs = append(proofs, *(*[48]C.uint8_t)(unsafe.Pointer(&proof)))
		}

		blobs := make([]*C.uint8_t, 0, len(payload.BlobsBundle.Blobs))
		for _, blob := range payload.BlobsBundle.Blobs {
			blobs = append(blobs, *(**C.uint8_t)(unsafe.Pointer(&blob)))
		}

		execution_requests := make([]C.CRequest, 0, len(payload.ExecutionRequests))
		for _, execution_request := range payload.ExecutionRequests {
			execution_requests = append(execution_requests, C.CRequest{
				bytes:     *(**C.uint8_t)(unsafe.Pointer(&execution_request)),
				bytes_len: C.uint64_t(len(execution_request)),
			})
		}

		return C.CResult_CEngineGetPayloadV4Response{value: C.CEngineGetPayloadV4Response{
			execution_payload: C.CExecutionPayloadV3{
				parent_hash:      *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ParentHash)),
				fee_recipient:    *(*[20]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.FeeRecipient)),
				state_root:       *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.StateRoot)),
				receipts_root:    *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ReceiptsRoot)),
				logs_bloom:       *(**C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.LogsBloom)),
				logs_bloom_len:   C.uint64_t(len(payload.ExecutionPayload.LogsBloom)),
				prev_randao:      *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.PrevRandao)),
				block_number:     C.uint64_t(payload.ExecutionPayload.BlockNumber),
				gas_limit:        C.uint64_t(payload.ExecutionPayload.GasLimit),
				gas_used:         C.uint64_t(payload.ExecutionPayload.GasUsed),
				timestamp:        C.uint64_t(payload.ExecutionPayload.Timestamp),
				extra_data:       *(**C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.ExtraData)),
				extra_data_len:   C.uint64_t(len(payload.ExecutionPayload.ExtraData)),
				base_fee_per_gas: *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.BaseFeePerGas)),
				block_hash:       *(*[32]C.uint8_t)(unsafe.Pointer(&payload.ExecutionPayload.BlockHash)),
				transactions:     *(**C.CTransaction)(unsafe.Pointer(&transactions)),
				transactions_len: C.uint64_t(len(transactions)),
				withdrawals:      *(**C.CWithdrawalV1)(unsafe.Pointer(&withdrawals)),
				withdrawals_len:  C.uint64_t(len(withdrawals)),
				blob_gas_used:    C.uint64_t(payload.ExecutionPayload.BlobGasUsed),
				excess_blob_gas:  C.uint64_t(payload.ExecutionPayload.ExcessBlobGas),
			},
			block_value: *(*[32]C.uint8_t)(unsafe.Pointer(&payload.BlockValue)),
			blobs_bundle: C.CBlobsBundleV1{
				commitments:     *(**[48]C.uint8_t)(unsafe.Pointer(&commitments)),
				commitments_len: C.uint64_t(len(commitments)),
				proofs:          *(**[48]C.uint8_t)(unsafe.Pointer(&proofs)),
				proofs_len:      C.uint64_t(len(proofs)),
				blobs:           *(***C.uint8_t)(unsafe.Pointer(&blobs)),
				blobs_len:       C.uint64_t(len(blobs)),
			},
			should_override_builder: C.bool(payload.ShouldOverrideBuilder),
			execution_requests: C.CExecutionRequests{
				requests:     *(**C.CRequest)(unsafe.Pointer(&execution_requests)),
				requests_len: C.uint64_t(len(execution_requests)),
			},
		}, error: 0}
	}

	return C.CResult_CEngineGetPayloadV4Response{error: 1}
}

func SetExecutionLayerAdapter(adapter ELAdapter) {
	globalAdapter = &adapter

	C.grandine_set_execution_layer_adapter(C.CEmbedAdapter{
		eth_block_number:             (C.go_eth_block_number_callback)(unsafe.Pointer(C.go_eth_block_number)),
		eth_get_block_by_hash:        (C.go_eth_get_block_by_hash_callback)(unsafe.Pointer(C.go_eth_get_block_by_hash)),
		eth_get_block_by_number:      (C.go_eth_get_block_by_number_callback)(unsafe.Pointer(C.go_eth_get_block_by_number)),
		eth_get_block_finalized:      (C.go_eth_get_block_finalized_callback)(unsafe.Pointer(C.go_eth_get_block_finalized)),
		eth_get_block_safe:           (C.go_eth_get_block_safe_callback)(unsafe.Pointer(C.go_eth_get_block_safe)),
		eth_get_block_latest:         (C.go_eth_get_block_latest_callback)(unsafe.Pointer(C.go_eth_get_block_latest)),
		eth_get_block_earliest:       (C.go_eth_get_block_earliest_callback)(unsafe.Pointer(C.go_eth_get_block_earliest)),
		eth_get_block_pending:        (C.go_eth_get_block_pending_callback)(unsafe.Pointer(C.go_eth_get_block_pending)),
		eth_logs:                     (C.go_eth_logs_callback)(unsafe.Pointer(C.go_eth_logs)),
		engine_new_payload_v1:        (C.go_engine_new_payload_v1_callback)(unsafe.Pointer(C.go_engine_new_payload_v1)),
		engine_new_payload_v2:        (C.go_engine_new_payload_v2_callback)(unsafe.Pointer(C.go_engine_new_payload_v2)),
		engine_new_payload_v3:        (C.go_engine_new_payload_v3_callback)(unsafe.Pointer(C.go_engine_new_payload_v3)),
		engine_new_payload_v4:        (C.go_engine_new_payload_v4_callback)(unsafe.Pointer(C.go_engine_new_payload_v4)),
		engine_forkchoice_updated_v1: (C.go_engine_forkchoice_updated_v1_callback)(unsafe.Pointer(C.go_engine_forkchoice_updated_v1)),
		engine_forkchoice_updated_v2: (C.go_engine_forkchoice_updated_v2_callback)(unsafe.Pointer(C.go_engine_forkchoice_updated_v2)),
		engine_forkchoice_updated_v3: (C.go_engine_forkchoice_updated_v3_callback)(unsafe.Pointer(C.go_engine_forkchoice_updated_v3)),
		engine_get_payload_v1:        (C.go_engine_get_payload_v1_callback)(unsafe.Pointer(C.go_engine_get_payload_v1)),
		engine_get_payload_v2:        (C.go_engine_get_payload_v2_callback)(unsafe.Pointer(C.go_engine_get_payload_v2)),
		engine_get_payload_v3:        (C.go_engine_get_payload_v3_callback)(unsafe.Pointer(C.go_engine_get_payload_v3)),
		engine_get_payload_v4:        (C.go_engine_get_payload_v4_callback)(unsafe.Pointer(C.go_engine_get_payload_v4)),
	})
}
