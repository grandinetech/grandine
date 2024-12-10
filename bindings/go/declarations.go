package grandine

/*
#include <stdint.h>
#include "./lib/c_grandine.h"

CResult_u64 go_eth_block_number(void) {
	CResult_u64 GoEthBlockNumber(void);

	return GoEthBlockNumber();
}

CResult_COption_CEth1Block go_eth_get_block_by_hash(uint8_t *hash) {
	CResult_COption_CEth1Block GoEthGetBlockByHash(uint8_t *hash);

	return GoEthGetBlockByHash(hash);
}

CResult_COption_CEth1Block go_eth_get_block_by_number(uint64_t number) {
	CResult_COption_CEth1Block GoEthGetBlockByNumber(uint64_t number);

	return GoEthGetBlockByNumber(number);
}

CResult_COption_CEth1Block go_eth_get_block_finalized(void) {
	CResult_COption_CEth1Block GoEthGetBlockFinalized(void);

	return GoEthGetBlockFinalized();
}
CResult_COption_CEth1Block go_eth_get_block_safe(void) {
	CResult_COption_CEth1Block GoEthGetBlockSafe(void);

	return GoEthGetBlockSafe();
}
CResult_COption_CEth1Block go_eth_get_block_latest(void) {
	CResult_COption_CEth1Block GoEthGetBlockLatest(void);

	return GoEthGetBlockLatest();
}
CResult_COption_CEth1Block go_eth_get_block_earliest(void) {
	CResult_COption_CEth1Block GoEthGetBlockEarliest(void);

	return GoEthGetBlockEarliest();
}
CResult_COption_CEth1Block go_eth_get_block_pending(void) {
	CResult_COption_CEth1Block GoEthGetBlockPending(void);

	return GoEthGetBlockPending();
}
CResult_CPayloadStatusV1 go_engine_new_payload_v1(CExecutionPayloadV1 payload) {
	CResult_CPayloadStatusV1 GoEngineNewPayloadV1(CExecutionPayloadV1 payload);

	return GoEngineNewPayloadV1(payload);
}
CResult_CPayloadStatusV1 go_engine_new_payload_v2(CExecutionPayloadV2 payload) {
	CResult_CPayloadStatusV1 GoEngineNewPayloadV2(CExecutionPayloadV2 payload);

	return GoEngineNewPayloadV2(payload);
}
CResult_CPayloadStatusV1 go_engine_new_payload_v3(CExecutionPayloadV3 payload, const uint8_t (*versioned_hashes)[32], uint64_t versioned_hashes_len, uint8_t parent_beacon_block_root[32]) {
	CResult_CPayloadStatusV1 GoEngineNewPayloadV3(CExecutionPayloadV3 payload, const uint8_t (*versioned_hashes)[32], uint64_t versioned_hashes_len, uint8_t parent_beacon_block_root[32]);

	return GoEngineNewPayloadV3(payload, versioned_hashes, versioned_hashes_len, parent_beacon_block_root);
}
CResult_CPayloadStatusV1 go_engine_new_payload_v4(CExecutionPayloadV3 payload, const uint8_t (*versioned_hashes)[32], uint64_t versioned_hashes_len, uint8_t parent_beacon_block_root[32], CExecutionRequests execution_requests) {
	CResult_CPayloadStatusV1 GoEngineNewPayloadV4(CExecutionPayloadV3 payload, const uint8_t (*versioned_hashes)[32], uint64_t versioned_hashes_len, uint8_t parent_beacon_block_root[32], CExecutionRequests execution_requests);

	return GoEngineNewPayloadV4(payload, versioned_hashes, versioned_hashes_len, parent_beacon_block_root, execution_requests);
}
CResult_CForkChoiceUpdatedResponse go_engine_forkchoice_updated_v1(CForkChoiceStateV1 state, COption_CPayloadAttributesV1 payload) {
	CResult_CForkChoiceUpdatedResponse GoEngineForkchoiceUpdatedV1(CForkChoiceStateV1 state, COption_CPayloadAttributesV1 payload);

	return GoEngineForkchoiceUpdatedV1(state, payload);
}
CResult_CForkChoiceUpdatedResponse go_engine_forkchoice_updated_v2(CForkChoiceStateV1 state, COption_CPayloadAttributesV2 payload) {
	CResult_CForkChoiceUpdatedResponse GoEngineForkchoiceUpdatedV2(CForkChoiceStateV1 state, COption_CPayloadAttributesV2 payload);

	return GoEngineForkchoiceUpdatedV2(state, payload);
}
CResult_CForkChoiceUpdatedResponse go_engine_forkchoice_updated_v3(CForkChoiceStateV1 state, COption_CPayloadAttributesV3 payload) {
	CResult_CForkChoiceUpdatedResponse GoEngineForkchoiceUpdatedV3(CForkChoiceStateV1 state, COption_CPayloadAttributesV3 payload);

	return GoEngineForkchoiceUpdatedV3(state, payload);
}
CResult_CExecutionPayloadV1 go_engine_get_payload_v1(uint8_t *payload_id) {
	CResult_CExecutionPayloadV1 GoEngineGetPayloadV1(uint8_t *payload_id);

	return GoEngineGetPayloadV1(payload_id);
}
CResult_CEngineGetPayloadV2Response go_engine_get_payload_v2(uint8_t *payload_id) {
	CResult_CEngineGetPayloadV2Response GoEngineGetPayloadV2(uint8_t *payload_id);

	return GoEngineGetPayloadV2(payload_id);
}
CResult_CEngineGetPayloadV3Response go_engine_get_payload_v3(uint8_t *payload_id) {
	CResult_CEngineGetPayloadV3Response GoEngineGetPayloadV3(uint8_t *payload_id);

	return GoEngineGetPayloadV3(payload_id);
}
CResult_CEngineGetPayloadV4Response go_engine_get_payload_v4(uint8_t *payload_id) {
	CResult_CEngineGetPayloadV4Response GoEngineGetPayloadV4(uint8_t *payload_id);

	return GoEngineGetPayloadV4(payload_id);
}
CResult_CLogs go_eth_logs(CFilter filter) {
	CResult_CLogs GoEthLogs(CFilter filter);

	return GoEthLogs(filter);
}
*/
import "C"
