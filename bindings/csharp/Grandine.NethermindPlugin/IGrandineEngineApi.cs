namespace Grandine.NethermindPlugin;

using Grandine.Native;

public interface IGrandineEngineApi
{
    unsafe CResult_CPayloadStatusV1 EngineNewPayloadV1(CExecutionPayloadV1* payload);

    unsafe CResult_CPayloadStatusV1 EngineNewPayloadV2(CExecutionPayloadV2* payload);

    unsafe CResult_CPayloadStatusV1 EngineNewPayloadV3(CExecutionPayloadV3* payload, CVec_CH256* versionedHashes, CH256 parentBeaconBlockRoot);

    unsafe CResult_CPayloadStatusV1 EngineNewPayloadV4(CExecutionPayloadV3* payload, CVec_CH256* versionedHashes, CH256 parentBeaconBlockRoot, CExecutionRequests* executionRequests);

    unsafe CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV1(CForkChoiceStateV1 state, COption_CPayloadAttributesV1 payload);

    unsafe CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV2(CForkChoiceStateV1 state, COption_CPayloadAttributesV2* payload);

    unsafe CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV3(CForkChoiceStateV1 state, COption_CPayloadAttributesV3* payload);

    CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV4(CForkChoiceStateV1 state, COption_CPayloadAttributesV4 payload);

    CResult_CExecutionPayloadV1 EngineGetPayloadV1(CH64 payloadId);

    CResult_CEngineGetPayloadV2Response EngineGetPayloadV2(CH64 payloadId);

    CResult_CEngineGetPayloadV3Response EngineGetPayloadV3(CH64 payloadId);

    CResult_CEngineGetPayloadV4Response EngineGetPayloadV4(CH64 payloadId);

    CResult_CEngineGetPayloadV5Response EngineGetPayloadV5(CH64 payloadId);

    unsafe CResult_CVec_COption_CBlobAndProofV1 EngineGetBlobsV1(CVec_CH256* versionedHashes);

    unsafe CResult_COption_CVec_CBlobAndProofV2 EngineGetBlobsV2(CVec_CH256* versionedHashes);

    unsafe CResult_CVec_CGrandineString EngineExchangeCapabilities(CVec_CGrandineString* capabilities);

    unsafe CResult_CVec_CClientVersionV1 EngineGetClientVersionV1(CClientVersionV1* version);
}
