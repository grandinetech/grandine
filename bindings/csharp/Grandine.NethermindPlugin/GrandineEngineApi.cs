namespace Grandine.NethermindPlugin;

using System.Runtime.InteropServices;
using Grandine.Native;
using Nethermind.Core;
using Nethermind.Logging;
using Nethermind.Merge.Plugin;
using Nethermind.Merge.Plugin.Data;

public class GrandineEngineApi : IGrandineEngineApi
{
    private readonly ILogger logger;
    private readonly IEngineRpcModule engineRpc;

    public GrandineEngineApi(ILogger logger, IEngineRpcModule engineRpc)
    {
        this.logger = logger;
        this.engineRpc = engineRpc;
    }

    public CResult_CPayloadStatusV1 EngineNewPayloadV1(CExecutionPayloadV1 payload)
    {
        this.logger.Debug("Received engine_newPayloadV1 request from grandine");

        try
        {
            var payloadStatus = this.engineRpc.engine_newPayloadV1(new ExecutionPayload
            {
                ParentHash = payload.parent_hash.ToHash256(),
                FeeRecipient = payload.fee_recipient.ToAddress(),
                StateRoot = payload.state_root.ToHash256(),
                ReceiptsRoot = payload.receipts_root.ToHash256(),
                LogsBloom = new Bloom(payload.logs_bloom.AsSpan()),
                PrevRandao = payload.prev_randao.ToHash256(),
                BlockNumber = (long)payload.block_number,
                GasLimit = (long)payload.gas_limit,
                GasUsed = (long)payload.gas_used,
                Timestamp = payload.timestamp,
                ExtraData = payload.extra_data.AsSpan().ToArray(),
                BaseFeePerGas = payload.base_fee_per_gas.ToUInt256(),
                BlockHash = payload.block_hash.ToHash256(),
                Transactions = GrandineUtils.TransactionsToBytes(payload.transactions),
            }).Result;

            return payloadStatus.Result != Result.Success
                ? CResult_CPayloadStatusV1.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payloadStatus.Result.Error)
                : CResult_CPayloadStatusV1.Success(new CPayloadStatusV1(payloadStatus.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_newPayloadV1 function invocation", e);
            return CResult_CPayloadStatusV1.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CPayloadStatusV1 EngineNewPayloadV2(CExecutionPayloadV2 payload)
    {
        this.logger.Debug("Received engine_newPayloadV2 request from grandine");

        try
        {
            var withdrawals = GrandineUtils.WithdrawalsFromNative(payload.withdrawals);

            var payloadStatus = this.engineRpc.engine_newPayloadV2(new ExecutionPayload
            {
                ParentHash = payload.parent_hash.ToHash256(),
                FeeRecipient = payload.fee_recipient.ToAddress(),
                StateRoot = payload.state_root.ToHash256(),
                ReceiptsRoot = payload.receipts_root.ToHash256(),
                LogsBloom = new Bloom(payload.logs_bloom.AsSpan()),
                PrevRandao = payload.prev_randao.ToHash256(),
                BlockNumber = (long)payload.block_number,
                GasLimit = (long)payload.gas_limit,
                GasUsed = (long)payload.gas_used,
                Timestamp = payload.timestamp,
                ExtraData = payload.extra_data.AsSpan().ToArray(),
                BaseFeePerGas = payload.base_fee_per_gas.ToUInt256(),
                BlockHash = payload.block_hash.ToHash256(),
                Transactions = GrandineUtils.TransactionsToBytes(payload.transactions),
                Withdrawals = withdrawals,
            }).Result;

            GrandineUtils.ReturnWithdrawals(withdrawals);

            return payloadStatus.Result != Result.Success
                ? CResult_CPayloadStatusV1.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payloadStatus.Result.Error)
                : CResult_CPayloadStatusV1.Success(new CPayloadStatusV1(payloadStatus.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_newPayloadV2 function invocation", e);
            return CResult_CPayloadStatusV1.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CPayloadStatusV1 EngineNewPayloadV3(CExecutionPayloadV3 payload, CVec_CH256 versionedHashes, CH256 parentBeaconBlockRoot)
    {
        this.logger.Debug("Received engine_newPayloadV3 request from grandine");

        try
        {
            var withdrawals = GrandineUtils.WithdrawalsFromNative(payload.withdrawals);
            var parentBeaconBlockRootConverted = parentBeaconBlockRoot.ToHash256();

            var payloadStatus = this.engineRpc.engine_newPayloadV3(
                new ExecutionPayloadV3
                {
                    ParentHash = payload.parent_hash.ToHash256(),
                    FeeRecipient = payload.fee_recipient.ToAddress(),
                    StateRoot = payload.state_root.ToHash256(),
                    ReceiptsRoot = payload.receipts_root.ToHash256(),
                    LogsBloom = new Bloom(payload.logs_bloom.AsSpan()),
                    PrevRandao = payload.prev_randao.ToHash256(),
                    BlockNumber = (long)payload.block_number,
                    GasLimit = (long)payload.gas_limit,
                    GasUsed = (long)payload.gas_used,
                    Timestamp = payload.timestamp,
                    ExtraData = payload.extra_data.AsSpan().ToArray(),
                    BaseFeePerGas = payload.base_fee_per_gas.ToUInt256(),
                    BlockHash = payload.block_hash.ToHash256(),
                    Transactions = GrandineUtils.TransactionsToBytes(payload.transactions),
                    Withdrawals = withdrawals,
                    BlobGasUsed = payload.blob_gas_used,
                    ExcessBlobGas = payload.excess_blob_gas,
                    ParentBeaconBlockRoot = parentBeaconBlockRootConverted,
                },
                GrandineUtils.ConvertVersionedHashes(versionedHashes),
                parentBeaconBlockRootConverted)
            .Result;

            GrandineUtils.ReturnWithdrawals(withdrawals);

            return payloadStatus.Result != Result.Success
                ? CResult_CPayloadStatusV1.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payloadStatus.Result.Error)
                : CResult_CPayloadStatusV1.Success(new CPayloadStatusV1(payloadStatus.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_newPayloadV3 function invocation", e);
            return CResult_CPayloadStatusV1.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CPayloadStatusV1 EngineNewPayloadV4(CExecutionPayloadV3 payload, CVec_CH256 versionedHashes, CH256 parentBeaconBlockRoot, CExecutionRequests executionRequests)
    {
        this.logger.Debug("Received engine_newPayloadV4 request from grandine");

        try
        {
            var withdrawals = GrandineUtils.WithdrawalsFromNative(payload.withdrawals);
            var executionRequestsConverted = GrandineUtils.ConvertExecutionRequests(executionRequests);
            var parentBeaconBlockRootConverted = parentBeaconBlockRoot.ToHash256();

            var payloadStatus = this.engineRpc.engine_newPayloadV4(
                new ExecutionPayloadV3
                {
                    ParentHash = payload.parent_hash.ToHash256(),
                    FeeRecipient = payload.fee_recipient.ToAddress(),
                    StateRoot = payload.state_root.ToHash256(),
                    ReceiptsRoot = payload.receipts_root.ToHash256(),
                    LogsBloom = new Bloom(payload.logs_bloom.AsSpan()),
                    PrevRandao = payload.prev_randao.ToHash256(),
                    BlockNumber = (long)payload.block_number,
                    GasLimit = (long)payload.gas_limit,
                    GasUsed = (long)payload.gas_used,
                    Timestamp = payload.timestamp,
                    ExtraData = payload.extra_data.AsSpan().ToArray(),
                    BaseFeePerGas = payload.base_fee_per_gas.ToUInt256(),
                    BlockHash = payload.block_hash.ToHash256(),
                    Transactions = GrandineUtils.TransactionsToBytes(payload.transactions),
                    Withdrawals = withdrawals,
                    BlobGasUsed = payload.blob_gas_used,
                    ExcessBlobGas = payload.excess_blob_gas,
                    ParentBeaconBlockRoot = parentBeaconBlockRootConverted,
                    ExecutionRequests = executionRequestsConverted,
                },
                GrandineUtils.ConvertVersionedHashes(versionedHashes),
                parentBeaconBlockRootConverted,
                executionRequestsConverted)
            .Result;

            GrandineUtils.ReturnWithdrawals(withdrawals);

            return payloadStatus.Result != Result.Success
                ? CResult_CPayloadStatusV1.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payloadStatus.Result.Error)
                : CResult_CPayloadStatusV1.Success(new CPayloadStatusV1(payloadStatus.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_newPayloadV4 function invocation", e);
            return CResult_CPayloadStatusV1.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV1(CForkChoiceStateV1 state, COption_CPayloadAttributesV1 payload)
    {
        this.logger.Debug("Received engine_forkchoiceUpdatedV1 request from grandine");

        try
        {
            var forkchoiceUpdatedResult = this.engineRpc.engine_forkchoiceUpdatedV1(
                state.ToForkchoiceStateV1(),
                GrandineUtils.ConvertPayloadAttributes(payload)).Result;

            return forkchoiceUpdatedResult.Result != Result.Success
                ? CResult_CForkChoiceUpdatedResponse.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, forkchoiceUpdatedResult.Result.Error)
                : CResult_CForkChoiceUpdatedResponse.Success(new CForkChoiceUpdatedResponse(forkchoiceUpdatedResult.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_forkchoiceUpdatedV1 function invocation", e);
            return CResult_CForkChoiceUpdatedResponse.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV2(CForkChoiceStateV1 state, COption_CPayloadAttributesV2 payload)
    {
        this.logger.Debug("Received engine_forkchoiceUpdatedV2 request from grandine");

        try
        {
            var forkchoiceUpdatedResult = this.engineRpc.engine_forkchoiceUpdatedV2(
                state.ToForkchoiceStateV1(),
                GrandineUtils.ConvertPayloadAttributes(payload)).Result;

            return forkchoiceUpdatedResult.Result != Result.Success
                ? CResult_CForkChoiceUpdatedResponse.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, forkchoiceUpdatedResult.Result.Error)
                : CResult_CForkChoiceUpdatedResponse.Success(new CForkChoiceUpdatedResponse(forkchoiceUpdatedResult.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_forkchoiceUpdatedV2 function invocation", e);
            return CResult_CForkChoiceUpdatedResponse.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CForkChoiceUpdatedResponse EngineForkchoiceUpdatedV3(CForkChoiceStateV1 state, COption_CPayloadAttributesV3 payload)
    {
        this.logger.Debug("Received engine_forkchoiceUpdatedV3 request from grandine");

        try
        {
            var forkchoiceUpdatedResult = this.engineRpc.engine_forkchoiceUpdatedV3(
                state.ToForkchoiceStateV1(),
                GrandineUtils.ConvertPayloadAttributes(payload)).Result;

            return forkchoiceUpdatedResult.Result != Result.Success
                ? CResult_CForkChoiceUpdatedResponse.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, forkchoiceUpdatedResult.Result.Error)
                : CResult_CForkChoiceUpdatedResponse.Success(new CForkChoiceUpdatedResponse(forkchoiceUpdatedResult.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_forkchoiceUpdatedV3 function invocation", e);
            return CResult_CForkChoiceUpdatedResponse.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CExecutionPayloadV1 EngineGetPayloadV1(CH64 payloadId)
    {
        this.logger.Debug("Received engine_getPayloadV1 request from grandine");

        try
        {
            var payload = this.engineRpc.engine_getPayloadV1(payloadId.ToArray()).Result;

            if (payload.Result != Result.Success)
            {
                return CResult_CExecutionPayloadV1.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payload.Result.Error);
            }

            if (payload.Data == null)
            {
                return CResult_CExecutionPayloadV1.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, "payload not found");
            }

            return CResult_CExecutionPayloadV1.Success(new CExecutionPayloadV1(payload.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_getPayloadV1 function invocation", e);
            return CResult_CExecutionPayloadV1.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CEngineGetPayloadV2Response EngineGetPayloadV2(CH64 payloadId)
    {
        this.logger.Debug("Received engine_getPayloadV2 request from grandine");

        try
        {
            var payload = this.engineRpc.engine_getPayloadV2(payloadId.ToArray()).Result;

            if (payload.Result != Result.Success)
            {
                return CResult_CEngineGetPayloadV2Response.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payload.Result.Error);
            }

            if (payload.Data == null)
            {
                return CResult_CEngineGetPayloadV2Response.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, "payload not found");
            }

            return CResult_CEngineGetPayloadV2Response.Success(new CEngineGetPayloadV2Response(payload.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_getPayloadV2 function invocation", e);
            return CResult_CEngineGetPayloadV2Response.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CEngineGetPayloadV3Response EngineGetPayloadV3(CH64 payloadId)
    {
        this.logger.Debug("Received engine_getPayloadV3 request from grandine");

        try
        {
            var payload = this.engineRpc.engine_getPayloadV3(payloadId.ToArray()).Result;

            if (payload.Result != Result.Success)
            {
                return CResult_CEngineGetPayloadV3Response.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payload.Result.Error);
            }

            if (payload.Data == null)
            {
                return CResult_CEngineGetPayloadV3Response.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, "payload not found");
            }

            return CResult_CEngineGetPayloadV3Response.Success(new CEngineGetPayloadV3Response(payload.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_getPayloadV3 function invocation", e);
            return CResult_CEngineGetPayloadV3Response.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CEngineGetPayloadV4Response EngineGetPayloadV4(CH64 payloadId)
    {
        this.logger.Debug("Received engine_getPayloadV4 request from grandine");

        try
        {
            var payload = this.engineRpc.engine_getPayloadV4(payloadId.ToArray()).Result;

            if (payload.Result != Result.Success)
            {
                return CResult_CEngineGetPayloadV4Response.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payload.Result.Error);
            }

            if (payload.Data == null)
            {
                return CResult_CEngineGetPayloadV4Response.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, "payload not found");
            }

            return CResult_CEngineGetPayloadV4Response.Success(new CEngineGetPayloadV4Response(payload.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_getPayloadV4 function invocation", e);
            return CResult_CEngineGetPayloadV4Response.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CEngineGetPayloadV5Response EngineGetPayloadV5(CH64 payloadId)
    {
        this.logger.Debug("Received engine_getPayloadV5 request from grandine");

        try
        {
            var payload = this.engineRpc.engine_getPayloadV5(payloadId.ToArray()).Result;

            if (payload.Result != Result.Success)
            {
                return CResult_CEngineGetPayloadV5Response.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, payload.Result.Error);
            }

            if (payload.Data == null)
            {
                return CResult_CEngineGetPayloadV5Response.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, "payload not found");
            }

            return CResult_CEngineGetPayloadV5Response.Success(new CEngineGetPayloadV5Response(payload.Data));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_getPayloadV5 function invocation", e);
            return CResult_CEngineGetPayloadV5Response.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_CVec_COption_CBlobAndProofV1 EngineGetBlobsV1(CVec_CH256 versionedHashes)
    {
        this.logger.Debug("Received engine_getBlobsV1 request from grandine");

        try
        {
            var blobs = this.engineRpc.engine_getBlobsV1(GrandineUtils.ConvertVersionedHashes(versionedHashes)).Result;

            if (blobs.Result != Result.Success)
            {
                return CResult_CVec_COption_CBlobAndProofV1.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, blobs.Result.Error);
            }

            var blobArray = new CVec_COption_CBlobAndProofV1(blobs.Data.Select(blob =>
            {
                if (blob == null)
                {
                    return COption_CBlobAndProofV1.None;
                }

                return COption_CBlobAndProofV1.Some(new CBlobAndProofV1(blob));
            }));

            return CResult_CVec_COption_CBlobAndProofV1.Success(blobArray);
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_getBlobsV1 function invocation", e);
            return CResult_CVec_COption_CBlobAndProofV1.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }

    public CResult_COption_CVec_CBlobAndProofV2 EngineGetBlobsV2(CVec_CH256 versionedHashes)
    {
        this.logger.Debug("Received engine_getBlobsV2 request from grandine");

        try
        {
            var blobs = this.engineRpc.engine_getBlobsV2(GrandineUtils.ConvertVersionedHashes(versionedHashes)).Result;

            if (blobs.Result != Result.Success)
            {
                return CResult_COption_CVec_CBlobAndProofV2.Fail(NativeMethods.GRANDINE_ERROR_ENGINE_API, blobs.Result.Error);
            }

            if (blobs.Data == null)
            {
                return CResult_COption_CVec_CBlobAndProofV2.Success(COption_CVec_CBlobAndProofV2.None);
            }

            var blobArray = new CVec_CBlobAndProofV2(blobs.Data.Select(blob =>
            {
                return new CBlobAndProofV2(blob);
            }));

            return CResult_COption_CVec_CBlobAndProofV2.Success(COption_CVec_CBlobAndProofV2.Some(blobArray));
        }
        catch (Exception e)
        {
            this.logger.Error("Unexpected exception occurred during engine_getBlobsV2 function invocation", e);
            return CResult_COption_CVec_CBlobAndProofV2.Fail(NativeMethods.GRANDINE_ERROR_GENERIC, e.Message);
        }
    }
}