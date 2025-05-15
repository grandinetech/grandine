using Nethermind.Logging;
using Nethermind.JsonRpc.Modules;
using Nethermind.Merge.Plugin;
using Nethermind.Core.Crypto;
using Nethermind.Facade;
using Nethermind.Consensus.Producers;
using Grandine.Bindings;
using Grandine.Native;
using static Grandine.Native.NativeMethods;
using Nethermind.Int256;
using Nethermind.Core;
using Nethermind.Merge.Plugin.Data;
using Nethermind.JsonRpc.Modules.Eth;
using System.Collections.Generic;
using System;
using System.Linq;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Text;

namespace Grandine.Bindings;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCPayloadStatusV1 EngineNewPayloadV1Delegate(CExecutionPayloadV1 payload);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCPayloadStatusV1 EngineNewPayloadV2Delegate(CExecutionPayloadV2 payload);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCPayloadStatusV1 EngineNewPayloadV3Delegate(CExecutionPayloadV3 payload, byte** versionedHashes, ulong versionedHashesLen, byte* parentBeaconBlockRoot);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCPayloadStatusV1 EngineNewPayloadV4Delegate(CExecutionPayloadV3 payload, byte** versionedHashes, ulong versionedHashesLen, byte* parentBeaconBlockRoot, CExecutionRequests executionRequests);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV1Delegate(CForkChoiceStateV1 state, COptionCPayloadAttributesV1 attributes);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV2Delegate(CForkChoiceStateV1 state, COptionCPayloadAttributesV2 attributes);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV3Delegate(CForkChoiceStateV1 state, COptionCPayloadAttributesV3 attributes);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCExecutionPayloadV1 EngineGetPayloadV1Delegate(byte *payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCEngineGetPayloadV2Response EngineGetPayloadV2Delegate(byte* payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCEngineGetPayloadV3Response EngineGetPayloadV3Delegate(byte* payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCEngineGetPayloadV4Response EngineGetPayloadV4Delegate(byte* payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCVecCOptionCBlobAndProofV1 EngineGetBlobsV1Delegate(byte** versionedHashes, ulong versionedHashesLen);

public class GrandineEngineApi
{
    EngineNewPayloadV1Delegate _engine_newPayloadV1;
    EngineNewPayloadV2Delegate _engine_newPayloadV2;
    EngineNewPayloadV3Delegate _engine_newPayloadV3;
    EngineNewPayloadV4Delegate _engine_newPayloadV4;
    EngineForkchoiceUpdatedV1Delegate _engine_forkchoiceUpdatedV1;
    EngineForkchoiceUpdatedV2Delegate _engine_forkchoiceUpdatedV2;
    EngineForkchoiceUpdatedV3Delegate _engine_forkchoiceUpdatedV3;
    EngineGetPayloadV1Delegate _engine_getPayloadV1;
    EngineGetPayloadV2Delegate _engine_getPayloadV2;
    EngineGetPayloadV3Delegate _engine_getPayloadV3;
    EngineGetPayloadV4Delegate _engine_getPayloadV4;
    EngineGetBlobsV1Delegate _engine_getBlobsV1;

    ILogger _logger; 
    IEngineRpcModule _engineRpc;

    CEmbedAdapter _adapter;

    public GrandineEngineApi(ILogger logger, IEngineRpcModule engineRpc) {
        _logger = logger;
        _engineRpc = engineRpc;

        unsafe
        {
            _engine_newPayloadV1 = EngineNewPayloadV1;
            _engine_newPayloadV2 = EngineNewPayloadV2;
            _engine_newPayloadV3 = EngineNewPayloadV3;
            _engine_newPayloadV4 = EngineNewPayloadV4;
            _engine_forkchoiceUpdatedV1 = EngineForkchoiceUpdatedV1;
            _engine_forkchoiceUpdatedV2 = EngineForkchoiceUpdatedV2;
            _engine_forkchoiceUpdatedV3 = EngineForkchoiceUpdatedV3;
            _engine_getPayloadV1 = EngineGetPayloadV1;
            _engine_getPayloadV2 = EngineGetPayloadV2;
            _engine_getPayloadV3 = EngineGetPayloadV3;
            _engine_getPayloadV4 = EngineGetPayloadV4;
            _engine_getBlobsV1 = EngineGetBlobsV1;

            IntPtr engine_newPayloadV1Ptr = Marshal.GetFunctionPointerForDelegate(_engine_newPayloadV1);
            IntPtr engine_newPayloadV2Ptr = Marshal.GetFunctionPointerForDelegate(_engine_newPayloadV2);
            IntPtr engine_newPayloadV3Ptr = Marshal.GetFunctionPointerForDelegate(_engine_newPayloadV3);
            IntPtr engine_newPayloadV4Ptr = Marshal.GetFunctionPointerForDelegate(_engine_newPayloadV4);
            IntPtr engine_forkchoiceUpdatedV1Ptr = Marshal.GetFunctionPointerForDelegate(_engine_forkchoiceUpdatedV1);
            IntPtr engine_forkchoiceUpdatedV2Ptr = Marshal.GetFunctionPointerForDelegate(_engine_forkchoiceUpdatedV2);
            IntPtr engine_forkchoiceUpdatedV3Ptr = Marshal.GetFunctionPointerForDelegate(_engine_forkchoiceUpdatedV3);
            IntPtr engine_getPayloadV1Ptr = Marshal.GetFunctionPointerForDelegate(_engine_getPayloadV1);
            IntPtr engine_getPayloadV2Ptr = Marshal.GetFunctionPointerForDelegate(_engine_getPayloadV2);
            IntPtr engine_getPayloadV3Ptr = Marshal.GetFunctionPointerForDelegate(_engine_getPayloadV3);
            IntPtr engine_getPayloadV4Ptr = Marshal.GetFunctionPointerForDelegate(_engine_getPayloadV4);
            IntPtr engine_getBlobsV1Ptr = Marshal.GetFunctionPointerForDelegate(_engine_getBlobsV1);

            _adapter = new CEmbedAdapter
            {
                engine_new_payload_v1 = (delegate* unmanaged[Cdecl]<CExecutionPayloadV1, CResultCPayloadStatusV1>)engine_newPayloadV1Ptr,
                engine_new_payload_v2 = (delegate* unmanaged[Cdecl]<CExecutionPayloadV2, CResultCPayloadStatusV1>)engine_newPayloadV2Ptr,
                engine_new_payload_v3 = (delegate* unmanaged[Cdecl]<CExecutionPayloadV3, byte**, ulong, byte*, CResultCPayloadStatusV1>)engine_newPayloadV3Ptr,
                engine_new_payload_v4 = (delegate* unmanaged[Cdecl]<CExecutionPayloadV3, byte**, ulong, byte*, CExecutionRequests, CResultCPayloadStatusV1>)engine_newPayloadV4Ptr,
                engine_forkchoice_updated_v1 = (delegate* unmanaged[Cdecl]<CForkChoiceStateV1, COptionCPayloadAttributesV1, CResultCForkChoiceUpdatedResponse>)engine_forkchoiceUpdatedV1Ptr,
                engine_forkchoice_updated_v2 = (delegate* unmanaged[Cdecl]<CForkChoiceStateV1, COptionCPayloadAttributesV2, CResultCForkChoiceUpdatedResponse>)engine_forkchoiceUpdatedV2Ptr,
                engine_forkchoice_updated_v3 = (delegate* unmanaged[Cdecl]<CForkChoiceStateV1, COptionCPayloadAttributesV3, CResultCForkChoiceUpdatedResponse>)engine_forkchoiceUpdatedV3Ptr,
                engine_get_payload_v1 = (delegate* unmanaged[Cdecl]<byte*, CResultCExecutionPayloadV1>)engine_getPayloadV1Ptr,
                engine_get_payload_v2 = (delegate* unmanaged[Cdecl]<byte*, CResultCEngineGetPayloadV2Response>)engine_getPayloadV2Ptr,
                engine_get_payload_v3 = (delegate* unmanaged[Cdecl]<byte*, CResultCEngineGetPayloadV3Response>)engine_getPayloadV3Ptr,
                engine_get_payload_v4 = (delegate* unmanaged[Cdecl]<byte*, CResultCEngineGetPayloadV4Response>)engine_getPayloadV4Ptr,
                engine_get_blobs_v1 = (delegate* unmanaged[Cdecl]<byte**, ulong, CResultCVecCOptionCBlobAndProofV1>)engine_getBlobsV1Ptr,
            };
        }
    }

    public CEmbedAdapter getAdapter() {
        return this._adapter;
    }

    CResultCPayloadStatusV1 EngineNewPayloadV1(CExecutionPayloadV1 payload)
    {
        _logger.Error("================================================================= engine_newPayloadV1 =================================================================");
        return new CResultCPayloadStatusV1
        {
            error = 1
        };
    }

    CResultCPayloadStatusV1 EngineNewPayloadV2(CExecutionPayloadV2 payload)
    {
        _logger.Error("================================================================= engine_newPayloadV2 =================================================================");
        return new CResultCPayloadStatusV1
        {
            error = 1
        };
    }

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV3(CExecutionPayloadV3 payload, byte** versionedHashes, ulong versionedHashesLen, byte* parentBeaconBlockRoot)
    {
        _logger.Error("================================================================= engine_newPayloadV3 =================================================================");
        return new CResultCPayloadStatusV1
        {
            error = 1
        };
    }

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV4(CExecutionPayloadV3 payload, byte** versionedHashes, ulong versionedHashesLen, byte* parentBeaconBlockRoot, CExecutionRequests executionRequests)
    {
        _logger.Warn("================================================================= engine_newPayloadV4 =================================================================");

        try
        {
            var transactions = new List<byte[]>();
            for (var i = 0; i < (int) payload.transactions_len; ++i) {
                transactions.Add(new ReadOnlySpan<byte>(payload.transactions[i].bytes, (int) payload.transactions[i].bytes_len).ToArray());
            }

            var withdrawals = new List<Withdrawal>();
            for (var i = 0; i < (int)payload.withdrawals_len; ++i) {
                withdrawals.Add(new Withdrawal
                {
                    Index = payload.withdrawals[i].index,
                    ValidatorIndex = payload.withdrawals[i].validator_index,
                    Address = new Address(new ReadOnlySpan<byte>(payload.withdrawals[i].address, 20).ToArray()),
                    AmountInGwei = payload.withdrawals[i].amount,
                });
            }

            var versionedHashesConverted = new List<byte[]>();
            for (var i = 0; i < (int)versionedHashesLen; ++i)
            {
                versionedHashesConverted.Add(new ReadOnlySpan<byte>(versionedHashes[i], 32).ToArray());
            }

            var parentBeaconBlockRootConverted = new Hash256(new ReadOnlySpan<byte>(parentBeaconBlockRoot, 32).ToArray());

            var executionRequestsConverted = new List<byte[]>();
            for (var i = 0; i < (int)executionRequests.requests_len; ++i)
            {
                executionRequestsConverted.Add(new ReadOnlySpan<byte>(executionRequests.requests[i].bytes, (int)executionRequests.requests[i].bytes_len).ToArray());
            }

            var payloadStatus = _engineRpc.engine_newPayloadV4(new Nethermind.Merge.Plugin.Data.ExecutionPayloadV3
            {
                ParentHash = new Hash256(new ReadOnlySpan<byte>(payload.parent_hash, 32).ToArray()),            
                FeeRecipient = new Address(new ReadOnlySpan<byte>(payload.fee_recipient, 20).ToArray()),
                StateRoot = new Hash256(new ReadOnlySpan<byte>(payload.state_root, 32).ToArray()),
                ReceiptsRoot = new Hash256(new ReadOnlySpan<byte>(payload.receipts_root, 32).ToArray()),
                LogsBloom = new Bloom(new ReadOnlySpan<byte>(payload.logs_bloom, (int)payload.logs_bloom_len).ToArray()),
                PrevRandao = new Hash256(new ReadOnlySpan<byte>(payload.prev_randao, 32).ToArray()),
                BlockNumber = (long)payload.block_number,
                GasLimit = (long)payload.gas_limit,
                GasUsed = (long)payload.gas_used,
                Timestamp = payload.timestamp,
                ExtraData = new ReadOnlySpan<byte>(payload.extra_data, (int)payload.extra_data_len).ToArray(),
                BaseFeePerGas = new UInt256(new ReadOnlySpan<byte>(payload.base_fee_per_gas, 32).ToArray(), true),
                BlockHash = new Hash256(new ReadOnlySpan<byte>(payload.block_hash, 32).ToArray()),
                Transactions = transactions.ToArray(),
                Withdrawals = withdrawals.ToArray(),
                BlobGasUsed = payload.blob_gas_used,
                ExcessBlobGas = payload.excess_blob_gas,
                ParentBeaconBlockRoot = parentBeaconBlockRootConverted,
                ExecutionRequests = executionRequestsConverted.ToArray(),
            }, versionedHashesConverted.ToArray(), parentBeaconBlockRootConverted, executionRequestsConverted.ToArray()).Result;

            if (payloadStatus.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            CPayloadValidationStatus status;
            if (payloadStatus.Data.Status == Nethermind.Merge.Plugin.Data.PayloadStatus.Valid)
            {
                status = CPayloadValidationStatus.Valid;
            }
            else if (payloadStatus.Data.Status == Nethermind.Merge.Plugin.Data.PayloadStatus.Invalid)
            {
                status = CPayloadValidationStatus.Invalid;
            }
            else if (payloadStatus.Data.Status == Nethermind.Merge.Plugin.Data.PayloadStatus.Syncing)
            {
                status = CPayloadValidationStatus.Syncing;
            }
            else
            {
                status = CPayloadValidationStatus.Accepted;
            }

            var latestValidHash = new CH256 {};

            if (payloadStatus.Data.LatestValidHash != null)
            {
                if (payloadStatus.Data.LatestValidHash.Bytes.Length != 32)
                {
                    throw new Exception("LatestValidHash field must be exactly 32 bytes long");
                }
                fixed (byte* sourcePtr = payloadStatus.Data.LatestValidHash.Bytes)
                {
                    Buffer.MemoryCopy(sourcePtr, latestValidHash.Item1, 32, 32);
                }
            }

            return new CResultCPayloadStatusV1
            {
                value = new CPayloadStatusV1
                {
                    status = status,
                    latest_valid_hash = new COptionCH256
                    {
                        is_something = payloadStatus.Data.LatestValidHash != null,
                        value = latestValidHash,
                    },
                },
                error = 0,
            };
        }
        catch (Exception)
        {
            return new CResultCPayloadStatusV1
            {
                error = 1
            };
        }
    }

    CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV1(CForkChoiceStateV1 state, COptionCPayloadAttributesV1 payload)
    {
        _logger.Error("================================================================= engine_forkchoiceUpdatedV1 =================================================================");
        return new CResultCForkChoiceUpdatedResponse
        {
            error = 1
        };
    }

    CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV2(CForkChoiceStateV1 state, COptionCPayloadAttributesV2 payload)
    {
        _logger.Error("================================================================= engine_forkchoiceUpdatedV2 =================================================================");
        return new CResultCForkChoiceUpdatedResponse
        {
            error = 1
        };
    }

    unsafe CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV3(CForkChoiceStateV1 state, COptionCPayloadAttributesV3 payload)
    {
        _logger.Warn("================================================================= engine_forkchoiceUpdatedV3 =================================================================");
        try {
            PayloadAttributes attributes = null;
            if (payload.is_something) {
                var withdrawals = new List<Withdrawal>();
                for (var i = 0; i < (int)payload.value.withdrawals_len; ++i) {
                    withdrawals.Add(new Withdrawal
                    {
                        Index = payload.value.withdrawals[i].index,
                        ValidatorIndex = payload.value.withdrawals[i].validator_index,
                        Address = new Address(new ReadOnlySpan<byte>(payload.value.withdrawals[i].address, 20).ToArray()),
                        AmountInGwei = payload.value.withdrawals[i].amount,
                    });
                }

                attributes = new PayloadAttributes
                {
                    Timestamp = payload.value.timestamp,
                    PrevRandao = new Hash256(new ReadOnlySpan<byte>(payload.value.prev_randao, 32).ToArray()),
                    SuggestedFeeRecipient = new Address(new ReadOnlySpan<byte>(payload.value.suggested_fee_recipient, 20).ToArray()),
                    Withdrawals = withdrawals.ToArray(),
                    ParentBeaconBlockRoot = new Hash256(new ReadOnlySpan<byte>(payload.value.parent_beacon_block_root, 32).ToArray())
                };
            }

            var forkchoiceUpdatedResult = _engineRpc.engine_forkchoiceUpdatedV3(
                new ForkchoiceStateV1(
                    new Hash256(new ReadOnlySpan<byte>(state.head_block_hash, 32).ToArray()),
                    new Hash256(new ReadOnlySpan<byte>(state.finalized_block_hash, 32).ToArray()),
                    new Hash256(new ReadOnlySpan<byte>(state.safe_block_hash, 32).ToArray())
                ),
                attributes
            ).Result;
            
            if (forkchoiceUpdatedResult.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            CPayloadValidationStatus status;
            if (forkchoiceUpdatedResult.Data.PayloadStatus.Status == Nethermind.Merge.Plugin.Data.PayloadStatus.Valid)
            {
                status = CPayloadValidationStatus.Valid;
            }
            else if (forkchoiceUpdatedResult.Data.PayloadStatus.Status == Nethermind.Merge.Plugin.Data.PayloadStatus.Invalid)
            {
                status = CPayloadValidationStatus.Invalid;
            }
            else if (forkchoiceUpdatedResult.Data.PayloadStatus.Status == Nethermind.Merge.Plugin.Data.PayloadStatus.Syncing)
            {
                status = CPayloadValidationStatus.Syncing;
            }
            else
            {
                status = CPayloadValidationStatus.Accepted;
            }

            var latestValidHash = new CH256 {};

            if (forkchoiceUpdatedResult.Data.PayloadStatus.LatestValidHash != null)
            {
                if (forkchoiceUpdatedResult.Data.PayloadStatus.LatestValidHash.Bytes.Length != 32)
                {
                    throw new Exception("LatestValidHash field must be exactly 32 bytes long");
                }
                fixed (byte* sourcePtr = forkchoiceUpdatedResult.Data.PayloadStatus.LatestValidHash.Bytes)
                {
                    Buffer.MemoryCopy(sourcePtr, latestValidHash.Item1, 32, 32);
                }
            }

            var payloadId = new CH64();
            if (forkchoiceUpdatedResult.Data.PayloadId != null) {
                var raw = Convert.FromHexString(forkchoiceUpdatedResult.Data.PayloadId);

                if (raw.Length != 8) {
                    throw new Exception("Payload field must be exactly 8 bytes long");
                }

                fixed (byte* sourcePtr = raw)
                {
                    Buffer.MemoryCopy(sourcePtr, payloadId.Item1, 8, 8);
                }
            }

            return new CResultCForkChoiceUpdatedResponse
            {
                value = new CForkChoiceUpdatedResponse
                {
                    payload_status = new CPayloadStatusV1
                    {
                        status = status,
                        latest_valid_hash = new COptionCH256
                        {
                            is_something = forkchoiceUpdatedResult.Data.PayloadStatus.LatestValidHash != null,
                            value = latestValidHash,
                        },
                    },
                    payload_id = new COptionCH64
                    {
                        is_something = forkchoiceUpdatedResult.Data.PayloadId != null,
                        value = payloadId,
                    }
                },
                error = 0,
            };
        } catch (Exception e) {
            _logger.Error("Exception " + e);
       
            return new CResultCForkChoiceUpdatedResponse
            {
                error = 1
            };
        };
    }

    unsafe CResultCExecutionPayloadV1 EngineGetPayloadV1(byte* payloadId)
    {
        _logger.Error("================================================================= engine_getPayloadV1 =================================================================");
        return new CResultCExecutionPayloadV1
        {
            error = 1
        };
    }

    unsafe CResultCEngineGetPayloadV2Response EngineGetPayloadV2(byte* payloadId)
    {
        _logger.Error("================================================================= engine_getPayloadV2 =================================================================");
        return new CResultCEngineGetPayloadV2Response
        {
            error = 1
        };
    }

    unsafe CResultCEngineGetPayloadV3Response EngineGetPayloadV3(byte* payloadId)
    {
        _logger.Error("================================================================= engine_getPayloadV3 =================================================================");
        return new CResultCEngineGetPayloadV3Response
        {
            error = 1
        };
    }

    unsafe CResultCEngineGetPayloadV4Response EngineGetPayloadV4(byte* payloadId)
    {
        _logger.Error("================================================================= engine_getPayloadV4 =================================================================");
        return new CResultCEngineGetPayloadV4Response
        {
            error = 1
        };
    }

    unsafe CResultCVecCOptionCBlobAndProofV1 EngineGetBlobsV1(byte** versionedHashes, ulong versionedHashesLen)
    {
        _logger.Warn("================================================================= engine_getBlobsV1 =================================================================");
        try {
            var versionedHashesConverted = new List<byte[]>();
            for (var i = 0; i < (int)versionedHashesLen; ++i)
            {
                versionedHashesConverted.Add(new ReadOnlySpan<byte>(versionedHashes[i], 32).ToArray());
            }
            var blobs = _engineRpc.engine_getBlobsV1(versionedHashesConverted.ToArray()).Result;

            if (blobs.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var blobArray = blobs.Data.Select(blob => {
                if (blob == null) {
                    return new COptionCBlobAndProofV1
                    {
                        is_something = false,
                    };
                }
                
                var proof = new CH384();
                if (blob.Proof.Length != 48)
                {
                    throw new Exception("Proof field must be exactly 48 bytes long");
                }
                fixed (byte* sourcePtr = blob.Proof)
                {
                    Buffer.MemoryCopy(sourcePtr, proof.Item1, 48, 48);
                }

                if (blob.Blob.Length != 4096 * 32) {
                    throw new Exception("Blob must be exactly 4096 * 32 bytes long");
                }
                IntPtr convBlob = Marshal.AllocHGlobal(blob.Blob.Length);
                Marshal.Copy(blob.Blob, 0, convBlob, blob.Blob.Length);
                return new COptionCBlobAndProofV1
                {
                    is_something = true,
                    value = new CBlobAndProofV1
                    {
                        proof = proof,
                        blob = (byte*)convBlob,
                    }
                };
            }).ToArray();

            IntPtr res = Marshal.AllocHGlobal(blobArray.Length * Marshal.SizeOf<COptionCBlobAndProofV1>());
            for (var i = 0; i < blobArray.Length; ++i) {
                Marshal.StructureToPtr(blobArray[i], IntPtr.Add(res, i * Marshal.SizeOf<COptionCBlobAndProofV1>()), false);
            };

            return new CResultCVecCOptionCBlobAndProofV1
            {
                error = 0,
                value = new CVecCOptionCBlobAndProofV1 {
                    data = (COptionCBlobAndProofV1*)res,
                    data_len = (ulong)blobArray.Length,
                }
            };
        } catch (Exception e)
        {
            _logger.Error("Exception: " + e);
            return new CResultCVecCOptionCBlobAndProofV1
            {
                error = 1
            };
        }
    }
}