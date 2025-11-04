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
unsafe internal delegate CResultCEngineGetPayloadV5Response EngineGetPayloadV5Delegate(byte* payloadId);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCVecCOptionCBlobAndProofV1 EngineGetBlobsV1Delegate(byte** versionedHashes, ulong versionedHashesLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate CResultCOptionCVecCBlobAndProofV2 EngineGetBlobsV2Delegate(byte** versionedHashes, ulong versionedHashesLen);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
unsafe internal delegate void FreeDelegate(void* ptr);

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
    EngineGetPayloadV5Delegate _engine_getPayloadV5;
    EngineGetBlobsV1Delegate _engine_getBlobsV1;
    EngineGetBlobsV2Delegate _engine_getBlobsV2;
    FreeDelegate _free;

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
            _engine_getPayloadV5 = EngineGetPayloadV5;
            _engine_getBlobsV1 = EngineGetBlobsV1;
            _engine_getBlobsV2 = EngineGetBlobsV2;
            _free = Free;

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
            IntPtr engine_getPayloadV5Ptr = Marshal.GetFunctionPointerForDelegate(_engine_getPayloadV5);
            IntPtr engine_getBlobsV1Ptr = Marshal.GetFunctionPointerForDelegate(_engine_getBlobsV1);
            IntPtr engine_getBlobsV2Ptr = Marshal.GetFunctionPointerForDelegate(_engine_getBlobsV2);
            IntPtr freePtr = Marshal.GetFunctionPointerForDelegate(_free);

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
                engine_get_payload_v5 = (delegate* unmanaged[Cdecl]<byte*, CResultCEngineGetPayloadV5Response>)engine_getPayloadV5Ptr,
                engine_get_blobs_v1 = (delegate* unmanaged[Cdecl]<byte**, ulong, CResultCVecCOptionCBlobAndProofV1>)engine_getBlobsV1Ptr,
                engine_get_blobs_v2 = (delegate* unmanaged[Cdecl]<byte**, ulong, CResultCOptionCVecCBlobAndProofV2>)engine_getBlobsV2Ptr,
                free = (delegate* unmanaged[Cdecl]<void*, void>)freePtr,
            };
        }
    }

    public CEmbedAdapter getAdapter() {
        return _adapter;
    }

    unsafe void Free(void* ptr) {
        Marshal.FreeHGlobal((IntPtr)ptr);
    }

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV1(CExecutionPayloadV1 payload)
    {
        _logger.Warn("================================================================= engine_newPayloadV1 =================================================================");

        try
        {
            var transactions = new List<byte[]>();
            for (var i = 0; i < (int) payload.transactions_len; ++i) {
                transactions.Add(new ReadOnlySpan<byte>(payload.transactions[i].bytes, (int) payload.transactions[i].bytes_len).ToArray());
            }

            var payloadStatus = _engineRpc.engine_newPayloadV1(new Nethermind.Merge.Plugin.Data.ExecutionPayloadV3
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
            }).Result;

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
        };
    }

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV2(CExecutionPayloadV2 payload)
    {
        _logger.Warn("================================================================= engine_newPayloadV2 =================================================================");

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

            var payloadStatus = _engineRpc.engine_newPayloadV2(new Nethermind.Merge.Plugin.Data.ExecutionPayloadV3
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
            }).Result;

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
        };
    }

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV3(CExecutionPayloadV3 payload, byte** versionedHashes, ulong versionedHashesLen, byte* parentBeaconBlockRoot)
    {
        _logger.Warn("================================================================= engine_newPayloadV3 =================================================================");

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

            var payloadStatus = _engineRpc.engine_newPayloadV3(new Nethermind.Merge.Plugin.Data.ExecutionPayloadV3
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
            }, versionedHashesConverted.ToArray(), parentBeaconBlockRootConverted).Result;

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

    unsafe CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV1(CForkChoiceStateV1 state, COptionCPayloadAttributesV1 payload)
    {
        _logger.Warn("================================================================= engine_forkchoiceUpdatedV1 =================================================================");
        try {
            PayloadAttributes attributes = null;
            if (payload.is_something) {
                attributes = new PayloadAttributes
                {
                    Timestamp = payload.value.timestamp,
                    PrevRandao = new Hash256(new ReadOnlySpan<byte>(payload.value.prev_randao, 32).ToArray()),
                    SuggestedFeeRecipient = new Address(new ReadOnlySpan<byte>(payload.value.suggested_fee_recipient, 20).ToArray()),
                };
            }

            var forkchoiceUpdatedResult = _engineRpc.engine_forkchoiceUpdatedV1(
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

    unsafe CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV2(CForkChoiceStateV1 state, COptionCPayloadAttributesV2 payload)
    {
        _logger.Warn("================================================================= engine_forkchoiceUpdatedV2 =================================================================");
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
                };
            }

            var forkchoiceUpdatedResult = _engineRpc.engine_forkchoiceUpdatedV2(
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
        _logger.Warn("================================================================= engine_getPayloadV1 =================================================================");

        try
        {
            var convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var payload = _engineRpc.engine_getPayloadV1(convertedPayloadId).Result;

            if (payload.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var exPayload = new CExecutionPayloadV1 { };

            fixed (byte* sourcePtr = payload.Data.ParentHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.parent_hash, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.FeeRecipient.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.fee_recipient, 20, 20); }
            fixed (byte* sourcePtr = payload.Data.StateRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.state_root, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ReceiptsRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.receipts_root, 32, 32); }

            {
                var bloomLen = payload.Data.LogsBloom.Bytes.Length;
                IntPtr convBloom = Marshal.AllocHGlobal(bloomLen);
                Marshal.Copy(payload.Data.LogsBloom.Bytes.ToArray(), 0, convBloom, bloomLen);
                exPayload.logs_bloom = (byte*)convBloom;
                exPayload.logs_bloom_len = (ulong)bloomLen;
            }

            fixed (byte* sourcePtr = payload.Data.PrevRandao.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.prev_randao, 32, 32); }
            exPayload.block_number = (ulong)payload.Data.BlockNumber;
            exPayload.gas_limit = (ulong)payload.Data.GasLimit;
            exPayload.gas_used = (ulong)payload.Data.GasUsed;
            exPayload.timestamp = payload.Data.Timestamp;

            {
                var extraDataLen = payload.Data.ExtraData.Length;
                IntPtr convExtraData = Marshal.AllocHGlobal(extraDataLen);
                Marshal.Copy(payload.Data.ExtraData.ToArray(), 0, convExtraData, extraDataLen);
                exPayload.extra_data = (byte*)convExtraData;
                exPayload.extra_data_len = (ulong)extraDataLen;
            }

            fixed (byte* sourcePtr = payload.Data.BaseFeePerGas.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, exPayload.base_fee_per_gas, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.BlockHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.block_hash, 32, 32); }

            {
                var transactionsLen = payload.Data.Transactions.Length;
                IntPtr convTransactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var len = payload.Data.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(len);
                    Marshal.Copy(payload.Data.Transactions[i], 0, transaction, len);
                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes_len = (ulong)len,
                        bytes = (byte*)transaction,
                    },
                        IntPtr.Add(convTransactions, i * Marshal.SizeOf<CTransaction>()),
                        false
                    );
                }

                exPayload.transactions = (CTransaction*)convTransactions;
                exPayload.transactions_len = (ulong)transactionsLen;
            }

            return new CResultCExecutionPayloadV1
            {
                error = 0,
                value = exPayload,
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception " + e);

            return new CResultCExecutionPayloadV1
            {
                error = 1
            };
        }
    }

    unsafe CResultCEngineGetPayloadV2Response EngineGetPayloadV2(byte* payloadId)
    {
        _logger.Warn("================================================================= engine_getPayloadV2 =================================================================");

        try
        {
            var convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var payload = _engineRpc.engine_getPayloadV2(convertedPayloadId).Result;

            if (payload.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var response = new CEngineGetPayloadV2Response { };

            var exPayload = new CExecutionPayloadV2 { };

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.ParentHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.parent_hash, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.FeeRecipient.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.fee_recipient, 20, 20); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.StateRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.state_root, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.ReceiptsRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.receipts_root, 32, 32); }

            {
                var bloomLen = payload.Data.ExecutionPayload.LogsBloom.Bytes.Length;
                IntPtr convBloom = Marshal.AllocHGlobal(bloomLen);
                Marshal.Copy(payload.Data.ExecutionPayload.LogsBloom.Bytes.ToArray(), 0, convBloom, bloomLen);
                exPayload.logs_bloom = (byte*)convBloom;
                exPayload.logs_bloom_len = (ulong)bloomLen;
            }

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.PrevRandao.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.prev_randao, 32, 32); }
            exPayload.block_number = (ulong)payload.Data.ExecutionPayload.BlockNumber;
            exPayload.gas_limit = (ulong)payload.Data.ExecutionPayload.GasLimit;
            exPayload.gas_used = (ulong)payload.Data.ExecutionPayload.GasUsed;
            exPayload.timestamp = payload.Data.ExecutionPayload.Timestamp;

            {
                var extraDataLen = payload.Data.ExecutionPayload.ExtraData.Length;
                IntPtr convExtraData = Marshal.AllocHGlobal(extraDataLen);
                Marshal.Copy(payload.Data.ExecutionPayload.ExtraData.ToArray(), 0, convExtraData, extraDataLen);
                exPayload.extra_data = (byte*)convExtraData;
                exPayload.extra_data_len = (ulong)extraDataLen;
            }

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.BaseFeePerGas.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, exPayload.base_fee_per_gas, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.BlockHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.block_hash, 32, 32); }

            {
                var transactionsLen = payload.Data.ExecutionPayload.Transactions.Length;
                IntPtr convTransactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var len = payload.Data.ExecutionPayload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(len);
                    Marshal.Copy(payload.Data.ExecutionPayload.Transactions[i], 0, transaction, len);
                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes_len = (ulong)len,
                        bytes = (byte*)transaction,
                    },
                        IntPtr.Add(convTransactions, i * Marshal.SizeOf<CTransaction>()),
                        false
                    );
                }
                ;

                exPayload.transactions = (CTransaction*)convTransactions;
                exPayload.transactions_len = (ulong)transactionsLen;
            }

            {
                var withdrawalsLen = payload.Data.ExecutionPayload.Transactions.Length;
                IntPtr convWithdrawals = Marshal.AllocHGlobal(withdrawalsLen * Marshal.SizeOf<CWithdrawalV1>());
                for (var i = 0; i < withdrawalsLen; ++i)
                {
                    var withdrawal = new CWithdrawalV1 { };

                    withdrawal.index = payload.Data.ExecutionPayload.Withdrawals[i].Index;
                    withdrawal.validator_index = payload.Data.ExecutionPayload.Withdrawals[i].ValidatorIndex;
                    fixed (byte* sourcePtr = payload.Data.ExecutionPayload.Withdrawals[i].Address.Bytes) { Buffer.MemoryCopy(sourcePtr, withdrawal.address, 20, 20); }
                    withdrawal.amount = (ulong)payload.Data.ExecutionPayload.Withdrawals[i].AmountInGwei;

                    Marshal.StructureToPtr(withdrawal, IntPtr.Add(convWithdrawals, i * Marshal.SizeOf<CWithdrawalV1>()), false);
                }

                exPayload.withdrawals = (CWithdrawalV1*)convWithdrawals;
                exPayload.withdrawals_len = (ulong)withdrawalsLen;
            }

            response.execution_payload = exPayload;

            fixed (byte* sourcePtr = payload.Data.BlockValue.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, response.block_value, 32, 32); }

            return new CResultCEngineGetPayloadV2Response
            {
                error = 0,
                value = response,
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception " + e);

            return new CResultCEngineGetPayloadV2Response
            {
                error = 1
            };
        }
    }

    unsafe CResultCEngineGetPayloadV3Response EngineGetPayloadV3(byte* payloadId)
    {
        _logger.Warn("================================================================= engine_getPayloadV3 =================================================================");

        try
        {
            var convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var payload = _engineRpc.engine_getPayloadV3(convertedPayloadId).Result;

            if (payload.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var response = new CEngineGetPayloadV3Response { };

            var exPayload = new CExecutionPayloadV3 { };

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.ParentHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.parent_hash, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.FeeRecipient.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.fee_recipient, 20, 20); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.StateRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.state_root, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.ReceiptsRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.receipts_root, 32, 32); }

            {
                var bloomLen = payload.Data.ExecutionPayload.LogsBloom.Bytes.Length;
                IntPtr convBloom = Marshal.AllocHGlobal(bloomLen);
                Marshal.Copy(payload.Data.ExecutionPayload.LogsBloom.Bytes.ToArray(), 0, convBloom, bloomLen);
                exPayload.logs_bloom = (byte*)convBloom;
                exPayload.logs_bloom_len = (ulong)bloomLen;
            }

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.PrevRandao.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.prev_randao, 32, 32); }
            exPayload.block_number = (ulong)payload.Data.ExecutionPayload.BlockNumber;
            exPayload.gas_limit = (ulong)payload.Data.ExecutionPayload.GasLimit;
            exPayload.gas_used = (ulong)payload.Data.ExecutionPayload.GasUsed;
            exPayload.timestamp = payload.Data.ExecutionPayload.Timestamp;

            {
                var extraDataLen = payload.Data.ExecutionPayload.ExtraData.Length;
                IntPtr convExtraData = Marshal.AllocHGlobal(extraDataLen);
                Marshal.Copy(payload.Data.ExecutionPayload.ExtraData.ToArray(), 0, convExtraData, extraDataLen);
                exPayload.extra_data = (byte*)convExtraData;
                exPayload.extra_data_len = (ulong)extraDataLen;
            }

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.BaseFeePerGas.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, exPayload.base_fee_per_gas, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.BlockHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.block_hash, 32, 32); }

            {
                var transactionsLen = payload.Data.ExecutionPayload.Transactions.Length;
                IntPtr convTransactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var len = payload.Data.ExecutionPayload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(len);
                    Marshal.Copy(payload.Data.ExecutionPayload.Transactions[i], 0, transaction, len);
                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes_len = (ulong)len,
                        bytes = (byte*)transaction,
                    },
                        IntPtr.Add(convTransactions, i * Marshal.SizeOf<CTransaction>()),
                        false
                    );
                }
                ;

                exPayload.transactions = (CTransaction*)convTransactions;
                exPayload.transactions_len = (ulong)transactionsLen;
            }

            {
                var withdrawalsLen = payload.Data.ExecutionPayload.Transactions.Length;
                IntPtr convWithdrawals = Marshal.AllocHGlobal(withdrawalsLen * Marshal.SizeOf<CWithdrawalV1>());
                for (var i = 0; i < withdrawalsLen; ++i)
                {
                    var withdrawal = new CWithdrawalV1 { };

                    withdrawal.index = payload.Data.ExecutionPayload.Withdrawals[i].Index;
                    withdrawal.validator_index = payload.Data.ExecutionPayload.Withdrawals[i].ValidatorIndex;
                    fixed (byte* sourcePtr = payload.Data.ExecutionPayload.Withdrawals[i].Address.Bytes) { Buffer.MemoryCopy(sourcePtr, withdrawal.address, 20, 20); }
                    withdrawal.amount = (ulong)payload.Data.ExecutionPayload.Withdrawals[i].AmountInGwei;

                    Marshal.StructureToPtr(withdrawal, IntPtr.Add(convWithdrawals, i * Marshal.SizeOf<CWithdrawalV1>()), false);
                }

                exPayload.withdrawals = (CWithdrawalV1*)convWithdrawals;
                exPayload.withdrawals_len = (ulong)withdrawalsLen;
            }

            exPayload.blob_gas_used = (ulong)payload.Data.ExecutionPayload.BlobGasUsed;
            exPayload.excess_blob_gas = (ulong)payload.Data.ExecutionPayload.ExcessBlobGas;

            response.execution_payload = exPayload;

            fixed (byte* sourcePtr = payload.Data.BlockValue.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, response.block_value, 32, 32); }

            var blobsBundle = new CBlobsBundleV1 { };

            {
                var commitmentsLen = payload.Data.BlobsBundle.Commitments.Length;
                var commitments = Marshal.AllocHGlobal(commitmentsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < commitmentsLen; ++i)
                {
                    var commitment = Marshal.AllocHGlobal(48);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)commitment, 48, 48); }
                    Marshal.StructureToPtr(commitment, IntPtr.Add(commitments, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.commitments = (byte**)commitments;
                blobsBundle.commitments_len = (ulong)commitmentsLen;
            }

            {
                var proofsLen = payload.Data.BlobsBundle.Commitments.Length;
                var proofs = Marshal.AllocHGlobal(proofsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < proofsLen; ++i)
                {
                    var proof = Marshal.AllocHGlobal(48);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)proof, 48, 48); }
                    Marshal.StructureToPtr(proof, IntPtr.Add(proofs, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.proofs = (byte**)proofs;
                blobsBundle.proofs_len = (ulong)proofsLen;
            }

            {
                var blobsLen = payload.Data.BlobsBundle.Commitments.Length;
                var blobs = Marshal.AllocHGlobal(blobsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < blobsLen; ++i)
                {
                    var blob = Marshal.AllocHGlobal(4096 * 32);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)blob, 4096 * 32, 4096 * 32); }
                    Marshal.StructureToPtr(blob, IntPtr.Add(blobs, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.blobs = (byte**)blobs;
                blobsBundle.blobs_len = (ulong)blobsLen;
            }

            response.blobs_bundle = blobsBundle;

            response.should_override_builder = payload.Data.ShouldOverrideBuilder;

            return new CResultCEngineGetPayloadV3Response
            {
                error = 0,
                value = response,
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception " + e);

            return new CResultCEngineGetPayloadV3Response
            {
                error = 1
            };
        }
    }

    unsafe CResultCEngineGetPayloadV4Response EngineGetPayloadV4(byte* payloadId)
    {
        _logger.Warn("================================================================= engine_getPayloadV4 =================================================================");

        try
        {
            var convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var payload = _engineRpc.engine_getPayloadV4(convertedPayloadId).Result;

            if (payload.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var response = new CEngineGetPayloadV4Response { };

            var exPayload = new CExecutionPayloadV3 { };

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.ParentHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.parent_hash, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.FeeRecipient.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.fee_recipient, 20, 20); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.StateRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.state_root, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.ReceiptsRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.receipts_root, 32, 32); }

            {
                var bloomLen = payload.Data.ExecutionPayload.LogsBloom.Bytes.Length;
                IntPtr convBloom = Marshal.AllocHGlobal(bloomLen);
                Marshal.Copy(payload.Data.ExecutionPayload.LogsBloom.Bytes.ToArray(), 0, convBloom, bloomLen);
                exPayload.logs_bloom = (byte*)convBloom;
                exPayload.logs_bloom_len = (ulong)bloomLen;
            }

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.PrevRandao.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.prev_randao, 32, 32); }
            exPayload.block_number = (ulong)payload.Data.ExecutionPayload.BlockNumber;
            exPayload.gas_limit = (ulong)payload.Data.ExecutionPayload.GasLimit;
            exPayload.gas_used = (ulong)payload.Data.ExecutionPayload.GasUsed;
            exPayload.timestamp = payload.Data.ExecutionPayload.Timestamp;

            {
                var extraDataLen = payload.Data.ExecutionPayload.ExtraData.Length;
                IntPtr convExtraData = Marshal.AllocHGlobal(extraDataLen);
                Marshal.Copy(payload.Data.ExecutionPayload.ExtraData.ToArray(), 0, convExtraData, extraDataLen);
                exPayload.extra_data = (byte*)convExtraData;
                exPayload.extra_data_len = (ulong)extraDataLen;
            }

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.BaseFeePerGas.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, exPayload.base_fee_per_gas, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.BlockHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.block_hash, 32, 32); }

            {
                var transactionsLen = payload.Data.ExecutionPayload.Transactions.Length;
                IntPtr convTransactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var len = payload.Data.ExecutionPayload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(len);
                    Marshal.Copy(payload.Data.ExecutionPayload.Transactions[i], 0, transaction, len);
                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes_len = (ulong)len,
                        bytes = (byte*)transaction,
                    },
                        IntPtr.Add(convTransactions, i * Marshal.SizeOf<CTransaction>()),
                        false
                    );
                }
                ;

                exPayload.transactions = (CTransaction*)convTransactions;
                exPayload.transactions_len = (ulong)transactionsLen;
            }

            {
                var withdrawalsLen = payload.Data.ExecutionPayload.Transactions.Length;
                IntPtr convWithdrawals = Marshal.AllocHGlobal(withdrawalsLen * Marshal.SizeOf<CWithdrawalV1>());
                for (var i = 0; i < withdrawalsLen; ++i)
                {
                    var withdrawal = new CWithdrawalV1 { };

                    withdrawal.index = payload.Data.ExecutionPayload.Withdrawals[i].Index;
                    withdrawal.validator_index = payload.Data.ExecutionPayload.Withdrawals[i].ValidatorIndex;
                    fixed (byte* sourcePtr = payload.Data.ExecutionPayload.Withdrawals[i].Address.Bytes) { Buffer.MemoryCopy(sourcePtr, withdrawal.address, 20, 20); }
                    withdrawal.amount = (ulong)payload.Data.ExecutionPayload.Withdrawals[i].AmountInGwei;

                    Marshal.StructureToPtr(withdrawal, IntPtr.Add(convWithdrawals, i * Marshal.SizeOf<CWithdrawalV1>()), false);
                }

                exPayload.withdrawals = (CWithdrawalV1*)convWithdrawals;
                exPayload.withdrawals_len = (ulong)withdrawalsLen;
            }

            exPayload.blob_gas_used = (ulong)payload.Data.ExecutionPayload.BlobGasUsed;
            exPayload.excess_blob_gas = (ulong)payload.Data.ExecutionPayload.ExcessBlobGas;

            response.execution_payload = exPayload;

            fixed (byte* sourcePtr = payload.Data.BlockValue.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, response.block_value, 32, 32); }

            var blobsBundle = new CBlobsBundleV1 { };

            {
                var commitmentsLen = payload.Data.BlobsBundle.Commitments.Length;
                var commitments = Marshal.AllocHGlobal(commitmentsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < commitmentsLen; ++i)
                {
                    var commitment = Marshal.AllocHGlobal(48);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)commitment, 48, 48); }
                    Marshal.StructureToPtr(commitment, IntPtr.Add(commitments, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.commitments = (byte**)commitments;
                blobsBundle.commitments_len = (ulong)commitmentsLen;
            }

            {
                var proofsLen = payload.Data.BlobsBundle.Commitments.Length;
                var proofs = Marshal.AllocHGlobal(proofsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < proofsLen; ++i)
                {
                    var proof = Marshal.AllocHGlobal(48);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)proof, 48, 48); }
                    Marshal.StructureToPtr(proof, IntPtr.Add(proofs, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.proofs = (byte**)proofs;
                blobsBundle.proofs_len = (ulong)proofsLen;
            }

            {
                var blobsLen = payload.Data.BlobsBundle.Commitments.Length;
                var blobs = Marshal.AllocHGlobal(blobsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < blobsLen; ++i)
                {
                    var blob = Marshal.AllocHGlobal(4096 * 32);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)blob, 4096 * 32, 4096 * 32); }
                    Marshal.StructureToPtr(blob, IntPtr.Add(blobs, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.blobs = (byte**)blobs;
                blobsBundle.blobs_len = (ulong)blobsLen;
            }

            response.blobs_bundle = blobsBundle;

            response.should_override_builder = payload.Data.ShouldOverrideBuilder;

            var executionRequests = new CExecutionRequests { };

            {
                var requestsLen = payload.Data.ExecutionRequests.Length;
                var requests = Marshal.AllocHGlobal(requestsLen * Marshal.SizeOf<CRequest>());

                for (var i = 0; i < requestsLen; ++i)
                {
                    var bytesLen = payload.Data.ExecutionRequests[i].Length;
                    var bytes = Marshal.AllocHGlobal(bytesLen);
                    fixed (byte* sourcePtr = payload.Data.ExecutionRequests[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)bytes, bytesLen, bytesLen); }
                    Marshal.StructureToPtr(new CRequest { bytes = (byte*)bytes, bytes_len = (ulong)bytesLen }, IntPtr.Add(requests, i * Marshal.SizeOf<CRequest>()), false);
                }

                executionRequests.requests = (CRequest*)requests;
                executionRequests.requests_len = (ulong)requestsLen;
            }

            response.execution_requests = executionRequests;

            return new CResultCEngineGetPayloadV4Response
            {
                error = 0,
                value = response,
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception " + e);

            return new CResultCEngineGetPayloadV4Response
            {
                error = 1
            };
        }
    }

    unsafe CResultCEngineGetPayloadV5Response EngineGetPayloadV5(byte* payloadId)
    {
        _logger.Warn("================================================================= engine_getPayloadV5 =================================================================");

        try
        {
            var convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var payload = _engineRpc.engine_getPayloadV5(convertedPayloadId).Result;

            if (payload.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var response = new CEngineGetPayloadV5Response { };

            var exPayload = new CExecutionPayloadV3 { };

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.ParentHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.parent_hash, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.FeeRecipient.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.fee_recipient, 20, 20); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.StateRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.state_root, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.ReceiptsRoot.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.receipts_root, 32, 32); }

            {
                var bloomLen = payload.Data.ExecutionPayload.LogsBloom.Bytes.Length;
                IntPtr convBloom = Marshal.AllocHGlobal(bloomLen);
                Marshal.Copy(payload.Data.ExecutionPayload.LogsBloom.Bytes.ToArray(), 0, convBloom, bloomLen);
                exPayload.logs_bloom = (byte*)convBloom;
                exPayload.logs_bloom_len = (ulong)bloomLen;
            }

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.PrevRandao.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.prev_randao, 32, 32); }
            exPayload.block_number = (ulong)payload.Data.ExecutionPayload.BlockNumber;
            exPayload.gas_limit = (ulong)payload.Data.ExecutionPayload.GasLimit;
            exPayload.gas_used = (ulong)payload.Data.ExecutionPayload.GasUsed;
            exPayload.timestamp = payload.Data.ExecutionPayload.Timestamp;

            {
                var extraDataLen = payload.Data.ExecutionPayload.ExtraData.Length;
                IntPtr convExtraData = Marshal.AllocHGlobal(extraDataLen);
                Marshal.Copy(payload.Data.ExecutionPayload.ExtraData.ToArray(), 0, convExtraData, extraDataLen);
                exPayload.extra_data = (byte*)convExtraData;
                exPayload.extra_data_len = (ulong)extraDataLen;
            }

            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.BaseFeePerGas.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, exPayload.base_fee_per_gas, 32, 32); }
            fixed (byte* sourcePtr = payload.Data.ExecutionPayload.BlockHash.Bytes) { Buffer.MemoryCopy(sourcePtr, exPayload.block_hash, 32, 32); }

            {
                var transactionsLen = payload.Data.ExecutionPayload.Transactions.Length;
                IntPtr convTransactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var len = payload.Data.ExecutionPayload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(len);
                    Marshal.Copy(payload.Data.ExecutionPayload.Transactions[i], 0, transaction, len);
                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes_len = (ulong)len,
                        bytes = (byte*)transaction,
                    },
                        IntPtr.Add(convTransactions, i * Marshal.SizeOf<CTransaction>()),
                        false
                    );
                }
                ;

                exPayload.transactions = (CTransaction*)convTransactions;
                exPayload.transactions_len = (ulong)transactionsLen;
            }

            {
                var withdrawalsLen = payload.Data.ExecutionPayload.Transactions.Length;
                IntPtr convWithdrawals = Marshal.AllocHGlobal(withdrawalsLen * Marshal.SizeOf<CWithdrawalV1>());
                for (var i = 0; i < withdrawalsLen; ++i)
                {
                    var withdrawal = new CWithdrawalV1 { };

                    withdrawal.index = payload.Data.ExecutionPayload.Withdrawals[i].Index;
                    withdrawal.validator_index = payload.Data.ExecutionPayload.Withdrawals[i].ValidatorIndex;
                    fixed (byte* sourcePtr = payload.Data.ExecutionPayload.Withdrawals[i].Address.Bytes) { Buffer.MemoryCopy(sourcePtr, withdrawal.address, 20, 20); }
                    withdrawal.amount = (ulong)payload.Data.ExecutionPayload.Withdrawals[i].AmountInGwei;

                    Marshal.StructureToPtr(withdrawal, IntPtr.Add(convWithdrawals, i * Marshal.SizeOf<CWithdrawalV1>()), false);
                }

                exPayload.withdrawals = (CWithdrawalV1*)convWithdrawals;
                exPayload.withdrawals_len = (ulong)withdrawalsLen;
            }

            exPayload.blob_gas_used = (ulong)payload.Data.ExecutionPayload.BlobGasUsed;
            exPayload.excess_blob_gas = (ulong)payload.Data.ExecutionPayload.ExcessBlobGas;

            response.execution_payload = exPayload;

            fixed (byte* sourcePtr = payload.Data.BlockValue.ToBigEndian()) { Buffer.MemoryCopy(sourcePtr, response.block_value, 32, 32); }

            var blobsBundle = new CBlobsBundleV1 { };

            {
                var commitmentsLen = payload.Data.BlobsBundle.Commitments.Length;
                var commitments = Marshal.AllocHGlobal(commitmentsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < commitmentsLen; ++i)
                {
                    var commitment = Marshal.AllocHGlobal(48);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)commitment, 48, 48); }
                    Marshal.StructureToPtr(commitment, IntPtr.Add(commitments, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.commitments = (byte**)commitments;
                blobsBundle.commitments_len = (ulong)commitmentsLen;
            }

            {
                var proofsLen = payload.Data.BlobsBundle.Commitments.Length;
                var proofs = Marshal.AllocHGlobal(proofsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < proofsLen; ++i)
                {
                    var proof = Marshal.AllocHGlobal(48);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)proof, 48, 48); }
                    Marshal.StructureToPtr(proof, IntPtr.Add(proofs, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.proofs = (byte**)proofs;
                blobsBundle.proofs_len = (ulong)proofsLen;
            }

            {
                var blobsLen = payload.Data.BlobsBundle.Commitments.Length;
                var blobs = Marshal.AllocHGlobal(blobsLen * Marshal.SizeOf<IntPtr>());

                for (var i = 0; i < blobsLen; ++i)
                {
                    var blob = Marshal.AllocHGlobal(4096 * 32);
                    fixed (byte* sourcePtr = payload.Data.BlobsBundle.Commitments[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)blob, 4096 * 32, 4096 * 32); }
                    Marshal.StructureToPtr(blob, IntPtr.Add(blobs, i * Marshal.SizeOf<IntPtr>()), false);
                }

                blobsBundle.blobs = (byte**)blobs;
                blobsBundle.blobs_len = (ulong)blobsLen;
            }

            response.blobs_bundle = blobsBundle;

            response.should_override_builder = payload.Data.ShouldOverrideBuilder;

            var executionRequests = new CExecutionRequests { };

            {
                var requestsLen = payload.Data.ExecutionRequests.Length;
                var requests = Marshal.AllocHGlobal(requestsLen * Marshal.SizeOf<CRequest>());

                for (var i = 0; i < requestsLen; ++i)
                {
                    var bytesLen = payload.Data.ExecutionRequests[i].Length;
                    var bytes = Marshal.AllocHGlobal(bytesLen);
                    fixed (byte* sourcePtr = payload.Data.ExecutionRequests[i]) { Buffer.MemoryCopy(sourcePtr, (byte*)bytes, bytesLen, bytesLen); }
                    Marshal.StructureToPtr(new CRequest { bytes = (byte*)bytes, bytes_len = (ulong)bytesLen }, IntPtr.Add(requests, i * Marshal.SizeOf<CRequest>()), false);
                }

                executionRequests.requests = (CRequest*)requests;
                executionRequests.requests_len = (ulong)requestsLen;
            }

            response.execution_requests = executionRequests;

            return new CResultCEngineGetPayloadV5Response
            {
                error = 0,
                value = response,
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception " + e);

            return new CResultCEngineGetPayloadV5Response
            {
                error = 1
            };
        }
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

    unsafe CResultCOptionCVecCBlobAndProofV2 EngineGetBlobsV2(byte** versionedHashes, ulong versionedHashesLen) {
        _logger.Warn("================================================================= engine_getBlobsV2 =================================================================");
        
        try {
            var versionedHashesConverted = new List<byte[]>();
            for (var i = 0; i < (int)versionedHashesLen; ++i)
            {
                versionedHashesConverted.Add(new ReadOnlySpan<byte>(versionedHashes[i], 32).ToArray());
            }
            var blobs = _engineRpc.engine_getBlobsV2(versionedHashesConverted.ToArray()).Result;

            if (blobs.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            if (blobs.Data == null)
            {
                return new CResultCOptionCVecCBlobAndProofV2
                {
                    error = 0,
                    value = new COptionCVecCBlobAndProofV2
                    {
                        is_something = false,
                    }
                };
            }

            var blobsArray = blobs.Data.ToArray();

            var result = Marshal.AllocHGlobal(blobsArray.Length * Marshal.SizeOf<CBlobAndProofV2>());

            for (var i = 0; i < blobsArray.Length; ++i)
            {
                var proofs = Marshal.AllocHGlobal(128 * Marshal.SizeOf<CH384>());
                for (var j = 0; j < 128; ++j)
                {
                    var proof = new CH384 { };
                    fixed (byte* sourcePtr = blobsArray[i].Proofs[j]) { Buffer.MemoryCopy(sourcePtr, proof.Item1, 48, 48); }
                    Marshal.StructureToPtr(proof, IntPtr.Add(proofs, j * Marshal.SizeOf<CH384>()), false);
                }

                var blob = Marshal.AllocHGlobal(4096 * 32);
                Marshal.Copy(blobsArray[i].Blob, 0, blob, 4096 * 32);

                Marshal.StructureToPtr(new CBlobAndProofV2 { proof = (CH384*)proofs, blob = (byte*)blob }, IntPtr.Add(result, i * Marshal.SizeOf<CBlobAndProofV2>()), false);
            }

            return new CResultCOptionCVecCBlobAndProofV2
            {
                error = 0,
                value = new COptionCVecCBlobAndProofV2
                {
                    is_something = true,
                    value = new CVecCBlobAndProofV2
                    {
                        data = (CBlobAndProofV2*)result,
                        data_len = (ulong)blobsArray.Length
                    }
                }
            };
        } catch (Exception e)
        {
            _logger.Error("Exception: " + e);
            return new CResultCOptionCVecCBlobAndProofV2
            {
                error = 1
            };
        }
    }
}