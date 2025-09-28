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
internal delegate CResultU64 EthBlockNumberDelegate();

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCOptionCEth1Block EthGetBlockByHashDelegate(CH256 hash);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCOptionCEth1Block EthGetBlockByNumberDelegate(ulong number);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCOptionCEth1Block EthGetBlockFinalizedDelegate();

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCOptionCEth1Block EthGetBlockSafeDelegate();

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCOptionCEth1Block EthGetBlockLatestDelegate();

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCOptionCEth1Block EthGetBlockEarliestDelegate();

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate CResultCOptionCEth1Block EthGetBlockPendingDelegate();

// [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
// internal delegate CResultCLogs EthGetLogsDelegate(CFilter filter);

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
unsafe internal delegate CResultCExecutionPayloadV1 EngineGetPayloadV1Delegate(byte* payloadId);

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

public class GrandineEngineApi
{
    EthBlockNumberDelegate _eth_blockNumber;
    EthGetBlockByHashDelegate _eth_getBlockByHash;
    EthGetBlockByNumberDelegate _eth_getBlockByNumber;
    EthGetBlockFinalizedDelegate _eth_getBlockFinalized;
    EthGetBlockSafeDelegate _eth_getBlockSafe;
    EthGetBlockLatestDelegate _eth_getBlockLatest;
    EthGetBlockEarliestDelegate _eth_getBlockEarliest;
    EthGetBlockPendingDelegate _eth_getBlockPending;
    // EthGetLogsDelegate _eth_getLogs;
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

    ILogger _logger;
    IEngineRpcModule _engineRpc;
    // IEthRpcModule _ethRpc;

    CEmbedAdapter _adapter;

    public GrandineEngineApi(ILogger logger, IEngineRpcModule engineRpc/*, IEthRpcModule ethRpc*/)
    {
        _logger = logger;
        _engineRpc = engineRpc;
        // _ethRpc = ethRpc;

        unsafe
        {
            _eth_blockNumber = EthBlockNumber;
            _eth_getBlockByHash = EthGetBlockByHash;
            _eth_getBlockByNumber = EthGetBlockByNumber;
            _eth_getBlockFinalized = EthGetBlockFinalized;
            _eth_getBlockSafe = EthGetBlockSafe;
            _eth_getBlockLatest = EthGetBlockLatest;
            _eth_getBlockEarliest = EthGetBlockEarliest;
            _eth_getBlockPending = EthGetBlockPending;
            // _eth_getLogs = EthGetLogs;
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

            IntPtr eth_blockNumberPtr = Marshal.GetFunctionPointerForDelegate(_eth_blockNumber);
            IntPtr eth_getBlockByHashPtr = Marshal.GetFunctionPointerForDelegate(_eth_getBlockByHash);
            IntPtr eth_getBlockByNumberPtr = Marshal.GetFunctionPointerForDelegate(_eth_getBlockByNumber);
            IntPtr eth_getBlockFinalizedPtr = Marshal.GetFunctionPointerForDelegate(_eth_getBlockFinalized);
            IntPtr eth_getBlockSafePtr = Marshal.GetFunctionPointerForDelegate(_eth_getBlockSafe);
            IntPtr eth_getBlockLatestPtr = Marshal.GetFunctionPointerForDelegate(_eth_getBlockLatest);
            IntPtr eth_getBlockEarliestPtr = Marshal.GetFunctionPointerForDelegate(_eth_getBlockEarliest);
            IntPtr eth_getBlockPendingPtr = Marshal.GetFunctionPointerForDelegate(_eth_getBlockPending);
            // IntPtr eth_getLogsPtr = Marshal.GetFunctionPointerForDelegate(_eth_getLogs);
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

            _adapter = new CEmbedAdapter
            {
                eth_block_number = (delegate* unmanaged[Cdecl]<CResultU64>)eth_blockNumberPtr,
                eth_get_block_by_hash = (delegate* unmanaged[Cdecl]<CH256, CResultCOptionCEth1Block>)eth_getBlockByHashPtr,
                eth_get_block_by_number = (delegate* unmanaged[Cdecl]<ulong, CResultCOptionCEth1Block>)eth_getBlockByNumberPtr,
                eth_get_block_finalized = (delegate* unmanaged[Cdecl]<CResultCOptionCEth1Block>)eth_getBlockFinalizedPtr,
                eth_get_block_safe = (delegate* unmanaged[Cdecl]<CResultCOptionCEth1Block>)eth_getBlockSafePtr,
                eth_get_block_latest = (delegate* unmanaged[Cdecl]<CResultCOptionCEth1Block>)eth_getBlockLatestPtr,
                eth_get_block_earliest = (delegate* unmanaged[Cdecl]<CResultCOptionCEth1Block>)eth_getBlockEarliestPtr,
                eth_get_block_pending = (delegate* unmanaged[Cdecl]<CResultCOptionCEth1Block>)eth_getBlockPendingPtr,
                // eth_logs = (delegate* unmanaged[Cdecl]<CFilter, CResultCLogs>)eth_getLogsPtr,
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
            };
        }
    }

    public CEmbedAdapter getAdapter()
    {
        return this._adapter;
    }

    CResultU64 EthBlockNumber()
    {
        _logger.Warn("================================================================= eth_blockNumber =================================================================");
        try
        {
            throw new Exception("Not implemented");
            // var blockNumber = _ethRpc.eth_blockNumber().Result;

            // if (blockNumber.Result != Result.Success)
            // {
            //     throw new Exception("unexpected failure");
            // }

            // return new CResultU64
            // {
            //     value = (ulong)(blockNumber.Data ?? 0),
            //     error = 0,
            // };
        }
        catch (Exception)
        {
            return new CResultU64
            {
                error = 1
            };
        }
    }

    unsafe CResultCOptionCEth1Block EthGetBlockByHash(CH256 hash)
    {
        _logger.Warn("================================================================= eth_getBlockByHash =================================================================");

        try
        {
            // var block = _ethRpc.eth_getBlockByHash(new Hash256(new ReadOnlySpan<byte>(hash.Item1, 32).ToArray()));

            // if (block.Result != Result.Success)
            // {
            //     throw new Exception("unexpected failure");
            // }

            throw new Exception("Not implemented");

            // var output = new CEth1Block();
            // if (block.Data != null) {
            //     if (block.Data.Hash.Bytes.Length != 32)
            //     {
            //         throw new Exception("Hash field must be exactly 32 bytes long");
            //     }
            //     fixed (byte* sourcePtr = block.Data.Hash.Bytes)
            //     {
            //         Buffer.MemoryCopy(sourcePtr, output.hash, 32, 32);
            //     }

            //     if (block.Data.Hash.ParentHash.Length != 32)
            //     {
            //         throw new Exception("ParentHash field must be exactly 32 bytes long");
            //     }
            //     fixed (byte* sourcePtr = block.Data.ParentHash.Bytes)
            //     {
            //         Buffer.MemoryCopy(sourcePtr, output.hash, 32, 32);
            //     }
            // }

            // return new CResultCOptionCEth1Block
            // {
            //     value = (ulong)(blockNumber.Data ?? 0),
            //     error = 0,
            // };
        }
        catch (Exception)
        {
            return new CResultCOptionCEth1Block
            {
                error = 1
            };
        }
    }

    CResultCOptionCEth1Block EthGetBlockByNumber(ulong number)
    {
        _logger.Error("================================================================= eth_getBlockByNumber =================================================================");
        return new CResultCOptionCEth1Block
        {
            error = 1
        };
    }

    CResultCOptionCEth1Block EthGetBlockFinalized()
    {
        _logger.Error("================================================================= eth_getBlockFinalized =================================================================");

        return new CResultCOptionCEth1Block
        {
            error = 1
        };
    }

    CResultCOptionCEth1Block EthGetBlockSafe()
    {
        _logger.Error("================================================================= eth_getBlockSafe =================================================================");
        return new CResultCOptionCEth1Block
        {
            error = 1
        };
    }

    CResultCOptionCEth1Block EthGetBlockLatest()
    {
        _logger.Error("================================================================= eth_getBlockLatest =================================================================");
        return new CResultCOptionCEth1Block
        {
            error = 1
        };
    }

    CResultCOptionCEth1Block EthGetBlockEarliest()
    {
        _logger.Error("================================================================= eth_getBlockEarliest =================================================================");
        return new CResultCOptionCEth1Block
        {
            error = 1
        };
    }

    CResultCOptionCEth1Block EthGetBlockPending()
    {
        _logger.Error("================================================================= eth_getBlockPending =================================================================");
        return new CResultCOptionCEth1Block
        {
            error = 1
        };
    }

    // CResultCLogs EthGetLogs(CFilter filter)
    // {
    //     _logger.Error("================================================================= eth_getLogs =================================================================");
    //     return new CResultCLogs
    //     {
    //         error = 1
    //     };
    // }

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV1(CExecutionPayloadV1 payload)
    {
        _logger.Warn("================================================================= engine_newPayloadV1 =================================================================");
        try
        {
            var transactions = new List<byte[]>();
            for (var i = 0; i < (int)payload.transactions_len; ++i)
            {
                transactions.Add(new ReadOnlySpan<byte>(payload.transactions[i].bytes, (int)payload.transactions[i].bytes_len).ToArray());
            }

            var payloadStatus = _engineRpc.engine_newPayloadV1(new Nethermind.Merge.Plugin.Data.ExecutionPayload
            {
                BaseFeePerGas = new UInt256(new ReadOnlySpan<byte>(payload.base_fee_per_gas, 32).ToArray(), true),
                BlockHash = new Hash256(new ReadOnlySpan<byte>(payload.block_hash, 32).ToArray()),
                BlockNumber = (long)payload.block_number,
                ExtraData = new ReadOnlySpan<byte>(payload.extra_data, (int)payload.extra_data_len).ToArray(),
                FeeRecipient = new Address(new ReadOnlySpan<byte>(payload.fee_recipient, 20).ToArray()),
                GasLimit = (long)payload.gas_limit,
                GasUsed = (long)payload.gas_used,
                LogsBloom = new Bloom(new ReadOnlySpan<byte>(payload.logs_bloom, (int)payload.logs_bloom_len).ToArray()),
                ParentHash = new Hash256(new ReadOnlySpan<byte>(payload.parent_hash, 32).ToArray()),
                PrevRandao = new Hash256(new ReadOnlySpan<byte>(payload.prev_randao, 32).ToArray()),
                ReceiptsRoot = new Hash256(new ReadOnlySpan<byte>(payload.receipts_root, 32).ToArray()),
                StateRoot = new Hash256(new ReadOnlySpan<byte>(payload.state_root, 32).ToArray()),
                Timestamp = payload.timestamp,
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

            var latestValidHash = new CH256 { };

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

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV2(CExecutionPayloadV2 payload)
    {
        _logger.Warn("================================================================= engine_newPayloadV2 =================================================================");

        try
        {
            var transactions = new List<byte[]>();
            for (var i = 0; i < (int)payload.transactions_len; ++i)
            {
                transactions.Add(new ReadOnlySpan<byte>(payload.transactions[i].bytes, (int)payload.transactions[i].bytes_len).ToArray());
            }

            var withdrawals = new List<Withdrawal>();
            for (var i = 0; i < (int)payload.withdrawals_len; ++i)
            {
                withdrawals.Add(new Withdrawal
                {
                    Index = payload.withdrawals[i].index,
                    ValidatorIndex = payload.withdrawals[i].validator_index,
                    Address = new Address(new ReadOnlySpan<byte>(payload.withdrawals[i].address, 20).ToArray()),
                    AmountInGwei = payload.withdrawals[i].amount,
                });
            }

            var payloadStatus = _engineRpc.engine_newPayloadV2(new Nethermind.Merge.Plugin.Data.ExecutionPayload
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

            var latestValidHash = new CH256 { };

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

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV3(CExecutionPayloadV3 payload, byte** versionedHashes, ulong versionedHashesLen, byte* parentBeaconBlockRoot)
    {
        _logger.Warn("================================================================= engine_newPayloadV3 =================================================================");

        try
        {
            var transactions = new List<byte[]>();
            for (var i = 0; i < (int)payload.transactions_len; ++i)
            {
                transactions.Add(new ReadOnlySpan<byte>(payload.transactions[i].bytes, (int)payload.transactions[i].bytes_len).ToArray());
            }

            var withdrawals = new List<Withdrawal>();
            for (var i = 0; i < (int)payload.withdrawals_len; ++i)
            {
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

            var latestValidHash = new CH256 { };

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

    unsafe CResultCPayloadStatusV1 EngineNewPayloadV4(CExecutionPayloadV3 payload, byte** versionedHashes, ulong versionedHashesLen, byte* parentBeaconBlockRoot, CExecutionRequests executionRequests)
    {
        _logger.Warn("================================================================= engine_newPayloadV4 =================================================================");

        try
        {
            var transactions = new List<byte[]>();
            for (var i = 0; i < (int)payload.transactions_len; ++i)
            {
                transactions.Add(new ReadOnlySpan<byte>(payload.transactions[i].bytes, (int)payload.transactions[i].bytes_len).ToArray());
            }

            var withdrawals = new List<Withdrawal>();
            for (var i = 0; i < (int)payload.withdrawals_len; ++i)
            {
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

            var latestValidHash = new CH256 { };

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
        try
        {
            PayloadAttributes? attributes = null;
            if (payload.is_something)
            {
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

            var latestValidHash = new CH256 { };

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
            if (forkchoiceUpdatedResult.Data.PayloadId != null)
            {
                var raw = Convert.FromHexString(forkchoiceUpdatedResult.Data.PayloadId);

                if (raw.Length != 8)
                {
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
        }
        catch (Exception e)
        {
            _logger.Error("Exception " + e);

            return new CResultCForkChoiceUpdatedResponse
            {
                error = 1
            };
        }
    }

    unsafe CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV2(CForkChoiceStateV1 state, COptionCPayloadAttributesV2 payload)
    {
        _logger.Warn("================================================================= engine_forkchoiceUpdatedV2 =================================================================");
        try
        {
            PayloadAttributes? attributes = null;
            if (payload.is_something)
            {
                var withdrawals = new List<Withdrawal>();
                for (var i = 0; i < (int)payload.value.withdrawals_len; ++i)
                {
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
                    // ParentBeaconBlockRoot = new Hash256(new ReadOnlySpan<byte>(payload.value.parent_beacon_block_root, 32).ToArray())
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

            var latestValidHash = new CH256 { };

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
            if (forkchoiceUpdatedResult.Data.PayloadId != null)
            {
                var raw = Convert.FromHexString(forkchoiceUpdatedResult.Data.PayloadId);

                if (raw.Length != 8)
                {
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
        }
        catch (Exception e)
        {
            _logger.Error("Exception " + e);

            return new CResultCForkChoiceUpdatedResponse
            {
                error = 1
            };
        }
    }

    unsafe CResultCForkChoiceUpdatedResponse EngineForkchoiceUpdatedV3(CForkChoiceStateV1 state, COptionCPayloadAttributesV3 payload)
    {
        _logger.Warn("================================================================= engine_forkchoiceUpdatedV3 =================================================================");
        try
        {
            PayloadAttributes? attributes = null;
            if (payload.is_something)
            {
                var withdrawals = new List<Withdrawal>();
                for (var i = 0; i < (int)payload.value.withdrawals_len; ++i)
                {
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

            var latestValidHash = new CH256 { };

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
            if (forkchoiceUpdatedResult.Data.PayloadId != null)
            {
                var raw = Convert.FromHexString(forkchoiceUpdatedResult.Data.PayloadId);

                if (raw.Length != 8)
                {
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
        }
        catch (Exception e)
        {
            _logger.Error("Exception " + e);

            return new CResultCForkChoiceUpdatedResponse
            {
                error = 1
            };
        }
    }

    unsafe CResultCExecutionPayloadV1 EngineGetPayloadV1(byte* payloadId)
    {
        _logger.Warn("================================================================= engine_getPayloadV1 =================================================================");

        try
        {
            byte[] convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var result = _engineRpc.engine_getPayloadV1(convertedPayloadId).Result;

            if (result.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var payload = result.Data;
            if (payload == null)
            {
                throw new Exception("Payload not found");
            }

            var convertedPayload = new CExecutionPayloadV1();
            fixed (byte* sourcePtr = payload.ParentHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.parent_hash, 32, 32);
            fixed (byte* sourcePtr = payload.FeeRecipient.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.fee_recipient, 20, 20);
            fixed (byte* sourcePtr = payload.StateRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.state_root, 32, 32);
            fixed (byte* sourcePtr = payload.ReceiptsRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.receipts_root, 32, 32);

            {
                var logsBloomLength = payload.LogsBloom.Bytes.Length;
                IntPtr logsBloom = Marshal.AllocHGlobal(logsBloomLength);
                fixed (byte* sourcePtr = payload.LogsBloom.Bytes) Buffer.MemoryCopy(sourcePtr, (byte*)logsBloom, logsBloomLength, logsBloomLength);
                convertedPayload.logs_bloom = (byte*)logsBloom;
                convertedPayload.logs_bloom_len = (ulong)logsBloomLength;
            }

            fixed (byte* sourcePtr = payload.PrevRandao.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.prev_randao, 32, 32);
            convertedPayload.block_number = (ulong)payload.BlockNumber;
            convertedPayload.gas_limit = (ulong)payload.GasLimit;
            convertedPayload.gas_used = (ulong)payload.GasUsed;
            convertedPayload.timestamp = payload.Timestamp;

            {
                var extraDataLength = payload.ExtraData.Length;
                IntPtr extraData = Marshal.AllocHGlobal(extraDataLength);
                fixed (byte* sourcePtr = payload.ExtraData) Buffer.MemoryCopy(sourcePtr, (byte*)extraData, extraDataLength, extraDataLength);
                convertedPayload.logs_bloom = (byte*)extraData;
                convertedPayload.logs_bloom_len = (ulong)extraDataLength;
            }

            fixed (byte* sourcePtr = payload.BaseFeePerGas.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedPayload.base_fee_per_gas, 32, 32);
            fixed (byte* sourcePtr = payload.BlockHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.block_hash, 32, 32);

            {
                var transactionsLen = payload.Transactions.Length;
                IntPtr transactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var transactionLen = payload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(transactionLen);
                    fixed (byte* sourcePtr = payload.Transactions[i]) Buffer.MemoryCopy(sourcePtr, (byte*)transaction, transactionLen, transactionLen);

                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes = (byte*)transaction,
                        bytes_len = (ulong)transactionLen,
                    }, IntPtr.Add(transactions, i * Marshal.SizeOf<CTransaction>()), false);
                }
                convertedPayload.transactions = (CTransaction*)transactions;
                convertedPayload.transactions_len = (ulong)transactionsLen;
            }

            return new CResultCExecutionPayloadV1
            {
                error = 0,
                value = convertedPayload
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception: " + e);

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
            byte[] convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var result = _engineRpc.engine_getPayloadV2(convertedPayloadId).Result;

            if (result.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var response = result.Data;
            if (response == null)
            {
                throw new Exception("Payload not found");
            }

            var convertedResponse = new CEngineGetPayloadV2Response();

            fixed (byte* sourcePtr = response.BlockValue.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedResponse.block_value, 32, 32);

            var convertedPayload = new CExecutionPayloadV2();
            fixed (byte* sourcePtr = response.ExecutionPayload.ParentHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.parent_hash, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.FeeRecipient.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.fee_recipient, 20, 20);
            fixed (byte* sourcePtr = response.ExecutionPayload.StateRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.state_root, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.ReceiptsRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.receipts_root, 32, 32);

            {
                var logsBloomLength = response.ExecutionPayload.LogsBloom.Bytes.Length;
                IntPtr logsBloom = Marshal.AllocHGlobal(logsBloomLength);
                fixed (byte* sourcePtr = response.ExecutionPayload.LogsBloom.Bytes) Buffer.MemoryCopy(sourcePtr, (byte*)logsBloom, logsBloomLength, logsBloomLength);
                convertedPayload.logs_bloom = (byte*)logsBloom;
                convertedPayload.logs_bloom_len = (ulong)logsBloomLength;
            }

            fixed (byte* sourcePtr = response.ExecutionPayload.PrevRandao.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.prev_randao, 32, 32);
            convertedPayload.block_number = (ulong)response.ExecutionPayload.BlockNumber;
            convertedPayload.gas_limit = (ulong)response.ExecutionPayload.GasLimit;
            convertedPayload.gas_used = (ulong)response.ExecutionPayload.GasUsed;
            convertedPayload.timestamp = response.ExecutionPayload.Timestamp;

            {
                var extraDataLength = response.ExecutionPayload.ExtraData.Length;
                IntPtr extraData = Marshal.AllocHGlobal(extraDataLength);
                fixed (byte* sourcePtr = response.ExecutionPayload.ExtraData) Buffer.MemoryCopy(sourcePtr, (byte*)extraData, extraDataLength, extraDataLength);
                convertedPayload.logs_bloom = (byte*)extraData;
                convertedPayload.logs_bloom_len = (ulong)extraDataLength;
            }

            fixed (byte* sourcePtr = response.ExecutionPayload.BaseFeePerGas.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedPayload.base_fee_per_gas, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.BlockHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.block_hash, 32, 32);

            {
                var transactionsLen = response.ExecutionPayload.Transactions.Length;
                IntPtr transactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var transactionLen = response.ExecutionPayload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(transactionLen);
                    fixed (byte* sourcePtr = response.ExecutionPayload.Transactions[i]) Buffer.MemoryCopy(sourcePtr, (byte*)transaction, transactionLen, transactionLen);

                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes = (byte*)transaction,
                        bytes_len = (ulong)transactionLen,
                    }, IntPtr.Add(transactions, i * Marshal.SizeOf<CTransaction>()), false);
                }
                convertedPayload.transactions = (CTransaction*)transactions;
                convertedPayload.transactions_len = (ulong)transactionsLen;
            }

            if (response.ExecutionPayload.Withdrawals == null)
            {
                convertedPayload.withdrawals = null;
                convertedPayload.withdrawals_len = 0;
            }
            else
            {
                var withdrawalsLen = response.ExecutionPayload.Withdrawals.Length;
                IntPtr withdrawals = Marshal.AllocHGlobal(withdrawalsLen * Marshal.SizeOf<CWithdrawalV1>());
                for (var i = 0; i < withdrawalsLen; ++i)
                {
                    var withdrawal = new CWithdrawalV1();
                    withdrawal.index = response.ExecutionPayload.Withdrawals[i].Index;
                    withdrawal.validator_index = response.ExecutionPayload.Withdrawals[i].ValidatorIndex;
                    fixed (byte* sourcePtr = response.ExecutionPayload.Withdrawals[i].Address.Bytes) Buffer.MemoryCopy(sourcePtr, withdrawal.address, 20, 20);
                    withdrawal.amount = response.ExecutionPayload.Withdrawals[i].AmountInGwei;
                    Marshal.StructureToPtr(withdrawal, IntPtr.Add(withdrawals, i * Marshal.SizeOf<CWithdrawalV1>()), false);
                }
                convertedPayload.withdrawals = (CWithdrawalV1*)withdrawals;
                convertedPayload.withdrawals_len = (ulong)withdrawalsLen;
            }
            convertedResponse.execution_payload = convertedPayload;

            return new CResultCEngineGetPayloadV2Response
            {
                error = 0,
                value = convertedResponse
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception: " + e);

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
            byte[] convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var result = _engineRpc.engine_getPayloadV3(convertedPayloadId).Result;

            if (result.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var response = result.Data;
            if (response == null)
            {
                throw new Exception("Payload not found");
            }

            var convertedResponse = new CEngineGetPayloadV3Response();

            fixed (byte* sourcePtr = response.BlockValue.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedResponse.block_value, 32, 32);

            var convertedPayload = new CExecutionPayloadV3();
            fixed (byte* sourcePtr = response.ExecutionPayload.ParentHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.parent_hash, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.FeeRecipient.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.fee_recipient, 20, 20);
            fixed (byte* sourcePtr = response.ExecutionPayload.StateRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.state_root, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.ReceiptsRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.receipts_root, 32, 32);

            {
                var logsBloomLength = response.ExecutionPayload.LogsBloom.Bytes.Length;
                IntPtr logsBloom = Marshal.AllocHGlobal(logsBloomLength);
                fixed (byte* sourcePtr = response.ExecutionPayload.LogsBloom.Bytes) Buffer.MemoryCopy(sourcePtr, (byte*)logsBloom, logsBloomLength, logsBloomLength);
                convertedPayload.logs_bloom = (byte*)logsBloom;
                convertedPayload.logs_bloom_len = (ulong)logsBloomLength;
            }

            fixed (byte* sourcePtr = response.ExecutionPayload.PrevRandao.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.prev_randao, 32, 32);
            convertedPayload.block_number = (ulong)response.ExecutionPayload.BlockNumber;
            convertedPayload.gas_limit = (ulong)response.ExecutionPayload.GasLimit;
            convertedPayload.gas_used = (ulong)response.ExecutionPayload.GasUsed;
            convertedPayload.timestamp = response.ExecutionPayload.Timestamp;

            {
                var extraDataLength = response.ExecutionPayload.ExtraData.Length;
                IntPtr extraData = Marshal.AllocHGlobal(extraDataLength);
                fixed (byte* sourcePtr = response.ExecutionPayload.ExtraData) Buffer.MemoryCopy(sourcePtr, (byte*)extraData, extraDataLength, extraDataLength);
                convertedPayload.logs_bloom = (byte*)extraData;
                convertedPayload.logs_bloom_len = (ulong)extraDataLength;
            }

            fixed (byte* sourcePtr = response.ExecutionPayload.BaseFeePerGas.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedPayload.base_fee_per_gas, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.BlockHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.block_hash, 32, 32);

            {
                var transactionsLen = response.ExecutionPayload.Transactions.Length;
                IntPtr transactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var transactionLen = response.ExecutionPayload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(transactionLen);
                    fixed (byte* sourcePtr = response.ExecutionPayload.Transactions[i]) Buffer.MemoryCopy(sourcePtr, (byte*)transaction, transactionLen, transactionLen);

                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes = (byte*)transaction,
                        bytes_len = (ulong)transactionLen,
                    }, IntPtr.Add(transactions, i * Marshal.SizeOf<CTransaction>()), false);
                }
                convertedPayload.transactions = (CTransaction*)transactions;
                convertedPayload.transactions_len = (ulong)transactionsLen;
            }

            if (response.ExecutionPayload.Withdrawals == null)
            {
                convertedPayload.withdrawals = null;
                convertedPayload.withdrawals_len = 0;
            }
            else
            {
                var withdrawalsLen = response.ExecutionPayload.Withdrawals.Length;
                IntPtr withdrawals = Marshal.AllocHGlobal(withdrawalsLen * Marshal.SizeOf<CWithdrawalV1>());
                for (var i = 0; i < withdrawalsLen; ++i)
                {
                    var withdrawal = new CWithdrawalV1();
                    withdrawal.index = response.ExecutionPayload.Withdrawals[i].Index;
                    withdrawal.validator_index = response.ExecutionPayload.Withdrawals[i].ValidatorIndex;
                    fixed (byte* sourcePtr = response.ExecutionPayload.Withdrawals[i].Address.Bytes) Buffer.MemoryCopy(sourcePtr, withdrawal.address, 20, 20);
                    withdrawal.amount = response.ExecutionPayload.Withdrawals[i].AmountInGwei;
                    Marshal.StructureToPtr(withdrawal, IntPtr.Add(withdrawals, i * Marshal.SizeOf<CWithdrawalV1>()), false);
                }
                convertedPayload.withdrawals = (CWithdrawalV1*)withdrawals;
                convertedPayload.withdrawals_len = (ulong)withdrawalsLen;
            }
            convertedPayload.blob_gas_used = response.ExecutionPayload.BlobGasUsed ?? 0;
            convertedPayload.excess_blob_gas = response.ExecutionPayload.ExcessBlobGas ?? 0;
            convertedResponse.execution_payload = convertedPayload;

            var convertedBlobsBundle = new CBlobsBundleV1();
            {
                var commitmentsLen = response.BlobsBundle.Commitments.Length;
                IntPtr commitments = Marshal.AllocHGlobal(commitmentsLen * Marshal.SizeOf<CH384>());
                for (var i = 0; i < commitmentsLen; ++i)
                {
                    var commitment = new CH384();
                    fixed (byte* sourcePtr = response.BlobsBundle.Commitments[i]) Buffer.MemoryCopy(sourcePtr, commitment.Item1, 48, 48);
                    Marshal.StructureToPtr(commitment, IntPtr.Add(commitments, i * Marshal.SizeOf<CH384>()), false);
                }
                convertedBlobsBundle.commitments = (CH384*)commitments;
                convertedBlobsBundle.commitments_len = (ulong)commitmentsLen;
            }

            {
                var proofsLen = response.BlobsBundle.Proofs.Length;
                IntPtr proofs = Marshal.AllocHGlobal(proofsLen * Marshal.SizeOf<CH384>());
                for (var i = 0; i < proofsLen; ++i)
                {
                    var proof = new CH384();
                    fixed (byte* sourcePtr = response.BlobsBundle.Proofs[i]) Buffer.MemoryCopy(sourcePtr, proof.Item1, 48, 48);
                    Marshal.StructureToPtr(proof, IntPtr.Add(proofs, i * Marshal.SizeOf<CH384>()), false);
                }
                convertedBlobsBundle.proofs = (CH384*)proofs;
                convertedBlobsBundle.proofs_len = (ulong)proofsLen;
            }

            {
                var blobsLen = response.BlobsBundle.Blobs.Length;
                IntPtr blobs = Marshal.AllocHGlobal(blobsLen * IntPtr.Size);
                for (var i = 0; i < blobsLen; ++i)
                {
                    var blobSize = 131072;
                    IntPtr blob = Marshal.AllocHGlobal(blobSize);
                    fixed (byte* sourcePtr = response.BlobsBundle.Blobs[i]) Buffer.MemoryCopy(sourcePtr, (byte*)blob, blobSize, blobSize);
                    Marshal.StructureToPtr(blob, IntPtr.Add(blobs, i * IntPtr.Size), false);
                }
                convertedBlobsBundle.blobs = (byte**)blobs;
                convertedBlobsBundle.blobs_len = (ulong)blobsLen;
            }
            convertedResponse.blobs_bundle = convertedBlobsBundle;
            convertedResponse.should_override_builder = response.ShouldOverrideBuilder;

            return new CResultCEngineGetPayloadV3Response
            {
                error = 0,
                value = convertedResponse
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception: " + e);

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
            byte[] convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var result = _engineRpc.engine_getPayloadV4(convertedPayloadId).Result;

            if (result.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var response = result.Data;
            if (response == null)
            {
                throw new Exception("Payload not found");
            }

            var convertedResponse = new CEngineGetPayloadV4Response();

            fixed (byte* sourcePtr = response.BlockValue.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedResponse.block_value, 32, 32);

            var convertedPayload = new CExecutionPayloadV3();
            fixed (byte* sourcePtr = response.ExecutionPayload.ParentHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.parent_hash, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.FeeRecipient.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.fee_recipient, 20, 20);
            fixed (byte* sourcePtr = response.ExecutionPayload.StateRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.state_root, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.ReceiptsRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.receipts_root, 32, 32);

            {
                var logsBloomLength = response.ExecutionPayload.LogsBloom.Bytes.Length;
                IntPtr logsBloom = Marshal.AllocHGlobal(logsBloomLength);
                fixed (byte* sourcePtr = response.ExecutionPayload.LogsBloom.Bytes) Buffer.MemoryCopy(sourcePtr, (byte*)logsBloom, logsBloomLength, logsBloomLength);
                convertedPayload.logs_bloom = (byte*)logsBloom;
                convertedPayload.logs_bloom_len = (ulong)logsBloomLength;
            }

            fixed (byte* sourcePtr = response.ExecutionPayload.PrevRandao.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.prev_randao, 32, 32);
            convertedPayload.block_number = (ulong)response.ExecutionPayload.BlockNumber;
            convertedPayload.gas_limit = (ulong)response.ExecutionPayload.GasLimit;
            convertedPayload.gas_used = (ulong)response.ExecutionPayload.GasUsed;
            convertedPayload.timestamp = response.ExecutionPayload.Timestamp;

            {
                var extraDataLength = response.ExecutionPayload.ExtraData.Length;
                IntPtr extraData = Marshal.AllocHGlobal(extraDataLength);
                fixed (byte* sourcePtr = response.ExecutionPayload.ExtraData) Buffer.MemoryCopy(sourcePtr, (byte*)extraData, extraDataLength, extraDataLength);
                convertedPayload.logs_bloom = (byte*)extraData;
                convertedPayload.logs_bloom_len = (ulong)extraDataLength;
            }

            fixed (byte* sourcePtr = response.ExecutionPayload.BaseFeePerGas.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedPayload.base_fee_per_gas, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.BlockHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.block_hash, 32, 32);

            {
                var transactionsLen = response.ExecutionPayload.Transactions.Length;
                IntPtr transactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var transactionLen = response.ExecutionPayload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(transactionLen);
                    fixed (byte* sourcePtr = response.ExecutionPayload.Transactions[i]) Buffer.MemoryCopy(sourcePtr, (byte*)transaction, transactionLen, transactionLen);

                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes = (byte*)transaction,
                        bytes_len = (ulong)transactionLen,
                    }, IntPtr.Add(transactions, i * Marshal.SizeOf<CTransaction>()), false);
                }
                convertedPayload.transactions = (CTransaction*)transactions;
                convertedPayload.transactions_len = (ulong)transactionsLen;
            }

            if (response.ExecutionPayload.Withdrawals == null)
            {
                convertedPayload.withdrawals = null;
                convertedPayload.withdrawals_len = 0;
            }
            else
            {
                var withdrawalsLen = response.ExecutionPayload.Withdrawals.Length;
                IntPtr withdrawals = Marshal.AllocHGlobal(withdrawalsLen * Marshal.SizeOf<CWithdrawalV1>());
                for (var i = 0; i < withdrawalsLen; ++i)
                {
                    var withdrawal = new CWithdrawalV1();
                    withdrawal.index = response.ExecutionPayload.Withdrawals[i].Index;
                    withdrawal.validator_index = response.ExecutionPayload.Withdrawals[i].ValidatorIndex;
                    fixed (byte* sourcePtr = response.ExecutionPayload.Withdrawals[i].Address.Bytes) Buffer.MemoryCopy(sourcePtr, withdrawal.address, 20, 20);
                    withdrawal.amount = response.ExecutionPayload.Withdrawals[i].AmountInGwei;
                    Marshal.StructureToPtr(withdrawal, IntPtr.Add(withdrawals, i * Marshal.SizeOf<CWithdrawalV1>()), false);
                }
                convertedPayload.withdrawals = (CWithdrawalV1*)withdrawals;
                convertedPayload.withdrawals_len = (ulong)withdrawalsLen;
            }
            convertedPayload.blob_gas_used = response.ExecutionPayload.BlobGasUsed ?? 0;
            convertedPayload.excess_blob_gas = response.ExecutionPayload.ExcessBlobGas ?? 0;
            convertedResponse.execution_payload = convertedPayload;

            var convertedBlobsBundle = new CBlobsBundleV1();
            {
                var commitmentsLen = response.BlobsBundle.Commitments.Length;
                IntPtr commitments = Marshal.AllocHGlobal(commitmentsLen * Marshal.SizeOf<CH384>());
                for (var i = 0; i < commitmentsLen; ++i)
                {
                    var commitment = new CH384();
                    fixed (byte* sourcePtr = response.BlobsBundle.Commitments[i]) Buffer.MemoryCopy(sourcePtr, commitment.Item1, 48, 48);
                    Marshal.StructureToPtr(commitment, IntPtr.Add(commitments, i * Marshal.SizeOf<CH384>()), false);
                }
                convertedBlobsBundle.commitments = (CH384*)commitments;
                convertedBlobsBundle.commitments_len = (ulong)commitmentsLen;
            }

            {
                var proofsLen = response.BlobsBundle.Proofs.Length;
                IntPtr proofs = Marshal.AllocHGlobal(proofsLen * Marshal.SizeOf<CH384>());
                for (var i = 0; i < proofsLen; ++i)
                {
                    var proof = new CH384();
                    fixed (byte* sourcePtr = response.BlobsBundle.Proofs[i]) Buffer.MemoryCopy(sourcePtr, proof.Item1, 48, 48);
                    Marshal.StructureToPtr(proof, IntPtr.Add(proofs, i * Marshal.SizeOf<CH384>()), false);
                }
                convertedBlobsBundle.proofs = (CH384*)proofs;
                convertedBlobsBundle.proofs_len = (ulong)proofsLen;
            }

            {
                var blobsLen = response.BlobsBundle.Blobs.Length;
                IntPtr blobs = Marshal.AllocHGlobal(blobsLen * IntPtr.Size);
                for (var i = 0; i < blobsLen; ++i)
                {
                    var blobSize = 131072;
                    IntPtr blob = Marshal.AllocHGlobal(blobSize);
                    fixed (byte* sourcePtr = response.BlobsBundle.Blobs[i]) Buffer.MemoryCopy(sourcePtr, (byte*)blob, blobSize, blobSize);
                    Marshal.StructureToPtr(blob, IntPtr.Add(blobs, i * IntPtr.Size), false);
                }
                convertedBlobsBundle.blobs = (byte**)blobs;
                convertedBlobsBundle.blobs_len = (ulong)blobsLen;
            }
            convertedResponse.blobs_bundle = convertedBlobsBundle;
            convertedResponse.should_override_builder = response.ShouldOverrideBuilder;

            if (response.ExecutionRequests == null)
            {
                convertedResponse.execution_requests = new CExecutionRequests
                {
                    requests = null,
                    requests_len = 0,
                };
            }
            else
            {
                var requestsLen = response.ExecutionRequests.Length;
                var requests = Marshal.AllocHGlobal(requestsLen * Marshal.SizeOf<CRequest>());
                for (var i = 0; i < requestsLen; ++i)
                {
                    var bytesLen = response.ExecutionRequests[i].Length;
                    IntPtr bytes = Marshal.AllocHGlobal(bytesLen);
                    fixed (byte* sourcePtr = response.ExecutionRequests[i]) Buffer.MemoryCopy(sourcePtr, (byte*)bytes, bytesLen, bytesLen);
                    Marshal.StructureToPtr(new CRequest
                    {
                        bytes = (byte*)bytes,
                        bytes_len = (ulong)bytesLen,
                    }, IntPtr.Add(requests, i * Marshal.SizeOf<CRequest>()), false);
                }
                convertedResponse.execution_requests = new CExecutionRequests
                {
                    requests = (CRequest*)requests,
                    requests_len = (ulong)requestsLen,
                };
            }

            return new CResultCEngineGetPayloadV4Response
            {
                error = 0,
                value = convertedResponse
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception: " + e);

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
            byte[] convertedPayloadId = new ReadOnlySpan<byte>(payloadId, 8).ToArray();

            var result = _engineRpc.engine_getPayloadV5(convertedPayloadId).Result;

            if (result.Result != Result.Success)
            {
                throw new Exception("unexpected failure");
            }

            var response = result.Data;
            if (response == null)
            {
                throw new Exception("Payload not found");
            }

            var convertedResponse = new CEngineGetPayloadV5Response();

            fixed (byte* sourcePtr = response.BlockValue.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedResponse.block_value, 32, 32);

            var convertedPayload = new CExecutionPayloadV3();
            fixed (byte* sourcePtr = response.ExecutionPayload.ParentHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.parent_hash, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.FeeRecipient.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.fee_recipient, 20, 20);
            fixed (byte* sourcePtr = response.ExecutionPayload.StateRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.state_root, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.ReceiptsRoot.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.receipts_root, 32, 32);

            {
                var logsBloomLength = response.ExecutionPayload.LogsBloom.Bytes.Length;
                IntPtr logsBloom = Marshal.AllocHGlobal(logsBloomLength);
                fixed (byte* sourcePtr = response.ExecutionPayload.LogsBloom.Bytes) Buffer.MemoryCopy(sourcePtr, (byte*)logsBloom, logsBloomLength, logsBloomLength);
                convertedPayload.logs_bloom = (byte*)logsBloom;
                convertedPayload.logs_bloom_len = (ulong)logsBloomLength;
            }

            fixed (byte* sourcePtr = response.ExecutionPayload.PrevRandao.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.prev_randao, 32, 32);
            convertedPayload.block_number = (ulong)response.ExecutionPayload.BlockNumber;
            convertedPayload.gas_limit = (ulong)response.ExecutionPayload.GasLimit;
            convertedPayload.gas_used = (ulong)response.ExecutionPayload.GasUsed;
            convertedPayload.timestamp = response.ExecutionPayload.Timestamp;

            {
                var extraDataLength = response.ExecutionPayload.ExtraData.Length;
                IntPtr extraData = Marshal.AllocHGlobal(extraDataLength);
                fixed (byte* sourcePtr = response.ExecutionPayload.ExtraData) Buffer.MemoryCopy(sourcePtr, (byte*)extraData, extraDataLength, extraDataLength);
                convertedPayload.logs_bloom = (byte*)extraData;
                convertedPayload.logs_bloom_len = (ulong)extraDataLength;
            }

            fixed (byte* sourcePtr = response.ExecutionPayload.BaseFeePerGas.ToBigEndian()) Buffer.MemoryCopy(sourcePtr, convertedPayload.base_fee_per_gas, 32, 32);
            fixed (byte* sourcePtr = response.ExecutionPayload.BlockHash.Bytes) Buffer.MemoryCopy(sourcePtr, convertedPayload.block_hash, 32, 32);

            {
                var transactionsLen = response.ExecutionPayload.Transactions.Length;
                IntPtr transactions = Marshal.AllocHGlobal(transactionsLen * Marshal.SizeOf<CTransaction>());
                for (var i = 0; i < transactionsLen; ++i)
                {
                    var transactionLen = response.ExecutionPayload.Transactions[i].Length;
                    var transaction = Marshal.AllocHGlobal(transactionLen);
                    fixed (byte* sourcePtr = response.ExecutionPayload.Transactions[i]) Buffer.MemoryCopy(sourcePtr, (byte*)transaction, transactionLen, transactionLen);

                    Marshal.StructureToPtr(new CTransaction
                    {
                        bytes = (byte*)transaction,
                        bytes_len = (ulong)transactionLen,
                    }, IntPtr.Add(transactions, i * Marshal.SizeOf<CTransaction>()), false);
                }
                convertedPayload.transactions = (CTransaction*)transactions;
                convertedPayload.transactions_len = (ulong)transactionsLen;
            }

            if (response.ExecutionPayload.Withdrawals == null)
            {
                convertedPayload.withdrawals = null;
                convertedPayload.withdrawals_len = 0;
            }
            else
            {
                var withdrawalsLen = response.ExecutionPayload.Withdrawals.Length;
                IntPtr withdrawals = Marshal.AllocHGlobal(withdrawalsLen * Marshal.SizeOf<CWithdrawalV1>());
                for (var i = 0; i < withdrawalsLen; ++i)
                {
                    var withdrawal = new CWithdrawalV1();
                    withdrawal.index = response.ExecutionPayload.Withdrawals[i].Index;
                    withdrawal.validator_index = response.ExecutionPayload.Withdrawals[i].ValidatorIndex;
                    fixed (byte* sourcePtr = response.ExecutionPayload.Withdrawals[i].Address.Bytes) Buffer.MemoryCopy(sourcePtr, withdrawal.address, 20, 20);
                    withdrawal.amount = response.ExecutionPayload.Withdrawals[i].AmountInGwei;
                    Marshal.StructureToPtr(withdrawal, IntPtr.Add(withdrawals, i * Marshal.SizeOf<CWithdrawalV1>()), false);
                }
                convertedPayload.withdrawals = (CWithdrawalV1*)withdrawals;
                convertedPayload.withdrawals_len = (ulong)withdrawalsLen;
            }
            convertedPayload.blob_gas_used = response.ExecutionPayload.BlobGasUsed ?? 0;
            convertedPayload.excess_blob_gas = response.ExecutionPayload.ExcessBlobGas ?? 0;
            convertedResponse.execution_payload = convertedPayload;

            var convertedBlobsBundle = new CBlobsBundleV1();
            {
                var commitmentsLen = response.BlobsBundle.Commitments.Length;
                IntPtr commitments = Marshal.AllocHGlobal(commitmentsLen * Marshal.SizeOf<CH384>());
                for (var i = 0; i < commitmentsLen; ++i)
                {
                    var commitment = new CH384();
                    fixed (byte* sourcePtr = response.BlobsBundle.Commitments[i]) Buffer.MemoryCopy(sourcePtr, commitment.Item1, 48, 48);
                    Marshal.StructureToPtr(commitment, IntPtr.Add(commitments, i * Marshal.SizeOf<CH384>()), false);
                }
                convertedBlobsBundle.commitments = (CH384*)commitments;
                convertedBlobsBundle.commitments_len = (ulong)commitmentsLen;
            }

            {
                var proofsLen = response.BlobsBundle.Proofs.Length;
                IntPtr proofs = Marshal.AllocHGlobal(proofsLen * Marshal.SizeOf<CH384>());
                for (var i = 0; i < proofsLen; ++i)
                {
                    var proof = new CH384();
                    fixed (byte* sourcePtr = response.BlobsBundle.Proofs[i]) Buffer.MemoryCopy(sourcePtr, proof.Item1, 48, 48);
                    Marshal.StructureToPtr(proof, IntPtr.Add(proofs, i * Marshal.SizeOf<CH384>()), false);
                }
                convertedBlobsBundle.proofs = (CH384*)proofs;
                convertedBlobsBundle.proofs_len = (ulong)proofsLen;
            }

            {
                var blobsLen = response.BlobsBundle.Blobs.Length;
                IntPtr blobs = Marshal.AllocHGlobal(blobsLen * IntPtr.Size);
                for (var i = 0; i < blobsLen; ++i)
                {
                    var blobSize = 131072;
                    IntPtr blob = Marshal.AllocHGlobal(blobSize);
                    fixed (byte* sourcePtr = response.BlobsBundle.Blobs[i]) Buffer.MemoryCopy(sourcePtr, (byte*)blob, blobSize, blobSize);
                    Marshal.StructureToPtr(blob, IntPtr.Add(blobs, i * IntPtr.Size), false);
                }
                convertedBlobsBundle.blobs = (byte**)blobs;
                convertedBlobsBundle.blobs_len = (ulong)blobsLen;
            }
            convertedResponse.blobs_bundle = convertedBlobsBundle;
            convertedResponse.should_override_builder = response.ShouldOverrideBuilder;

            if (response.ExecutionRequests == null)
            {
                convertedResponse.execution_requests = new CExecutionRequests
                {
                    requests = null,
                    requests_len = 0,
                };
            }
            else
            {
                var requestsLen = response.ExecutionRequests.Length;
                var requests = Marshal.AllocHGlobal(requestsLen * Marshal.SizeOf<CRequest>());
                for (var i = 0; i < requestsLen; ++i)
                {
                    var bytesLen = response.ExecutionRequests[i].Length;
                    IntPtr bytes = Marshal.AllocHGlobal(bytesLen);
                    fixed (byte* sourcePtr = response.ExecutionRequests[i]) Buffer.MemoryCopy(sourcePtr, (byte*)bytes, bytesLen, bytesLen);
                    Marshal.StructureToPtr(new CRequest
                    {
                        bytes = (byte*)bytes,
                        bytes_len = (ulong)bytesLen,
                    }, IntPtr.Add(requests, i * Marshal.SizeOf<CRequest>()), false);
                }
                convertedResponse.execution_requests = new CExecutionRequests
                {
                    requests = (CRequest*)requests,
                    requests_len = (ulong)requestsLen,
                };
            }

            return new CResultCEngineGetPayloadV5Response
            {
                error = 0,
                value = convertedResponse
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception: " + e);

            return new CResultCEngineGetPayloadV5Response
            {
                error = 1
            };
        }
    }

    unsafe CResultCVecCOptionCBlobAndProofV1 EngineGetBlobsV1(byte** versionedHashes, ulong versionedHashesLen)
    {
        _logger.Warn("================================================================= engine_getBlobsV1 =================================================================");
        try
        {
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

            var blobArray = blobs.Data.Select(blob =>
            {
                if (blob == null)
                {
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

                if (blob.Blob.Length != 4096 * 32)
                {
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
            for (var i = 0; i < blobArray.Length; ++i)
            {
                Marshal.StructureToPtr(blobArray[i], IntPtr.Add(res, i * Marshal.SizeOf<COptionCBlobAndProofV1>()), false);
            }

            return new CResultCVecCOptionCBlobAndProofV1
            {
                error = 0,
                value = new CVecCOptionCBlobAndProofV1
                {
                    data = (COptionCBlobAndProofV1*)res,
                    data_len = (ulong)blobArray.Length,
                }
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception: " + e);
            return new CResultCVecCOptionCBlobAndProofV1
            {
                error = 1
            };
        }
    }

    unsafe CResultCOptionCVecCBlobAndProofV2 EngineGetBlobsV2(byte** versionedHashes, ulong versionedHashesLen)
    {
        _logger.Warn("================================================================= engine_getBlobsV2 =================================================================");
        try
        {
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
                    value = new COptionCVecCBlobAndProofV2
                    {
                        is_something = false,
                    },
                    error = 0
                };
            }

            var blobArray = blobs.Data.Select(blob =>
            {
                if (blob.Blob.Length != 4096 * 32)
                {
                    throw new Exception("Blob must be exactly 4096 * 32 bytes long");
                }
                IntPtr convBlob = Marshal.AllocHGlobal(blob.Blob.Length);
                Marshal.Copy(blob.Blob, 0, convBlob, blob.Blob.Length);

                var proofs = blob.Proofs.Select(proof =>
                {
                    var converted = new CH384();
                    if (proof.Length != 48)
                    {
                        throw new Exception("Proof field must be exactly 48 bytes long");
                    }
                    fixed (byte* sourcePtr = proof)
                    {
                        Buffer.MemoryCopy(sourcePtr, converted.Item1, 48, 48);
                    }

                    return converted;
                }).ToArray();

                IntPtr proofsConv = Marshal.AllocHGlobal(proofs.Length * Marshal.SizeOf<CH384>());
                for (var i = 0; i < proofs.Length; ++i)
                {
                    Marshal.StructureToPtr(proofs[i], IntPtr.Add(proofsConv, i * Marshal.SizeOf<CH384>()), false);
                }

                return new CBlobAndProofV2
                {
                    proof = (CH384*)proofsConv,
                    blob = (byte*)convBlob,
                };
            }).ToArray();

            IntPtr res = Marshal.AllocHGlobal(blobArray.Length * Marshal.SizeOf<CBlobAndProofV2>());
            for (var i = 0; i < blobArray.Length; ++i)
            {
                Marshal.StructureToPtr(blobArray[i], IntPtr.Add(res, i * Marshal.SizeOf<CBlobAndProofV2>()), false);
            }

            return new CResultCOptionCVecCBlobAndProofV2
            {
                error = 0,
                value = new COptionCVecCBlobAndProofV2
                {
                    is_something = true,
                    value = new CVecCBlobAndProofV2
                    {
                        data = (CBlobAndProofV2*)res,
                        data_len = (ulong)blobArray.Length,
                    }
                }
            };
        }
        catch (Exception e)
        {
            _logger.Error("Exception: " + e);
            return new CResultCOptionCVecCBlobAndProofV2
            {
                error = 1
            };
        }
    }
}
