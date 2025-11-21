namespace Grandine.Native;

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

using Grandine.NethermindPlugin;

using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Int256;
using Nethermind.Merge.Plugin.Data;

public unsafe partial struct CPayloadStatusV1
{
    public CPayloadStatusV1(PayloadStatusV1 status)
    {
        this.status = GrandineUtils.ConvertPayloadValidationStatus(status.Status);
        this.latest_valid_hash = CH256.FromOptionalHash256(status.LatestValidHash);
        this.validation_error = new CErrorMessage(status.ValidationError);
    }
}

public unsafe partial struct CWithdrawalV1
{
    public CWithdrawalV1(Withdrawal withdrawal)
    {
        this.index = withdrawal.Index;
        this.validator_index = withdrawal.ValidatorIndex;
        this.address = new CH160(withdrawal.Address);
        this.amount = withdrawal.AmountInGwei;
    }

    public readonly Withdrawal ToWithdrawal() => new Withdrawal
    {
        Index = this.index,
        ValidatorIndex = this.validator_index,
        Address = this.address.ToAddress(),
        AmountInGwei = this.amount,
    };
}

public unsafe partial struct CForkChoiceStateV1
{
    public readonly ForkchoiceStateV1 ToForkchoiceStateV1() => new ForkchoiceStateV1(
        this.head_block_hash.ToHash256(),
        this.finalized_block_hash.ToHash256(),
        this.safe_block_hash.ToHash256());
}

public unsafe partial struct CForkChoiceUpdatedResponse
{
    public CForkChoiceUpdatedResponse(ForkchoiceUpdatedV1Result result)
    {
        this.payload_status = new CPayloadStatusV1(result.PayloadStatus);
        this.payload_id = CH64.FromOptionalHexString(result.PayloadId);
    }
}

public unsafe partial struct CExecutionPayloadV1
{
    public CExecutionPayloadV1(ExecutionPayload payload)
    {
        this.parent_hash = new CH256(payload.ParentHash);
        this.fee_recipient = new CH160(payload.FeeRecipient);
        this.state_root = new CH256(payload.StateRoot);
        this.receipts_root = new CH256(payload.ReceiptsRoot);
        this.logs_bloom = GrandineUtils.ConvertLogsBloom(payload.LogsBloom);
        this.prev_randao = new CH256(payload.PrevRandao);
        this.block_number = (ulong)payload.BlockNumber;
        this.gas_limit = (ulong)payload.GasLimit;
        this.gas_used = (ulong)payload.GasUsed;
        this.timestamp = payload.Timestamp;
        this.extra_data = new CVec_u8(payload.ExtraData);
        this.base_fee_per_gas = new CH256(payload.BaseFeePerGas);
        this.block_hash = new CH256(payload.BlockHash);
        this.transactions = GrandineUtils.TransactionsFromBytes(payload.Transactions);
    }
}

public unsafe partial struct CExecutionPayloadV2
{
    public CExecutionPayloadV2(ExecutionPayload payload)
    {
        this.parent_hash = new CH256(payload.ParentHash);
        this.fee_recipient = new CH160(payload.FeeRecipient);
        this.state_root = new CH256(payload.StateRoot);
        this.receipts_root = new CH256(payload.ReceiptsRoot);
        this.logs_bloom = GrandineUtils.ConvertLogsBloom(payload.LogsBloom);
        this.prev_randao = new CH256(payload.PrevRandao);
        this.block_number = (ulong)payload.BlockNumber;
        this.gas_limit = (ulong)payload.GasLimit;
        this.gas_used = (ulong)payload.GasUsed;
        this.timestamp = payload.Timestamp;
        this.extra_data = new CVec_u8(payload.ExtraData);
        this.base_fee_per_gas = new CH256(payload.BaseFeePerGas);
        this.block_hash = new CH256(payload.BlockHash);
        this.transactions = GrandineUtils.TransactionsFromBytes(payload.Transactions);
        this.withdrawals = GrandineUtils.WithdrawalsToNative(payload.Withdrawals ?? throw new ArgumentException("ExecutionPayload.Withdrawals must not be null", nameof(payload)));
    }
}

public unsafe partial struct CExecutionPayloadV3
{
    public CExecutionPayloadV3(ExecutionPayload payload)
    {
        this.parent_hash = new CH256(payload.ParentHash);
        this.fee_recipient = new CH160(payload.FeeRecipient);
        this.state_root = new CH256(payload.StateRoot);
        this.receipts_root = new CH256(payload.ReceiptsRoot);
        this.logs_bloom = GrandineUtils.ConvertLogsBloom(payload.LogsBloom);
        this.prev_randao = new CH256(payload.PrevRandao);
        this.block_number = (ulong)payload.BlockNumber;
        this.gas_limit = (ulong)payload.GasLimit;
        this.gas_used = (ulong)payload.GasUsed;
        this.timestamp = payload.Timestamp;
        this.extra_data = new CVec_u8(payload.ExtraData);
        this.base_fee_per_gas = new CH256(payload.BaseFeePerGas);
        this.block_hash = new CH256(payload.BlockHash);
        this.transactions = GrandineUtils.TransactionsFromBytes(payload.Transactions);
        this.withdrawals = GrandineUtils.WithdrawalsToNative(payload.Withdrawals ?? throw new ArgumentException("ExecutionPayload.Withdrawals must not be null", nameof(payload)));
        this.blob_gas_used = (ulong)(payload.BlobGasUsed ?? throw new ArgumentException("ExecutionPayload.BlobGasUsed must not be null", nameof(payload)));
        this.excess_blob_gas = (ulong)(payload.ExcessBlobGas ?? throw new ArgumentException("ExecutionPayload.ExcessBlobGas must not be null", nameof(payload)));
    }
}

public unsafe partial struct CEngineGetPayloadV2Response
{
    public CEngineGetPayloadV2Response(GetPayloadV2Result result)
    {
        this.execution_payload = new CExecutionPayloadV2(result.ExecutionPayload ?? throw new ArgumentException("GetPayloadV2Result.ExecutionPayload must not be null", nameof(result)));
        this.block_value = new CH256(result.BlockValue);
    }
}

public unsafe partial struct CEngineGetPayloadV3Response
{
    public CEngineGetPayloadV3Response(GetPayloadV3Result result)
    {
        this.execution_payload = new CExecutionPayloadV3(result.ExecutionPayload);
        this.block_value = new CH256(result.BlockValue);
        this.blobs_bundle = new CBlobsBundleV1(result.BlobsBundle);
        this.should_override_builder = result.ShouldOverrideBuilder;
    }
}

public unsafe partial struct CEngineGetPayloadV4Response
{
    public CEngineGetPayloadV4Response(GetPayloadV4Result result)
    {
        this.execution_payload = new CExecutionPayloadV3(result.ExecutionPayload);
        this.block_value = new CH256(result.BlockValue);
        this.blobs_bundle = new CBlobsBundleV1(result.BlobsBundle);
        this.should_override_builder = result.ShouldOverrideBuilder;
        this.execution_requests = new CExecutionRequests(result.ExecutionRequests ?? throw new ArgumentException("GetPayloadV4Result.ExecutionRequests must not be null", nameof(result)));
    }
}

public unsafe partial struct CEngineGetPayloadV5Response
{
    public CEngineGetPayloadV5Response(GetPayloadV5Result result)
    {
        this.execution_payload = new CExecutionPayloadV3(result.ExecutionPayload);
        this.block_value = new CH256(result.BlockValue);
        this.blobs_bundle = new CBlobsBundleV1(result.BlobsBundle);
        this.should_override_builder = result.ShouldOverrideBuilder;
        this.execution_requests = new CExecutionRequests(result.ExecutionRequests ?? throw new ArgumentException("GetPayloadV5Result.ExecutionRequests must not be null", nameof(result)));
    }
}

public unsafe partial struct CTransaction
{
    public CTransaction(CVec_u8 input)
    {
        this._0 = input;
    }

    public readonly ReadOnlySpan<byte> AsBytes()
    {
        return this._0.AsSpan();
    }
}

public unsafe partial struct CBlobsBundleV1
{
    public CBlobsBundleV1(BlobsBundleV1 bundle)
    {
        this.commitments = GrandineUtils.CommitmentsOrProofsToNative(bundle.Commitments);
        this.proofs = GrandineUtils.CommitmentsOrProofsToNative(bundle.Proofs);
        this.blobs = GrandineUtils.BytesToNative(bundle.Blobs);
    }

    public CBlobsBundleV1(BlobsBundleV2 bundle)
    {
        this.commitments = GrandineUtils.CommitmentsOrProofsToNative(bundle.Commitments);
        this.proofs = GrandineUtils.CommitmentsOrProofsToNative(bundle.Proofs);
        this.blobs = GrandineUtils.BytesToNative(bundle.Blobs);
    }
}

public unsafe partial struct CBlobAndProofV1
{
    public CBlobAndProofV1(BlobAndProofV1 value)
    {
        this.blob = new CVec_u8(value.Blob);
        this.proof = new CH384(value.Proof);
    }
}

public unsafe partial struct CBlobAndProofV2
{
    public CBlobAndProofV2(BlobAndProofV2 value)
    {
        this.blob = new CVec_u8(value.Blob);
        this.proof = GrandineUtils.CommitmentsOrProofsToNative(value.Proofs);
    }
}

public unsafe partial struct CExecutionRequests
{
    public CExecutionRequests(byte[][] bytes)
    {
        this._0 = GrandineUtils.BytesToNative(bytes);
    }

    public readonly ReadOnlySpan<CVec_u8> AsSpan()
    {
        return this._0.AsSpan();
    }
}

public unsafe partial struct CH384
{
    public CH384(byte[] bytes)
    {
        if (bytes.Length != 48)
        {
            throw new ArgumentException("CH384 requires exactly 48 bytes", nameof(bytes));
        }

        fixed (byte* destinationPtr = this._0)
        fixed (byte* sourcePtr = bytes)
        {
            Buffer.MemoryCopy(sourcePtr, destinationPtr, 48, 48);
        }
    }
}

public unsafe partial struct CH256
{
    public CH256(UInt256 input)
    {
        fixed (byte* destinationPtr = this._0)
        fixed (byte* sourcePtr = input.ToBigEndian())
        {
            Buffer.MemoryCopy(sourcePtr, destinationPtr, 32, 32);
        }
    }

    public CH256(Hash256 hash)
    {
        fixed (byte* destinationPtr = this._0)
        fixed (byte* sourcePtr = hash.Bytes)
        {
            Buffer.MemoryCopy(sourcePtr, destinationPtr, 32, 32);
        }
    }

    public static COption_CH256 FromOptionalHash256(Hash256? value)
    {
        if (value == null)
        {
            return new COption_CH256() { is_something = false };
        }

        return new COption_CH256() { is_something = true, value = new CH256(value) };
    }

    public Hash256 ToHash256()
    {
        return new Hash256(this.AsSpan());
    }

    public UInt256 ToUInt256()
    {
        return new UInt256(this.AsSpan(), true);
    }

    public readonly ReadOnlySpan<byte> AsSpan()
    {
        fixed (byte* data = this._0)
        {
            return new ReadOnlySpan<byte>(data, 32);
        }
    }

    public readonly byte[] ToArray() => this.AsSpan().ToArray();
}

public unsafe partial struct CH160
{
    public CH160(Address address)
    {
        fixed (byte* destinationPtr = this._0)
        fixed (byte* sourcePtr = address.Bytes)
        {
            Buffer.MemoryCopy(sourcePtr, destinationPtr, 20, 20);
        }
    }

    public unsafe readonly Address ToAddress()
    {
        return new Address(this.AsSpan());
    }

    public unsafe readonly ReadOnlySpan<byte> AsSpan()
    {
        fixed (byte* data = this._0)
        {
            return new ReadOnlySpan<byte>(data, 20);
        }
    }
}

public unsafe partial struct CH64
{
    public CH64(string value)
    {
        if (value.StartsWith("0x"))
        {
            value = value[2..];
        }

        var raw = Convert.FromHexString(value);

        if (raw.Length != 8)
        {
            throw new ArgumentException("Hex payloadmust decode to exactly 8 bytes.");
        }

        fixed (byte* destinationPtr = this._0)
        fixed (byte* sourcePtr = raw)
        {
            Buffer.MemoryCopy(sourcePtr, destinationPtr, 8, 8);
        }
    }

    public static COption_CH64 FromOptionalHexString(string? value)
    {
        if (value == null)
        {
            return new COption_CH64()
            {
                is_something = false,
            };
        }

        return new COption_CH64
        {
            is_something = true,
            value = new CH64(value),
        };
    }

    public unsafe readonly ReadOnlySpan<byte> AsSpan()
    {
        fixed (byte* data = this._0)
        {
            return new ReadOnlySpan<byte>(data, 8);
        }
    }

    public unsafe readonly byte[] ToArray() => this.AsSpan().ToArray();
}

public unsafe partial struct CVec_u8
{
    public CVec_u8(nuint length)
    {
        if (length == 0)
        {
            this.data = null;
            this.data_len = 0;
            return;
        }

        IntPtr pointer;
        unsafe
        {
            pointer = (IntPtr)NativeMethods.grandine_alloc(length);
        }

        this.data = (byte*)pointer.ToPointer();
        this.data_len = length;
    }

    public CVec_u8(byte[] input)
        : this((uint)input.Length)
    {
        if (input.Length == 0)
        {
            return;
        }

        unsafe
        {
            Marshal.Copy((byte[])(object)input, 0, (IntPtr)this.data, input.Length);
        }
    }

    public readonly ReadOnlySpan<byte> AsSpan()
    {
        if (sizeof(nuint) > sizeof(int) && this.data_len > int.MaxValue)
        {
            ThrowLengthTooLarge();
        }

        return new ReadOnlySpan<byte>(this.data, checked((int)this.data_len));
    }

    public readonly Span<byte> AsMutableSpan()
    {
        if (sizeof(nuint) > sizeof(int) && this.data_len > int.MaxValue)
        {
            ThrowLengthTooLarge();
        }

        return new Span<byte>(this.data, checked((int)this.data_len));
    }

    public readonly byte[] ToArray()
    {
        var span = this.AsSpan();
        if (span.Length == 0)
        {
            return Array.Empty<byte>();
        }

        var arr = new byte[span.Length];
        span.CopyTo(arr);
        return arr;
    }

    private static void ThrowLengthTooLarge() =>
        throw new OverflowException("data_len exceeds Int32.MaxValue");
}

public unsafe partial struct CVec_CVec_u8
{
    public CVec_CVec_u8(nuint length)
    {
        if (length == 0)
        {
            this.data = null;
            this.data_len = 0;
            return;
        }

        IntPtr pointer;
        unsafe
        {
            pointer = (IntPtr)NativeMethods.grandine_alloc(length * (nuint)Marshal.SizeOf<CVec_u8>());
        }

        this.data = (CVec_u8*)pointer.ToPointer();
        this.data_len = length;
    }

    public static CVec_CVec_u8 Empty() => new (0);

    public readonly ReadOnlySpan<CVec_u8> AsSpan()
    {
        if (sizeof(nuint) > sizeof(int) && this.data_len > int.MaxValue)
        {
            ThrowLengthTooLarge();
        }

        return new ReadOnlySpan<CVec_u8>(this.data, checked((int)this.data_len));
    }

    public readonly Span<CVec_u8> AsMutableSpan()
    {
        if (sizeof(nuint) > sizeof(int) && this.data_len > int.MaxValue)
        {
            ThrowLengthTooLarge();
        }

        return new Span<CVec_u8>(this.data, checked((int)this.data_len));
    }

    public readonly CVec_u8[] ToArray()
    {
        var span = this.AsSpan();
        if (span.Length == 0)
        {
            return Array.Empty<CVec_u8>();
        }

        var arr = new CVec_u8[span.Length];
        span.CopyTo(arr);
        return arr;
    }

    private static void ThrowLengthTooLarge() =>
        throw new OverflowException("data_len exceeds Int32.MaxValue");
}

public unsafe partial struct CVec_CBlobAndProofV2
{
    public CVec_CBlobAndProofV2(nuint length)
    {
        if (length == 0)
        {
            this.data = null;
            this.data_len = 0;
            return;
        }

        IntPtr pointer;
        unsafe
        {
            pointer = (IntPtr)NativeMethods.grandine_alloc(length * (nuint)Marshal.SizeOf<CBlobAndProofV2>());
        }

        this.data = (CBlobAndProofV2*)pointer.ToPointer();
        this.data_len = length;
    }

    public CVec_CBlobAndProofV2(CBlobAndProofV2[] array)
        : this((nuint)array.Length)
    {
        if (array.Length == 0)
        {
            return;
        }

        unsafe
        {
            var ptr = (IntPtr)this.data;

            for (var i = 0; i < array.Length; ++i)
            {
                Marshal.StructureToPtr(array[i], IntPtr.Add(ptr, i * Marshal.SizeOf<CBlobAndProofV2>()), false);
            }
        }
    }

    public CVec_CBlobAndProofV2(IEnumerable<CBlobAndProofV2> enumerator)
        : this(enumerator?.ToArray() ?? Array.Empty<CBlobAndProofV2>())
    {
    }
}

public unsafe partial struct CVec_COption_CBlobAndProofV1
{
    public CVec_COption_CBlobAndProofV1(nuint length)
    {
        if (length == 0)
        {
            this.data = null;
            this.data_len = 0;
            return;
        }

        IntPtr pointer;
        unsafe
        {
            pointer = (IntPtr)NativeMethods.grandine_alloc(length * (nuint)Marshal.SizeOf<COption_CBlobAndProofV1>());
        }

        this.data = (COption_CBlobAndProofV1*)pointer.ToPointer();
        this.data_len = length;
    }

    public CVec_COption_CBlobAndProofV1(COption_CBlobAndProofV1[] array)
        : this((nuint)array.Length)
    {
        if (array.Length == 0)
        {
            return;
        }

        unsafe
        {
            var ptr = (IntPtr)this.data;

            for (var i = 0; i < array.Length; ++i)
            {
                Marshal.StructureToPtr(array[i], IntPtr.Add(ptr, i * Marshal.SizeOf<COption_CBlobAndProofV1>()), false);
            }
        }
    }

    public CVec_COption_CBlobAndProofV1(IEnumerable<COption_CBlobAndProofV1> enumerator)
        : this(enumerator?.ToArray() ?? Array.Empty<COption_CBlobAndProofV1>())
    {
    }
}

public unsafe partial struct CVec_CTransaction
{
    public CVec_CTransaction(nuint length)
    {
        if (length == 0)
        {
            this.data = null;
            this.data_len = 0;
            return;
        }

        IntPtr pointer;
        unsafe
        {
            pointer = (IntPtr)NativeMethods.grandine_alloc(length * (nuint)Marshal.SizeOf<CTransaction>());
        }

        this.data = (CTransaction*)pointer.ToPointer();
        this.data_len = length;
    }

    public CVec_CTransaction(CTransaction[] input)
        : this((uint)input.Length)
    {
        if (input.Length == 0)
        {
            return;
        }

        unsafe
        {
            var ptr = (IntPtr)this.data;

            for (var i = 0; i < input.Length; ++i)
            {
                Marshal.StructureToPtr(input[i], IntPtr.Add(ptr, i * Marshal.SizeOf<CTransaction>()), false);
            }
        }
    }

    public static CVec_CTransaction Empty() => new (0);

    public readonly ReadOnlySpan<CTransaction> AsSpan()
    {
        if (sizeof(nuint) > sizeof(int) && this.data_len > int.MaxValue)
        {
            ThrowLengthTooLarge();
        }

        return new ReadOnlySpan<CTransaction>(this.data, checked((int)this.data_len));
    }

    public readonly Span<CTransaction> AsMutableSpan()
    {
        if (sizeof(nuint) > sizeof(int) && this.data_len > int.MaxValue)
        {
            ThrowLengthTooLarge();
        }

        return new Span<CTransaction>(this.data, checked((int)this.data_len));
    }

    private static void ThrowLengthTooLarge() =>
        throw new OverflowException("data_len exceeds Int32.MaxValue");
}

public unsafe partial struct CVec_CWithdrawalV1
{
    public CVec_CWithdrawalV1(nuint length)
    {
        if (length == 0)
        {
            this.data = null;
            this.data_len = 0;
            return;
        }

        IntPtr pointer;
        unsafe
        {
            pointer = (IntPtr)NativeMethods.grandine_alloc(length * (nuint)Marshal.SizeOf<CWithdrawalV1>());
        }

        this.data = (CWithdrawalV1*)pointer.ToPointer();
        this.data_len = length;
    }

    public CVec_CWithdrawalV1(CWithdrawalV1[] input)
        : this((uint)input.Length)
    {
        if (input.Length == 0)
        {
            return;
        }

        unsafe
        {
            var ptr = (IntPtr)this.data;

            for (var i = 0; i < input.Length; ++i)
            {
                Marshal.StructureToPtr(input[i], IntPtr.Add(ptr, i * Marshal.SizeOf<CWithdrawalV1>()), false);
            }
        }
    }

    public static CVec_CWithdrawalV1 Empty() => new (0);

    public readonly ReadOnlySpan<CWithdrawalV1> AsSpan()
    {
        if (sizeof(nuint) > sizeof(int) && this.data_len > int.MaxValue)
        {
            ThrowLengthTooLarge();
        }

        return new ReadOnlySpan<CWithdrawalV1>(this.data, checked((int)this.data_len));
    }

    private static void ThrowLengthTooLarge() =>
        throw new OverflowException("data_len exceeds Int32.MaxValue");
}

public unsafe partial struct CVec_CH384
{
    public CVec_CH384(nuint length)
    {
        if (length == 0)
        {
            this.data = null;
            this.data_len = 0;
            return;
        }

        IntPtr pointer;
        unsafe
        {
            pointer = (IntPtr)NativeMethods.grandine_alloc(length * (nuint)Marshal.SizeOf<CH384>());
        }

        this.data = (CH384*)pointer.ToPointer();
        this.data_len = length;
    }

    public static CVec_CH384 Empty() => new (0);
}

public unsafe partial struct CVec_CH256
{
    public readonly ReadOnlySpan<CH256> AsSpan()
    {
        if (sizeof(nuint) > sizeof(int) && this.data_len > int.MaxValue)
        {
            ThrowLengthTooLarge();
        }

        return new ReadOnlySpan<CH256>(this.data, checked((int)this.data_len));
    }

    private static void ThrowLengthTooLarge() =>
        throw new OverflowException("data_len exceeds Int32.MaxValue");
}

public unsafe partial struct CResult_COption_CVec_CBlobAndProofV2
{
    public static CResult_COption_CVec_CBlobAndProofV2 Success(COption_CVec_CBlobAndProofV2 value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_COption_CVec_CBlobAndProofV2 Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_COption_CVec_CBlobAndProofV2 Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct CResult_CVec_COption_CBlobAndProofV1
{
    public static CResult_CVec_COption_CBlobAndProofV1 Success(CVec_COption_CBlobAndProofV1 value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_CVec_COption_CBlobAndProofV1 Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_CVec_COption_CBlobAndProofV1 Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct CResult_CEngineGetPayloadV5Response
{
    public static CResult_CEngineGetPayloadV5Response Success(CEngineGetPayloadV5Response value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_CEngineGetPayloadV5Response Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_CEngineGetPayloadV5Response Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct CResult_CEngineGetPayloadV4Response
{
    public static CResult_CEngineGetPayloadV4Response Success(CEngineGetPayloadV4Response value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_CEngineGetPayloadV4Response Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_CEngineGetPayloadV4Response Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct CResult_CEngineGetPayloadV3Response
{
    public static CResult_CEngineGetPayloadV3Response Success(CEngineGetPayloadV3Response value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_CEngineGetPayloadV3Response Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_CEngineGetPayloadV3Response Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct CResult_CEngineGetPayloadV2Response
{
    public static CResult_CEngineGetPayloadV2Response Success(CEngineGetPayloadV2Response value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_CEngineGetPayloadV2Response Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_CEngineGetPayloadV2Response Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct CResult_CExecutionPayloadV1
{
    public static CResult_CExecutionPayloadV1 Success(CExecutionPayloadV1 value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_CExecutionPayloadV1 Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_CExecutionPayloadV1 Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct CResult_CForkChoiceUpdatedResponse
{
    public static CResult_CForkChoiceUpdatedResponse Success(CForkChoiceUpdatedResponse value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_CForkChoiceUpdatedResponse Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_CForkChoiceUpdatedResponse Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct CResult_CPayloadStatusV1
{
    public static CResult_CPayloadStatusV1 Success(CPayloadStatusV1 value) => new () { code = NativeMethods.GRANDINE_SUCCESS, value = value };

    public static CResult_CPayloadStatusV1 Fail(uint errorCode) => new () { code = errorCode, message = CErrorMessage.Empty };

    public static CResult_CPayloadStatusV1 Fail(uint errorCode, string? message) => new () { code = errorCode, message = new CErrorMessage(message) };
}

public unsafe partial struct COption_CVec_CBlobAndProofV2
{
    public static COption_CVec_CBlobAndProofV2 None => new () { is_something = false };

    public static COption_CVec_CBlobAndProofV2 Some(CVec_CBlobAndProofV2 value) => new () { is_something = true, value = value };
}

public unsafe partial struct COption_CBlobAndProofV1
{
    public static COption_CBlobAndProofV1 None => new () { is_something = false };

    public static COption_CBlobAndProofV1 Some(CBlobAndProofV1 value) => new () { is_something = true, value = value };
}

public unsafe partial struct CErrorMessage
{
    public CErrorMessage(string? message)
    {
        if (message == null)
        {
            this._0 = null;
        }
        else
        {
            byte[] strBytes = Encoding.ASCII.GetBytes(message + '\0');

            fixed (byte* bytesPtr = strBytes)
            unsafe
            {
                var msg = NativeMethods.grandine_error_message(bytesPtr);
                this._0 = msg._0;
            }
        }
    }

    public static CErrorMessage Empty => new (null);

    public override readonly string ToString()
    {
        if (this._0 == null)
        {
            return string.Empty;
        }

        return Marshal.PtrToStringUTF8((nint)this._0) ?? string.Empty;
    }
}
