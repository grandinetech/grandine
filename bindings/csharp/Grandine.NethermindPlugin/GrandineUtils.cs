namespace Grandine.NethermindPlugin;

using System;
using System.Runtime.InteropServices;
using Grandine.Native;
using Nethermind.Consensus.Producers;
using Nethermind.Core;
using Nethermind.Merge.Plugin.Data;

public static class GrandineUtils
{
    private static readonly ExactSizeArrayPool<Withdrawal> WithdrawalPool = new (1);

    public static byte[][] TransactionsToBytes(in CVec_CTransaction transactions)
    {
        var span = transactions.AsSpan();
        if (span.Length == 0)
        {
            return Array.Empty<byte[]>();
        }

        // possible optimization suggested by @LukaszRozmej: replacing this with ArrayPool allocation.
        // not possible at this moment, as ArrayPool can't return arrays with exact size. So to use this
        // optimization, big refactoring on nethermind side is required.
        var result = new byte[span.Length][];

        for (int i = 0; i < span.Length; ++i)
        {
            result[i] = span[i].AsBytes().ToArray();
        }

        return result;
    }

    public static CVec_CTransaction TransactionsFromBytes(byte[][] input)
    {
        if (input is null || input.Length == 0)
        {
            return CVec_CTransaction.Empty();
        }

        var result = new CVec_CTransaction((nuint)input.Length);
        var span = result.AsMutableSpan();

        for (int i = 0; i < input.Length; ++i)
        {
            byte[] array = input[i] ?? Array.Empty<byte>();
            var inner = new CVec_u8(array);
            span[i] = new CTransaction(inner);
        }

        return result;
    }

    public static Withdrawal[] WithdrawalsFromNative(in CVec_CWithdrawalV1 withdrawals)
    {
        var span = withdrawals.AsSpan();
        if (span.Length == 0)
        {
            return Array.Empty<Withdrawal>();
        }

        var result = WithdrawalPool.Rent(span.Length);

        for (int i = 0; i < span.Length; ++i)
        {
            result[i] = span[i].ToWithdrawal();
        }

        return result;
    }

    public static void ReturnWithdrawals(Withdrawal[] withdrawals)
    {
        WithdrawalPool.Return(withdrawals);
    }

    public static CVec_CWithdrawalV1 WithdrawalsToNative(Withdrawal[] withdrawals)
    {
        if (withdrawals == null || withdrawals.Length == 0)
        {
            return CVec_CWithdrawalV1.Empty();
        }

        var result = new CVec_CWithdrawalV1((nuint)withdrawals.Length);

        unsafe
        {
            var ptr = (IntPtr)result.data;

            for (var i = 0; i < withdrawals.Length; ++i)
            {
                Marshal.StructureToPtr(new CWithdrawalV1(withdrawals[i]), IntPtr.Add(ptr, i * Marshal.SizeOf<CWithdrawalV1>()), false);
            }
        }

        return result;
    }

    public static CVec_CH384 CommitmentsOrProofsToNative(byte[][] input)
    {
        if (input == null || input.Length == 0)
        {
            return CVec_CH384.Empty();
        }

        var result = new CVec_CH384((nuint)input.Length);

        unsafe
        {
            var ptr = (IntPtr)result.data;

            for (var i = 0; i < input.Length; ++i)
            {
                Marshal.StructureToPtr(new CH384(input[i]), IntPtr.Add(ptr, i * Marshal.SizeOf<CH384>()), false);
            }
        }

        return result;
    }

    public static CVec_CVec_u8 BytesToNative(byte[][] bytes)
    {
        if (bytes == null || bytes.Length == 0)
        {
            return CVec_CVec_u8.Empty();
        }

        var result = new CVec_CVec_u8((nuint)bytes.Length);

        unsafe
        {
            var ptr = (IntPtr)result.data;

            for (var i = 0; i < bytes.Length; ++i)
            {
                Marshal.StructureToPtr(new CVec_u8(bytes[i]), IntPtr.Add(ptr, i * Marshal.SizeOf<CVec_u8>()), false);
            }
        }

        return result;
    }

    public static byte[][] ConvertVersionedHashes(in CVec_CH256 versionedHashes)
    {
        var span = versionedHashes.AsSpan();
        if (span.Length == 0)
        {
            return Array.Empty<byte[]>();
        }

        var result = new byte[span.Length][];

        for (int i = 0; i < span.Length; ++i)
        {
            result[i] = span[i].ToArray();
        }

        return result;
    }

    public static byte[][] ConvertExecutionRequests(in CExecutionRequests executionRequests)
    {
        var span = executionRequests.AsSpan();
        if (span.Length == 0)
        {
            return Array.Empty<byte[]>();
        }

        var result = new byte[span.Length][];

        for (int i = 0; i < span.Length; ++i)
        {
            result[i] = span[i].ToArray();
        }

        return result;
    }

    public static CVec_u8 ConvertLogsBloom(Bloom bloom)
    {
        var bytes = bloom.Bytes;
        var result = new CVec_u8((nuint)bytes.Length);

        bytes.CopyTo(result.AsMutableSpan());

        return result;
    }

    public static CPayloadValidationStatus ConvertPayloadValidationStatus(string status) =>
        status switch
        {
            PayloadStatus.Valid => CPayloadValidationStatus.Valid,
            PayloadStatus.Invalid => CPayloadValidationStatus.Invalid,
            PayloadStatus.Syncing => CPayloadValidationStatus.Syncing,
            PayloadStatus.Accepted => CPayloadValidationStatus.Accepted,
            _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown payload validation status."),
        };

    public static PayloadAttributes? ConvertPayloadAttributes(COption_CPayloadAttributesV1 attr)
    {
        if (!attr.is_something)
        {
            return null;
        }

        return new PayloadAttributes
        {
            Timestamp = attr.value.timestamp,
            PrevRandao = attr.value.prev_randao.ToHash256(),
            SuggestedFeeRecipient = attr.value.suggested_fee_recipient.ToAddress(),
        };
    }

    public static PayloadAttributes? ConvertPayloadAttributes(COption_CPayloadAttributesV2 attr)
    {
        if (!attr.is_something)
        {
            return null;
        }

        return new PayloadAttributes
        {
            Timestamp = attr.value.timestamp,
            PrevRandao = attr.value.prev_randao.ToHash256(),
            SuggestedFeeRecipient = attr.value.suggested_fee_recipient.ToAddress(),
            Withdrawals = WithdrawalsFromNative(attr.value.withdrawals),
        };
    }

    public static PayloadAttributes? ConvertPayloadAttributes(COption_CPayloadAttributesV3 attr)
    {
        if (!attr.is_something)
        {
            return null;
        }

        return new PayloadAttributes
        {
            Timestamp = attr.value.timestamp,
            PrevRandao = attr.value.prev_randao.ToHash256(),
            SuggestedFeeRecipient = attr.value.suggested_fee_recipient.ToAddress(),
            Withdrawals = WithdrawalsFromNative(attr.value.withdrawals),
            ParentBeaconBlockRoot = attr.value.parent_beacon_block_root.ToHash256(),
        };
    }
}