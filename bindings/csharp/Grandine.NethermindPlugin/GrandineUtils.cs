using Grandine.Native;
using Nethermind.Core;
using Nethermind.Consensus.Producers;
using Nethermind.Merge.Plugin.Data;
using System;

namespace Grandine.NethermindPlugin;

public static class GrandineUtils
{

    public static unsafe byte[][] ConvertTransactions(in CVec<CTransaction> transactions)
    {
        var span = transactions.AsSpan();
        if (span.Length == 0)
            return Array.Empty<byte[]>();

        var result = new byte[span.Length][];

        for (int i = 0; i < span.Length; ++i)
        {
            result[i] = span[i].Bytes().ToArray();
        }

        return result;
    }

    public static Withdrawal[] ConvertWithdrawals(in CVec<CWithdrawalV1> withdrawals)
    {
        var span = withdrawals.AsSpan();
        if (span.Length == 0)
            return Array.Empty<Withdrawal>();

        var result = new Withdrawal[span.Length];
        
        for (int i = 0; i < span.Length; ++i)
        {
            result[i] = span[i].ToWithdrawal();
        }

        return result;
    }

    public static byte[][] ConvertVersionedHashes(in CVec<CH256> versionedHashes)
    {
        var span = versionedHashes.AsSpan();
        if (span.Length == 0)
            return Array.Empty<byte[]>();
        
        var result = new byte[span.Length][];

        for (int i = 0; i < span.Length; ++i)
        {
            result[i] = span[i].ToArray();
        }

        return result;
    }

    public static unsafe byte[][] ConvertExecutionRequests(in CExecutionRequests executionRequests)
    {
        var span = executionRequests.AsSpan();
        if (span.Length == 0)
            return Array.Empty<byte[]>();

        var result = new byte[span.Length][];

        for (int i = 0; i < span.Length; ++i)
        {
            result[i] = span[i].ToArray();
        }

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

    public static PayloadAttributes? ConvertPayloadAttributes(COption<CPayloadAttributesV1> attr) 
    {
        if (!attr.is_something) {
            return null;
        }

        return new PayloadAttributes
            {
                Timestamp = attr.value.timestamp,
                PrevRandao = attr.value.prev_randao.ToHash256(),
                SuggestedFeeRecipient = attr.value.suggested_fee_recipient.ToAddress(),
            };
    }

    public static PayloadAttributes? ConvertPayloadAttributes(COption<CPayloadAttributesV2> attr)
    {
        if (!attr.is_something) {
            return null;
        }

        return new PayloadAttributes
            {
                Timestamp = attr.value.timestamp,
                PrevRandao = attr.value.prev_randao.ToHash256(),
                SuggestedFeeRecipient = attr.value.suggested_fee_recipient.ToAddress(),
                Withdrawals = ConvertWithdrawals(attr.value.withdrawals),
            };
    }

    public static PayloadAttributes? ConvertPayloadAttributes(COption<CPayloadAttributesV3> attr)
    {
        if (!attr.is_something) {
            return null;
        }

        return new PayloadAttributes
            {
                Timestamp = attr.value.timestamp,
                PrevRandao = attr.value.prev_randao.ToHash256(),
                SuggestedFeeRecipient = attr.value.suggested_fee_recipient.ToAddress(),
                Withdrawals = ConvertWithdrawals(attr.value.withdrawals),
                ParentBeaconBlockRoot = attr.value.parent_beacon_block_root.ToHash256(),
            };
    }
}
