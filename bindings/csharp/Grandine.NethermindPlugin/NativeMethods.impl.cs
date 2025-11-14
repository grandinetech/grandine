using Grandine.NethermindPlugin;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Int256;
using Nethermind.Merge.Plugin.Data;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Grandine.Native;

public unsafe partial struct CPayloadStatusV1
{
    public static CPayloadStatusV1 From(PayloadStatusV1 status) => new() 
    { 
        status = GrandineUtils.ConvertPayloadValidationStatus(status.Status), 
        latest_valid_hash = CH256.FromOptionalHash256(status.LatestValidHash) 
    };
}

public unsafe partial struct CWithdrawalV1
{
    public readonly Withdrawal ToWithdrawal() => new Withdrawal
    {
        Index = index,
        ValidatorIndex = validator_index,
        Address = address.ToAddress(),
        AmountInGwei = amount,
    };
}

public unsafe partial struct CForkChoiceStateV1
{
    public readonly ForkchoiceStateV1 ToForkchoiceStateV1() => new ForkchoiceStateV1(
        head_block_hash.ToHash256(),
        finalized_block_hash.ToHash256(),
        safe_block_hash.ToHash256()
    );
}

public unsafe partial struct CForkChoiceUpdatedResponse
{
    public static CForkChoiceUpdatedResponse From(ForkchoiceUpdatedV1Result result) => new CForkChoiceUpdatedResponse
    {
        payload_status = CPayloadStatusV1.From(result.PayloadStatus),
        payload_id = CH64.FromOptinalHexString(result.PayloadId),
    };
}

public unsafe partial struct CTransaction
{
    public readonly ReadOnlySpan<byte> Bytes()
    {
        return Item1.AsSpan();
    }
}

public unsafe partial struct CExecutionRequests
{
    public readonly ReadOnlySpan<CVec<byte>> AsSpan()
    {
        return Item1.AsSpan();
    }
}

public unsafe partial struct CH256
{
    public static CH256 From(Hash256 hash) {
        var output = new CH256{};

        fixed (byte* sourcePtr = hash.Bytes) 
        { 
            Buffer.MemoryCopy(sourcePtr, output.Item1, 32, 32); 
        }

        return output;
    }

    public unsafe Hash256 ToHash256()
    {
        return new Hash256(AsSpan());
    }

    public unsafe UInt256 ToUInt256()
    {
        return new UInt256(AsSpan(), true);
    }

    public unsafe readonly ReadOnlySpan<byte> AsSpan()
    {
        fixed (byte* data = Item1)
        {
            return new ReadOnlySpan<byte>(data, 32);
        }
    }

    public unsafe readonly byte[] ToArray() => AsSpan().ToArray();

    public static CH256 FromHash256(Hash256 value)
    {
        var output = new CH256 { };
        fixed (byte* sourcePtr = value.Bytes)
        {
            Buffer.MemoryCopy(sourcePtr, output.Item1, 32, 32);
        }
        return output;
    }

    public static COption<CH256> FromOptionalHash256(Hash256? value)
    {
        if (value == null)
        {
            return COption<CH256>.None;
        }

        return COption<CH256>.Some(FromHash256(value));
    }
}

public unsafe partial struct CH160
{
    public static CH160 From(Address address)
    {
        var output = new CH160 {};

        fixed (byte* sourcePtr = address.Bytes) { Buffer.MemoryCopy(sourcePtr, output.Item1, 20, 20); }
        
        return output;
    }

    public unsafe readonly Address ToAddress()
    {
        return new Address(AsSpan());
    }

    public unsafe readonly ReadOnlySpan<byte> AsSpan()
    {
        fixed (byte* data = Item1)
        {
            return new ReadOnlySpan<byte>(data, 20);
        }
    }
}

public unsafe partial struct CH64
{
    public unsafe readonly ReadOnlySpan<byte> AsSpan()
    {
        fixed (byte* data = Item1)
        {
            return new ReadOnlySpan<byte>(data, 8);
        }
    }

    public unsafe readonly byte[] ToArray() => AsSpan().ToArray();

    public static CH64 FromHexString(String value)
    {
        var raw = Convert.FromHexString(value);

        if (raw.Length != 8) {
            throw new ArgumentException("Hex payloadmust decode to exactly 8 bytes.");
        }

        var output = new CH64 {};

        fixed (byte* sourcePtr = raw)
        {
            Buffer.MemoryCopy(sourcePtr, output.Item1, 8, 8);
        }

        return output;
    }

    public static COption<CH64> FromOptinalHexString(String? value)
    {
        if (value == null)
        {
            return COption<CH64>.None;
        }

        return COption<CH64>.Some(FromHexString(value));
    }
}

public unsafe partial struct CResult<T>
{
    public static CResult<T> Fail(int errorCode) => new() { error = (ulong)errorCode };

    public static CResult<T> Success(T data) => new() { error = 0, value = data };
}

public unsafe partial struct COption<T>
{
    public static COption<T> None => new() { is_something = false };

    public static COption<T> Some(T value) => new() { is_something = true, value = value };
}

public unsafe partial struct CVec<T> where T : unmanaged
{
    public CVec(nuint length)
    {
        IntPtr pointer;
        unsafe { pointer = (IntPtr)NativeMethods.grandine_alloc(length * (nuint)Marshal.SizeOf<T>()); }

        data = (T*)pointer.ToPointer();
        data_len = length;
    }

    public readonly ReadOnlySpan<T> AsSpan()
    {
        if (sizeof(nuint) > sizeof(int) && data_len > int.MaxValue)
            ThrowLengthTooLarge();

        return new ReadOnlySpan<T>(data, checked((int)data_len));
    }

    public readonly Span<T> AsMutableSpan()
    {
        if (sizeof(nuint) > sizeof(int) && data_len > int.MaxValue)
            ThrowLengthTooLarge();

        return new Span<T>(data, checked((int)data_len));
    }

    public readonly T[] ToArray()
    {
        var span = AsSpan();
        if (span.Length == 0)
            return Array.Empty<T>();

        var arr = new T[span.Length];
        span.CopyTo(arr);
        return arr;
    }

    public readonly List<T> ToList()
    {
        var span = AsSpan();
        var list = new List<T>(span.Length);
        list.AddRange(span);
        return list;
    }

    private static void ThrowLengthTooLarge() =>
        throw new OverflowException("data_len exceeds Int32.MaxValue");
}