
using static Grandine.Native.NativeMethods;
using Grandine.Native;
using Nethermind.Core.Crypto;
using Nethermind.Facade.Eth;
using System;

namespace Grandine.Bindings;

public static class GrandineUtils {

    public unsafe static CH256 convertHash256(Hash256 hash) {
        var result = new CH256();

        if (hash == null) {
            return result;
        }

        if (hash.Bytes.Length != 32)
        {
            throw new Exception("Hash256 must be exactly 32 bytes long");
        }
        fixed (byte* sourcePtr = hash.Bytes)
        {
            Buffer.MemoryCopy(sourcePtr, result.Item1, 32, 32);
        }

        return result;
    }
}