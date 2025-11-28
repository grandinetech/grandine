namespace Grandine.NethermindPlugin;

using Grandine.Native;

public sealed class GrandineInitializationException(uint errorCode, CErrorMessage errorMessage) : Exception(errorMessage.ToString())
{
    public uint ErrorCode => errorCode;
}