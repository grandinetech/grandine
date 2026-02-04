namespace Grandine.NethermindPlugin;

using Grandine.Native;

public sealed class GrandineInitializationException(uint errorCode, CGrandineString errorMessage) : Exception(errorMessage.ToString())
{
    public uint ErrorCode => errorCode;
}