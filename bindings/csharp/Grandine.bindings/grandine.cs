using static Grandine.Native.NativeMethods;

namespace Grandine;

public sealed unsafe class Grandine
{
    public Grandine()
    {
    }

    public void Run() {
        grandine_run();
    }
}
