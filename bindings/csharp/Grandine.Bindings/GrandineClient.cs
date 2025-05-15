using System.Runtime.InteropServices;
using System.Text;
using Grandine.Native;
using static Grandine.Native.NativeMethods;

namespace Grandine.Bindings;

public class GrandineClient
{
    public GrandineClient(CEmbedAdapter adapter)
    {
        Console.WriteLine("================================================================= init =================================================================");

        unsafe
        {
            grandine_set_execution_layer_adapter(adapter);
        }
    }

    public void Run(string[] args)
    {
        IntPtr convArgs = Marshal.AllocHGlobal(
            args.Length * IntPtr.Size
        );

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            byte[] strBytes = Encoding.ASCII.GetBytes(arg + '\0');
            IntPtr bytesPtr = Marshal.AllocHGlobal(strBytes.Length);
            Marshal.Copy(strBytes, 0, bytesPtr, strBytes.Length);
            Marshal.WriteIntPtr(
                convArgs,
                i * IntPtr.Size,
                bytesPtr
            );
        }

        unsafe
        {
            grandine_run((ulong)args.Length, (byte**)convArgs);
        }
    }
}
