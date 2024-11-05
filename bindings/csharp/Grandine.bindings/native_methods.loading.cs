using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace Grandine.Native;

internal static unsafe partial class NativeMethods
{
    // When the static methods are called, .NET will look for the library in some
    // conventional locations. If it cannot find it, it will then trigger 
    // "ResolvingUnmanagedDll" event.
    // The below just says that LoadNativeLibrary will handle this event.
    //
    // The first parameter to DLLImport is the path that gets passed to the event handler.
    static NativeMethods() => AssemblyLoadContext.Default.ResolvingUnmanagedDll += LoadNativeLibrary;

    internal static IntPtr LoadNativeLibrary(Assembly _, string path)
    {
        // This checks whether the requested library is the one we're interested in
        // ie this class can only be used to load a dynamic library with the name `__DllName`
        if (!path.Equals(__DllName, StringComparison.OrdinalIgnoreCase))
        {
            return IntPtr.Zero;
        }

        string target =
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && RuntimeInformation.ProcessArchitecture == Architecture.X64 ? "x86_64-unknown-linux-gnu" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "aarch64-unknown-linux-gnu" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) && RuntimeInformation.ProcessArchitecture == Architecture.X64 ? "x86_64-apple-darwin" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) && RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "aarch64-apple-darwin" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && RuntimeInformation.ProcessArchitecture == Architecture.X64 ? "x86_64-pc-windows-gnu" :
            // Windows on ARM doesn't seem to be massively supported in nethermind. Check the secp256k1 bindings for example.
            // We can add support for it later if needed.
            // RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "aarch64-pc-windows-msvc" :
            "";

        string extension =
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "so" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "dylib" :
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "dll" : "";

        // All platforms should have an extension, an unknown extension is unexpected and an error
        if (extension == "")
        {
            return IntPtr.Zero;
        }

        // Windows doesn't have a lib prefix
        string prefix =
           RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "lib" : "";

        string baseDirectory = AppContext.BaseDirectory;

        string libraryPath = Path.Combine(baseDirectory, $"runtimes/{target}/{prefix}{path}.{extension}");

        if (File.Exists(libraryPath))
        {
            return NativeLibrary.Load(libraryPath);
        }

        return IntPtr.Zero;
    }
}
