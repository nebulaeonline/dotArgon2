using System.Reflection;
using System.Runtime.InteropServices;

namespace nebulae.dotArgon2
{
    internal static class Argon2Library
    {
        private static bool _isLoaded;

        internal static void Init()
        {
            if (_isLoaded)
                return;

            NativeLibrary.SetDllImportResolver(typeof(Argon2Library).Assembly, Resolve);

            _isLoaded = true;
        }

        private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            if (libraryName != "argon2")
                return IntPtr.Zero;

            var libName = GetPlatformLibraryName();
            // NuGet/publish may place the selected RID asset beside the assembly.
            // The runtime path below also supports project-reference builds.
            if (NativeLibrary.TryLoad(Path.GetFileName(libName), assembly, searchPath, out var handle))
                return handle;

            var assemblyDir = Path.GetDirectoryName(assembly.Location);
            if (string.IsNullOrEmpty(assemblyDir))
                assemblyDir = AppContext.BaseDirectory;
            var fullPath = Path.Combine(assemblyDir, libName);

            if (!File.Exists(fullPath))
                throw new DllNotFoundException($"Could not find native Argon2 library at {fullPath}");

            return NativeLibrary.Load(fullPath);
        }

        private static string GetPlatformLibraryName()
        {
            var architecture = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "x64",
                Architecture.Arm64 => "arm64",
                _ => throw new PlatformNotSupportedException($"Unsupported process architecture: {RuntimeInformation.ProcessArchitecture}")
            };

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return Path.Combine("runtimes", $"win-{architecture}", "native", "argon2.dll");

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return Path.Combine("runtimes", $"linux-{architecture}", "native", "libargon2.so");

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return Path.Combine("runtimes", $"osx-{architecture}", "native", "libargon2.dylib");
            }

            throw new PlatformNotSupportedException("Unsupported platform");
        }
    }
}
