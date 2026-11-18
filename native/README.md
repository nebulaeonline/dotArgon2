# Building dotArgon2's native libraries

The NuGet package includes prebuilt native libraries for all six supported RIDs.
These instructions are for anyone who prefers to inspect the source and build
their own libraries, and for maintainers preparing a release. Native compilation
is optional when using the package.

Build this CMake project against the included Argon2 reference source. It selects
`src/opt.c` with AVX2 for x64 and `src/ref.c` for ARM64. ARM64 does not require
AVX2. Threading remains enabled on every platform. Windows uses the static MSVC
runtime, avoiding a separate Visual C++ runtime installation.

## Source and prerequisites

Use the repository's existing `argon2` source tree; it stays outside the native
build directory. The instructions assume this relative layout:

```text
checkout/
  argon2/
    include/
    src/
    LICENSE
  dotnet/
    native/
    dotArgon2/
    dotArgon2Tests/
    global.json
```

Run all platform commands below from the directory containing `native`,
`dotArgon2`, and `dotArgon2Tests` (`dotnet` in the layout above). Thus, the default
source location is `../argon2`, resolved relative to the CMake project rather
than the current shell directory. No source duplication is needed.

The source includes dotArgon2's native verification buffer-clearing changes.
Review that source tree when assessing the bundled implementation; a stock
upstream checkout may not contain the same changes. The
[build manifest](builds/2026-11-17.json) records the source hashes used for the
bundled rebuild. Retain the Argon2 `LICENSE` with redistributions.

Use the same source snapshot and local edits on every build machine. To use an
alternative source tree, add `-DARGON2_SOURCE_DIR=/path/to/argon2` to the configure
command. On Windows the same option accepts a quoted Windows path. If reusing a
build directory after moving the checkout or source tree, set this option again
to replace its cached source path.

Install CMake 3.20 or later and the platform's C toolchain. Keep a separate build
directory for each RID. The build checks the compiler's target architecture
against the RID. CMake writes a `native-build.txt` recording the compiler, RID,
implementation, and implementation hash. Keep a full source snapshot or all
source hashes as well; the implementation hash alone does not identify every
input. Different compilers and build environments can produce different binary
hashes even from identical source.

## Windows x64 and ARM64

Install Visual Studio 2022's C++ tools and Windows SDK. Also install the MSVC
ARM64 tools for ARM64 builds. Install CMake separately if it is not already
available on PATH. In PowerShell, from the managed build directory described above:

```powershell
cmake -S native -B artifacts/native-win-x64 -G "Visual Studio 17 2022" -A x64 -DDOTARGON2_RID=win-x64
cmake --build artifacts/native-win-x64 --config Release
ctest --test-dir artifacts/native-win-x64 -C Release --output-on-failure

cmake -S native -B artifacts/native-win-arm64 -G "Visual Studio 17 2022" -A ARM64 -DDOTARGON2_RID=win-arm64
cmake --build artifacts/native-win-arm64 --config Release
```

MSVC can cross-compile ARM64 on x64 Windows. Copy the ARM64 Release smoke
executable and DLL together to Windows ARM64 and run `argon2-smoke.exe` there.
On an ARM64 build machine, run:

```powershell
ctest --test-dir artifacts/native-win-arm64 -C Release --output-on-failure
```

An x64 Windows host cannot execute an ARM64 smoke test.

## Ubuntu 18.04 VMs: ARM64 and x64

Build `linux-arm64` on the Ubuntu 18.04 ARM64 VM and `linux-x64` on the
Ubuntu 18.04 x64 VM. These are native builds; no cross-compiler is needed.
On both VMs install the native tools, retaining Ubuntu 18.04's GCC 7 and glibc:

```sh
sudo apt update
sudo apt install build-essential git wget ca-certificates file binutils
gcc -dumpmachine
```

Ubuntu 18.04's bundled CMake 3.10 is too old for this project. Install Kitware's
standalone CMake 3.28.6 under your home directory on each VM. This leaves the
system compiler, glibc, and CMake unchanged. On the ARM64 VM:

```sh
mkdir -p "$HOME/.local/opt"
wget -O "$HOME/.local/opt/cmake-3.28.6-linux-aarch64.tar.gz" \
  https://github.com/Kitware/CMake/releases/download/v3.28.6/cmake-3.28.6-linux-aarch64.tar.gz
tar -xzf "$HOME/.local/opt/cmake-3.28.6-linux-aarch64.tar.gz" -C "$HOME/.local/opt"
export PATH="$HOME/.local/opt/cmake-3.28.6-linux-aarch64/bin:$PATH"
hash -r
cmake --version
```

On the x64 VM:

```sh
mkdir -p "$HOME/.local/opt"
wget -O "$HOME/.local/opt/cmake-3.28.6-linux-x86_64.tar.gz" \
  https://github.com/Kitware/CMake/releases/download/v3.28.6/cmake-3.28.6-linux-x86_64.tar.gz
tar -xzf "$HOME/.local/opt/cmake-3.28.6-linux-x86_64.tar.gz" -C "$HOME/.local/opt"
export PATH="$HOME/.local/opt/cmake-3.28.6-linux-x86_64/bin:$PATH"
hash -r
cmake --version
```

Repeat the PATH export in each new shell, or add it to your shell configuration.
Official archives and checksums are on the
[Kitware CMake 3.28.6 release](https://github.com/Kitware/CMake/releases/tag/v3.28.6).

From the managed build directory on the ARM64 VM:

```sh
cmake -S native -B artifacts/native-linux-arm64 \
  -DDOTARGON2_RID=linux-arm64 -DCMAKE_BUILD_TYPE=Release
cmake --build artifacts/native-linux-arm64 -- -j2
ctest --test-dir artifacts/native-linux-arm64 --output-on-failure
file artifacts/native-linux-arm64/package/runtimes/linux-arm64/native/libargon2.so
readelf -d artifacts/native-linux-arm64/package/runtimes/linux-arm64/native/libargon2.so
readelf --version-info artifacts/native-linux-arm64/package/runtimes/linux-arm64/native/libargon2.so
```

From the managed build directory on the x64 VM:

```sh
cmake -S native -B artifacts/native-linux-x64 \
  -DDOTARGON2_RID=linux-x64 -DCMAKE_BUILD_TYPE=Release
cmake --build artifacts/native-linux-x64 -- -j2
ctest --test-dir artifacts/native-linux-x64 --output-on-failure
file artifacts/native-linux-x64/package/runtimes/linux-x64/native/libargon2.so
readelf -d artifacts/native-linux-x64/package/runtimes/linux-x64/native/libargon2.so
readelf --version-info artifacts/native-linux-x64/package/runtimes/linux-x64/native/libargon2.so
```

Expose AVX2 to the x64 VM; the x64 library and smoke test require it. Building
on Ubuntu 18.04 preserves an older glibc baseline, but retain the actual GLIBC
requirements reported by `readelf` for each binary as part of release validation.
These RIDs target glibc Linux; musl builds would need separate RIDs. Avoid
`-march=native` and `-mcpu=native` in distributable libraries.

## macOS ARM64 and Intel

Install Xcode Command Line Tools (`xcode-select --install`) and CMake. Both
architectures below explicitly target macOS 11.0 and later. On an Apple Silicon
Mac, build ARM64 with:

```sh
cmake -S native -B artifacts/native-osx-arm64 \
  -DDOTARGON2_RID=osx-arm64 -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 -DCMAKE_BUILD_TYPE=Release
cmake --build artifacts/native-osx-arm64 -- -j2
ctest --test-dir artifacts/native-osx-arm64 --output-on-failure
file artifacts/native-osx-arm64/package/runtimes/osx-arm64/native/libargon2.dylib
otool -L artifacts/native-osx-arm64/package/runtimes/osx-arm64/native/libargon2.dylib
otool -l artifacts/native-osx-arm64/package/runtimes/osx-arm64/native/libargon2.dylib
```

Build x64 on the same Mac, or on an Intel Mac, from the managed build directory:

```sh
cmake -S native -B artifacts/native-osx-x64 \
  -DDOTARGON2_RID=osx-x64 -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 -DCMAKE_BUILD_TYPE=Release
cmake --build artifacts/native-osx-x64 -- -j2
file artifacts/native-osx-x64/package/runtimes/osx-x64/native/libargon2.dylib
otool -L artifacts/native-osx-x64/package/runtimes/osx-x64/native/libargon2.dylib
otool -l artifacts/native-osx-x64/package/runtimes/osx-x64/native/libargon2.dylib
```

Run `ctest --test-dir artifacts/native-osx-x64 --output-on-failure` when building
on an AVX2-capable Intel Mac. When cross-compiling on Apple Silicon, copy the x64
smoke executable and dylib together to an AVX2-capable Intel Mac and run
`./argon2-smoke` there. Do not assume Rosetta can run the AVX2 test.
These commands produce separate architecture libraries; a universal
dylib is not required. In `otool -l` output, check that `LC_BUILD_VERSION` reports
`minos 11.0` (or that `LC_VERSION_MIN_MACOSX` reports version 11.0 with an older
toolchain). The deployment target does not set .NET's OS requirements.

## Collecting and packaging

Each build stages one library under:

```text
artifacts/native-<rid>/package/runtimes/<rid>/native/
```

| RID | Library | Implementation |
| --- | --- | --- |
| `win-x64` | `argon2.dll` | AVX2 |
| `win-arm64` | `argon2.dll` | Reference |
| `linux-x64` | `libargon2.so` | AVX2 |
| `linux-arm64` | `libargon2.so` | Reference |
| `osx-x64` | `libargon2.dylib` | AVX2 |
| `osx-arm64` | `libargon2.dylib` | Reference |

After testing, copy each staged library into the matching
`dotArgon2/runtimes/<rid>/native/` directory in the packaging checkout. Retain
`native-build.txt` and the full upstream source record separately. Builds stage
outputs without automatically replacing existing bundled binaries.

For example, after testing a Linux ARM64 build:

```sh
cp artifacts/native-linux-arm64/package/runtimes/linux-arm64/native/libargon2.so \
  dotArgon2/runtimes/linux-arm64/native/libargon2.so
```

On Windows ARM64, the equivalent PowerShell command is:

```powershell
Copy-Item artifacts/native-win-arm64/package/runtimes/win-arm64/native/argon2.dll `
  dotArgon2/runtimes/win-arm64/native/argon2.dll
```

Use the matching paths from the table for the other RIDs. Replacing one library
changes only that runtime asset; collect all six builds to make a package entirely
from your own native binaries. Keep the Argon2 license with redistributions.

The smoke executable links to the built shared library and exercises raw and
encoded hashing, successful verification, and wrong-password rejection for all
three variants with two lanes, plus an upstream Argon2i known-answer vector.
It must pass on each target before release.

With your native files collected, use the .NET 8 SDK selected by `global.json`:

```sh
dotnet test dotArgon2Tests/dotArgon2Tests.csproj -c Release
dotnet pack dotArgon2/dotArgon2.csproj -c Release -o artifacts/packages
```

Inspect the NuGet ZIP archive and confirm it contains exactly one native library
at each of the six `runtimes/<rid>/native/` paths. Test a consuming application on
each platform as well as the project tests. The managed loader selects by process
architecture on all three operating systems and rejects architectures other than
x64 and ARM64.

## Verified rebuild: November 17, 2026

All six bundled libraries were rebuilt from one source snapshot and collected
after passing the native smoke test and all 31 managed tests per RID (186 managed
test passes). The [build manifest](builds/2026-11-17.json) records source hashes,
binary hashes, compilers, target architectures, and test counts. Use its
`argon2/` source-file hashes to check the native source snapshot.

Both Linux libraries were built and tested on Ubuntu 18.04.6 VMs with GCC 7.5.0.
Their highest imported GLIBC version is 2.25. Windows x64 and ARM64 libraries
were built and tested on matching-architecture systems.

Both macOS libraries have a verified Mach-O minimum OS of 11.0. ARM64 execution
was native on Apple M1; x64 execution used Rosetta on the same Mac running macOS
27.2. These results do not constitute execution testing on macOS 11.0 or Intel
hardware. The .NET 8 test assembly used the installed .NET 8 or .NET 10 runtime,
with major-version roll-forward enabled where .NET 8 was unavailable.

The exact Ubuntu 18.04-built Linux binaries also passed the native smoke test and
all 31 managed tests on each Ubuntu 26.04.1 VM, bringing managed validation to
248 passes. Ubuntu 26 x64 used its existing private SDK 10.0.403/runtime 10.0.14;
ARM64 used the installed SDK 10.0.115/runtime 10.0.15. The collected NuGet package
was checked against all six tested binary hashes, and a published Windows x64
NuGet consumer passed UTF-8 hash/verify round-trips for all three variants.

