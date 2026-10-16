# Building dotArgon2's native libraries

This is a maintainer guide for producing the prebuilt libraries shipped in the
NuGet package. Package users do not need a C compiler or these build steps.

Build this CMake project against the official Argon2 reference source. It selects
`src/opt.c` with AVX2 for x64 and `src/ref.c` for ARM64. ARM64 does not require
AVX2. Threading remains enabled on every platform. Windows uses the static MSVC
runtime, avoiding a separate Visual C++ runtime installation.

Use the same source snapshot on every build machine, including any local edits.
The supplied `argon2` directory has no Git metadata; retain an archive and its
SHA256 alongside the release records. For a Git checkout, record the upstream
commit and `git status --short`. Each build writes compiler, RID, implementation,
and implementation hash to `native-build.txt`; that hash is not a hash of the
entire upstream tree. Retain the upstream license with distributed binaries.

Commands run from the dotArgon2 repository root (`dotnet` in this workspace).
The default source location is `../argon2`. Override it using
`-DARGON2_SOURCE_DIR=/absolute/path/to/argon2` when needed. Both trees must be
present on each build machine. Install CMake 3.20 or later and the platform's C
toolchain. Keep a separate build directory for each RID. The build checks the
compiler's target architecture against the RID.

## Windows x64 and ARM64

Install Visual Studio 2022's C++ tools and Windows SDK. Also install the MSVC
ARM64 tools for ARM64 builds. In PowerShell:

```powershell
cmake -S native -B artifacts/native-win-x64 -G "Visual Studio 17 2022" -A x64 -DDOTARGON2_RID=win-x64
cmake --build artifacts/native-win-x64 --config Release
ctest --test-dir artifacts/native-win-x64 -C Release --output-on-failure

cmake -S native -B artifacts/native-win-arm64 -G "Visual Studio 17 2022" -A ARM64 -DDOTARGON2_RID=win-arm64
cmake --build artifacts/native-win-arm64 --config Release
```

MSVC can cross-compile ARM64 on x64 Windows. Copy the ARM64 Release smoke
executable and DLL together to Windows ARM64 and run `argon2-smoke.exe` there.
On an ARM64 build machine, run CTest as above with the ARM64 build directory.
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

From the dotArgon2 repository root on the ARM64 VM:

```sh
cmake -S native -B artifacts/native-linux-arm64 \
  -DDOTARGON2_RID=linux-arm64 -DCMAKE_BUILD_TYPE=Release
cmake --build artifacts/native-linux-arm64 -- -j2
ctest --test-dir artifacts/native-linux-arm64 --output-on-failure
file artifacts/native-linux-arm64/package/runtimes/linux-arm64/native/libargon2.so
readelf -d artifacts/native-linux-arm64/package/runtimes/linux-arm64/native/libargon2.so
readelf --version-info artifacts/native-linux-arm64/package/runtimes/linux-arm64/native/libargon2.so
```

From the dotArgon2 repository root on the x64 VM:

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
```

Build x64 on the same Mac, or on an Intel Mac, from the repository root:

```sh
cmake -S native -B artifacts/native-osx-x64 \
  -DDOTARGON2_RID=osx-x64 -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 -DCMAKE_BUILD_TYPE=Release
cmake --build artifacts/native-osx-x64 -- -j2
file artifacts/native-osx-x64/package/runtimes/osx-x64/native/libargon2.dylib
otool -L artifacts/native-osx-x64/package/runtimes/osx-x64/native/libargon2.dylib
```

Run `ctest --test-dir artifacts/native-osx-x64 --output-on-failure` when building
on an AVX2-capable Intel Mac. When cross-compiling on Apple Silicon, copy the x64
smoke executable and dylib together to an AVX2-capable Intel Mac and run
`./argon2-smoke` there. Do not assume Rosetta can run the AVX2 test.
These commands produce separate architecture libraries; a universal
dylib is not required. The deployment target does not set .NET's OS requirements.

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

The smoke executable links to the built shared library and exercises raw and
encoded hashing, successful verification, and wrong-password rejection for all
three variants with two lanes, plus an upstream Argon2i known-answer vector.
It must pass on each target before release.

With all six native files collected, use the .NET 8 SDK:

```sh
dotnet test dotArgon2Tests/dotArgon2Tests.csproj -c Release
dotnet pack dotArgon2/dotArgon2.csproj -c Release -o artifacts/packages
```

Inspect the NuGet ZIP archive and confirm it contains exactly one native library
at each of the six `runtimes/<rid>/native/` paths. Test a consuming application on
each platform as well as the project tests. The managed loader selects by process
architecture on all three operating systems and rejects architectures other than
x64 and ARM64.

## Verification status in this workspace

Windows x64 builds and passes the native smoke test and the 21 managed tests.
Windows ARM64 cross-compiles and its DLL has been collected into the runtime
directory; execution still requires Windows ARM64. Linux ARM64 has not yet been
built or collected. The existing Linux x64 and both macOS binaries are retained;
the Linux and macOS commands above still require validation on those systems.
Do not release the six-RID package until the Linux ARM64 binary is collected and
all target checks pass.

