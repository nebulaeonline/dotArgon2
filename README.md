# nebulae.dotArgon2

A minimal, fast, cross-platform Argon2 wrapper for .NET applications.

This library provides access to native **Argon2id**, **Argon2i**, and **Argon2d** password hashing using optimized AVX2-enabled builds of the official reference implementation.

---

## Features

- Supports **Argon2id**, **Argon2i**, and **Argon2d**
- Exposes both raw byte output and encoded string output
- Full control over all parameters: memory cost, time cost, parallelism (nothing is hidden away, so you can follow OWASP recommendations)
- Cross-platform support: **Windows**, **Linux**, **macOS**
- Ships with native binaries: `.dll`, `.so`, `.dylib`
- Built against the **SIMD-optimized** version of the Argon2 reference implementation
- Requires **AVX2** instruction set (x86_64 only)

---

## Requirements

- .NET 8 or later
- AVX2-capable CPU (required for the optimized native library)
- Windows x64, Linux x64, or macOS x64/arm64

> Note: On macOS, the library ships as a universal `dylib` supporting both Intel and Apple Silicon. The arm64 build uses the reference (non-AVX2) implementation.

---

## Usage

For general usage, it is recommended to use the encoded string output for password hashing. If you do so you can use the built-in verification functions. Otherwise, you must re-compute the hash using the same original settings and compare the raw hashes yourself. 

*Important:* salts are required to be at least *8 bytes* in length; this is a requirement of the underlying Argon2 library.

```csharp

using nebulae.dotArgon2;

// Ensure native library is loaded
Argon2.Init();

// Hash a password using Argon2id
byte[] rawHash = Argon2.Argon2idHashRaw(2, 65536, 2, passwordBytes, saltBytes, 32);

// Get an encoded string instead
string encoded = Argon2.Argon2idHashEncoded(2, 65536, 2, passwordBytes, saltBytes);

// Verify
bool isValid = Argon2.Argon2idVerify(encoded, passwordBytes);

```

---

## Installation

Coming soon as a NuGet package. For now, clone and build from source:

```bash

git clone https://github.com/nebulaeonline/dotArgon2.git
cd dotArgon2
dotnet build

```

---

## License

MIT

## Roadmap

- Secure memory clearing for sensitive hash buffers
- Span<T> and Memory<T> overloads for zero-allocation scenarios