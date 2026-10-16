# nebulae.dotArgon2

A minimal, fast, cross-platform Argon2 wrapper for .NET applications.

This library provides access to native **Argon2id**, **Argon2i**, and **Argon2d** password hashing using the official reference implementation, with AVX2 builds for x64 and portable reference builds for ARM64.

[![NuGet](https://img.shields.io/nuget/v/nebulae.dotArgon2.svg)](https://www.nuget.org/packages/nebulae.dotArgon2)

---

## Features

- Supports **Argon2id**, **Argon2i**, and **Argon2d**
- Exposes both raw byte output and encoded string output
- Full control over all parameters: memory cost, time cost, parallelism (nothing is hidden away, so you can follow OWASP recommendations)
- Cross-platform support: **Windows**, **Linux**, **macOS**
- Ships with native binaries: `.dll`, `.so`, `.dylib` for both x64 and ARM64
- AVX2-optimized native code on x64; portable reference code on ARM64

---

## Requirements

- .NET 8 or later
- AVX2-capable CPU for x64 processes
- Windows, Linux, or macOS with an x64 or ARM64 processor

The NuGet package includes prebuilt native libraries for `win-x64`, `win-arm64`,
`linux-x64`, `linux-arm64`, `osx-x64`, and `osx-arm64`. No native compilation is
required to use the package. Library selection follows the process architecture,
so an x64 process on an ARM64 machine uses the x64 library.

---

## Usage

For general usage, it is recommended to use the encoded string output for password hashing. If you do so you can use the built-in verification functions. Otherwise, you must re-compute the hash using the same original settings and compare the raw hashes yourself. 

*Important:* salts are required to be at least *8 bytes* in length; this is a requirement of the underlying Argon2 library.

```csharp

using nebulae.dotArgon2;

// Set inputs
byte[] password = Encoding.UTF8.GetBytes("correct horse battery staple");
byte[] salt = Encoding.UTF8.GetBytes("sodiumchloride");

// Choose the variant
var algorithm = Argon2.Argon2Algorithm.Argon2id;

// Hash to a raw 32-byte buffer
byte[] rawHash = Argon2.Argon2HashRaw(
    algorithm,
    timeCost: 2,
    memCost: 65536,
    parallelism: 2,
    password,
    salt,
    hashLength: 32);

// Get a base64-compatible encoded string
string encoded = Argon2.Argon2HashEncodedToString(
    algorithm,
    timeCost: 2,
    memCost: 65536,
    parallelism: 2,
    password,
    salt);

// Verify the encoded hash using the original password
bool isValid = Argon2.VerifyEncoded(algorithm, encoded, password);

```

---

## Installation

You can install the package via NuGet:

```bash

$ dotnet add package nebulae.dotArgon2

```

Or via git:

```bash

$ git clone https://github.com/nebulaeonline/dotArgon2.git
$ cd dotArgon2
$ dotnet build

```

---

## License

MIT

## Sensitive memory

Library-owned temporary hash buffers are cleared with
`CryptographicOperations.ZeroMemory`, including when conversion or hashing fails.
Encoded hashing uses a byte buffer that is cleared after copying the result.
Returned arrays and caller-provided password, salt, and destination buffers remain
caller-owned; clear sensitive byte buffers with `CryptographicOperations.ZeroMemory`
when finished. Returned strings are immutable and cannot be reliably wiped; prefer
byte arrays or span APIs when explicit clearing is required.

The supplied native source clears Argon2 working memory and temporary verification
buffers before freeing them.
