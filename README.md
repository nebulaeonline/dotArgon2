# nebulae.dotArgon2

A minimal, fast, cross-platform Argon2 wrapper for .NET applications.

This library provides access to native **Argon2id**, **Argon2i**, and **Argon2d** password hashing using the official reference implementation, with AVX2 builds for x64 and portable reference builds for ARM64.

[![NuGet](https://img.shields.io/nuget/v/nebulae.dotArgon2.svg)](https://www.nuget.org/packages/nebulae.dotArgon2)

---

## Features

- Supports **Argon2id**, **Argon2i**, and **Argon2d**
- Exposes raw hashes and encoded PHC records as bytes, spans, or strings
- Verifies encoded hashes directly from `ReadOnlySpan<byte>` without creating managed strings
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

For password hashing with explicit memory clearing, keep passwords and encoded
hashes in writable byte buffers and use the UTF-8 span verification overload:

```csharp
bool VerifyEncoded(
    Argon2Algorithm algorithm,
    ReadOnlySpan<byte> encoded,
    ReadOnlySpan<byte> password);
```

`Argon2Algorithm` is nested under `Argon2`. The encoded
value is a complete PHC record containing the algorithm, version, cost parameters,
salt, and Base64 hash. Pass the full record, rather than just its Base64 hash.
Neither hashing nor verification requires conversion to a managed string.

*Important:* salts are required to be at least *8 bytes* in length; this is a requirement of the underlying Argon2 library.

### Hash and verify with spans

`TryArgon2HashEncodedFast` writes UTF-8 bytes into caller-owned storage.
`VerifyEncoded` accepts the written slice directly:

```csharp
using nebulae.dotArgon2;
using System.Security.Cryptography;

// Demonstration only: obtain password bytes directly from your input source in production.
ReadOnlySpan<byte> sample = "correct horse battery staple"u8;
Span<byte> password = stackalloc byte[sample.Length];
sample.CopyTo(password);
Span<byte> salt = stackalloc byte[16];
Span<byte> destination = stackalloc byte[Argon2.GetEncodedSizeEstimate(salt.Length)];

try
{
    RandomNumberGenerator.Fill(salt);
    var algorithm = Argon2.Argon2Algorithm.Argon2id;

    if (!Argon2.TryArgon2HashEncodedFast(
        algorithm, timeCost: 2, memCost: 65536, parallelism: 2,
        password, salt, destination, out int bytesWritten))
    {
        throw new InvalidOperationException("Argon2 hashing failed.");
    }

    ReadOnlySpan<byte> encoded = destination[..bytesWritten];
    bool isValid = Argon2.VerifyEncoded(algorithm, encoded, password);
}
finally
{
    CryptographicOperations.ZeroMemory(password);
    CryptographicOperations.ZeroMemory(salt);
    CryptographicOperations.ZeroMemory(destination);
}
```

The written slice excludes the native NUL terminator. Verification leaves the
caller-owned buffers unchanged and clears its own temporary NUL-terminated copy
in a `finally` block. It returns `false` for malformed records or a wrong password,
and rejects NUL bytes and non-ASCII encoded input. Native Argon2 still allocates
working memory; the span API does not make the complete operation allocation-free.

### Hash and verify with byte arrays

For an allocated encoded result, `Argon2HashEncoded` returns a `byte[]` that can
be stored and passed directly to the same span verification overload:

```csharp

using nebulae.dotArgon2;
using System.Security.Cryptography;

// Demonstration only: obtain password bytes directly from your input source in production.
byte[] password = "correct horse battery staple"u8.ToArray();
byte[] salt = RandomNumberGenerator.GetBytes(16);
byte[]? encoded = null;

// Choose the variant
var algorithm = Argon2.Argon2Algorithm.Argon2id;

try
{
    encoded = Argon2.Argon2HashEncoded(
        algorithm, timeCost: 2, memCost: 65536, parallelism: 2,
        password, salt);

    // Store encoded as bytes; later verify with the supplied password bytes.
    bool isValid = Argon2.VerifyEncoded(algorithm, encoded, password);
}
finally
{
    CryptographicOperations.ZeroMemory(password);
    CryptographicOperations.ZeroMemory(salt);
    if (encoded is not null)
        CryptographicOperations.ZeroMemory(encoded);
}

```

### Hash and verify with strings

**Prefer the byte/span examples above when explicit memory clearing matters.**
String helpers remain available for convenience and integration with systems that
store PHC records as text. The encoded string is immutable and cannot be reliably
wiped, even though the library clears its temporary byte buffers.

```csharp
using nebulae.dotArgon2;
using System.Security.Cryptography;
using System.Text;

// Demonstration only: this password literal cannot be wiped.
byte[] password = Encoding.UTF8.GetBytes("correct horse battery staple");
byte[] salt = RandomNumberGenerator.GetBytes(16);
var algorithm = Argon2.Argon2Algorithm.Argon2id;

try
{
    string encoded = Argon2.Argon2HashEncodedToString(
        algorithm, timeCost: 2, memCost: 65536, parallelism: 2,
        password, salt);

    bool isValid = Argon2.VerifyEncoded(algorithm, encoded, password);
    // encoded remains a managed string; there is no reliable way to clear it.
}
finally
{
    CryptographicOperations.ZeroMemory(password);
    CryptographicOperations.ZeroMemory(salt);
}
```

Encoding an existing password string into bytes does not erase the original
string. The sample password literals in these examples are illustrative;
clearing the writable copies does not erase those literals.

---

## Installation

You can install the package via NuGet:

```bash

$ dotnet add package nebulae.dotArgon2

```

Or build from a source checkout. Run this from the managed build directory
containing `native`, `dotArgon2`, and `dotArgon2Tests` (see the layout in the
native build guide):

```bash

dotnet build dotArgon2/dotArgon2.csproj -c Release

```

---

## Building your own native libraries

Prebuilt native libraries for all six RIDs are included in the NuGet package.
If you prefer to review the native source and compile it yourself, follow the
[native build guide](https://github.com/nebulaeonline/dotArgon2/blob/main/native/README.md).
Use the repository's `argon2` source tree, which includes dotArgon2's
memory-clearing changes, alongside the managed build directory. The build guide
explains the relative layout, source provenance, and license.

The guide covers Windows x64/ARM64, Ubuntu 18.04 x64/ARM64, and macOS x64/ARM64
with a macOS 11.0 deployment target. It explains how to test your libraries,
replace the corresponding runtime assets, and build your own NuGet package.

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

The byte-span `VerifyEncoded` overload creates no managed strings. It clears its
temporary NUL-terminated copy in a `finally` block on success, mismatch, or an
exception. Caller-owned encoded and password buffers are left unchanged. Short
records use stack storage; larger records use a temporary managed array. Native
verification still allocates its working memory.

Encoded hashes are intended for storage and are not plaintext passwords, but
keeping them in writable bytes lets applications apply their own clearing policy.
Clearing a buffer does not erase earlier copies, persisted records, or literal
sample data. In particular, encoding an existing password string into bytes does
not make the original string wipeable.

The supplied native source clears Argon2 working memory and temporary verification
buffers before freeing them.
