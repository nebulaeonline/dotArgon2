using System.Text;
using nebulae.dotArgon2;
using Xunit;

namespace dotArgon2Tests;

public class Utf8VerificationTests
{
    [Theory]
    [InlineData(Argon2.Argon2Algorithm.Argon2d, 16)]
    [InlineData(Argon2.Argon2Algorithm.Argon2i, 16)]
    [InlineData(Argon2.Argon2Algorithm.Argon2id, 16)]
    [InlineData(Argon2.Argon2Algorithm.Argon2id, 512)]
    public void BytesAndSlices_VerifyWithoutChangingInputs(Argon2.Argon2Algorithm algorithm, int saltLength)
    {
        byte[] password = [0x70, 0, 0x61, 0xc3, 0xa9];
        byte[] salt = Enumerable.Repeat((byte)42, saltLength).ToArray();
        byte[] encoded = Argon2.Argon2HashEncoded(algorithm, 2, 32, 2, password, salt);
        byte[] original = encoded.ToArray();
        byte[] originalPassword = password.ToArray();

        Assert.True(Argon2.VerifyEncoded(algorithm, encoded, password));
        Assert.True(Argon2.VerifyEncoded(algorithm, Encoding.UTF8.GetString(encoded), password));
        Assert.False(Argon2.VerifyEncoded(algorithm, encoded, "wrong"u8));
        Assert.False(Argon2.VerifyEncoded((Argon2.Argon2Algorithm)(((int)algorithm + 1) % 3), encoded, password));

        byte[] padded = new byte[encoded.Length + 8];
        encoded.CopyTo(padded, 3);
        Assert.True(Argon2.VerifyEncoded(algorithm, padded.AsSpan(3, encoded.Length), password));
        Assert.Equal(original, encoded);
        Assert.Equal(originalPassword, password);
    }

    [Theory]
    [InlineData(Argon2.Argon2Algorithm.Argon2d)]
    [InlineData(Argon2.Argon2Algorithm.Argon2i)]
    [InlineData(Argon2.Argon2Algorithm.Argon2id)]
    public void FastHashOutput_VerifiesDirectly(Argon2.Argon2Algorithm algorithm)
    {
        Span<byte> destination = stackalloc byte[256];
        Assert.True(Argon2.TryArgon2HashEncodedFast(algorithm, 2, 32, 2,
            "password"u8, "somesalt"u8, destination, out int written));
        Assert.True(Argon2.VerifyEncoded(algorithm, destination[..written], "password"u8));
        // Passing the terminator must not silently accept a truncated C string.
        Assert.False(Argon2.VerifyEncoded(algorithm, destination[..(written + 1)], "password"u8));
    }

    [Fact]
    public void InvalidRecords_ReturnFalse()
    {
        const Argon2.Argon2Algorithm algorithm = Argon2.Argon2Algorithm.Argon2id;
        byte[] valid = Argon2.Argon2HashEncoded(algorithm, 2, 32, 1, "password"u8.ToArray(), "somesalt"u8.ToArray());
        Assert.False(Argon2.VerifyEncoded(algorithm, ReadOnlySpan<byte>.Empty, "password"u8));
        Assert.False(Argon2.VerifyEncoded(algorithm, valid, ReadOnlySpan<byte>.Empty));
        Assert.False(Argon2.VerifyEncoded((Argon2.Argon2Algorithm)99, valid, "password"u8));
        Assert.False(Argon2.VerifyEncoded(algorithm, "not a PHC record"u8, "password"u8));
        Assert.False(Argon2.VerifyEncoded(algorithm, valid.AsSpan(0, valid.Length - 1), "password"u8));
        byte[] withSuffix = [..valid, 0, (byte)'x'];
        Assert.False(Argon2.VerifyEncoded(algorithm, withSuffix, "password"u8));
        valid[5] = 0xff;
        Assert.False(Argon2.VerifyEncoded(algorithm, valid, "password"u8));
    }
}
