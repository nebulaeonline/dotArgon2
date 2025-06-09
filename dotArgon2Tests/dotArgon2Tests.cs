using Xunit;
using nebulae.dotArgon2;
using System.Text;

namespace dotArgon2Tests
{
    public class dotArgon2Tests
    {
        [Theory]
        [InlineData(Argon2.Argon2Algorithm.Argon2id)]
        [InlineData(Argon2.Argon2Algorithm.Argon2i)]
        [InlineData(Argon2.Argon2Algorithm.Argon2d)]
        public void HashRaw_Generates_CorrectLength(Argon2.Argon2Algorithm algo)
        {
            Argon2.Init();

            var password = Encoding.UTF8.GetBytes("password123");
            var salt = Encoding.UTF8.GetBytes("somesalt");
            const int hashLength = 64;

            var result = Argon2.Argon2HashRaw(algo, 2, 65536, 2, password, salt, hashLength);

            Assert.NotNull(result);
            Assert.Equal(hashLength, result.Length);
        }

        [Theory]
        [InlineData(Argon2.Argon2Algorithm.Argon2id)]
        [InlineData(Argon2.Argon2Algorithm.Argon2i)]
        [InlineData(Argon2.Argon2Algorithm.Argon2d)]
        public void TryHashRawFast_Writes_ExpectedLength(Argon2.Argon2Algorithm algo)
        {
            Argon2.Init();

            Span<byte> buffer = stackalloc byte[64];
            var password = Encoding.UTF8.GetBytes("securepass");
            var salt = Encoding.UTF8.GetBytes("uniquesalt");

            bool success = Argon2.TryArgon2HashRawFast(algo, 2, 65536, 2, password, salt, buffer, out int written, 64);

            Assert.True(success);
            Assert.Equal(64, written);
        }

        [Theory]
        [InlineData(Argon2.Argon2Algorithm.Argon2id)]
        [InlineData(Argon2.Argon2Algorithm.Argon2i)]
        [InlineData(Argon2.Argon2Algorithm.Argon2d)]
        public void Parallelism_Affects_Hash_Output(Argon2.Argon2Algorithm algo)
        {
            Argon2.Init();

            byte[] password = Encoding.UTF8.GetBytes("parallelism-test");
            byte[] salt = Encoding.UTF8.GetBytes("same-salt");

            byte[] hash1 = Argon2.Argon2HashRaw(algo, 2, 65536, 1, password, salt, 32);
            byte[] hash2 = Argon2.Argon2HashRaw(algo, 2, 65536, 4, password, salt, 32);

            Assert.NotEqual(Convert.ToHexString(hash1), Convert.ToHexString(hash2));
        }

        [Theory]
        [InlineData(Argon2.Argon2Algorithm.Argon2id)]
        [InlineData(Argon2.Argon2Algorithm.Argon2i)]
        [InlineData(Argon2.Argon2Algorithm.Argon2d)]
        public void HashAndVerify_Encoded_Roundtrip(Argon2.Argon2Algorithm algo)
        {
            Argon2.Init();

            byte[] password = Encoding.UTF8.GetBytes("correct-horse-battery-staple");
            byte[] salt = Encoding.UTF8.GetBytes("somesalt");

            byte[] encodedBytes = Argon2.Argon2HashEncoded(algo, 2, 65536, 2, password, salt);
            string encodedString = Encoding.UTF8.GetString(encodedBytes);

            bool valid = Argon2.VerifyEncoded(algo, encodedString, password);

            Assert.True(valid);
        }

        [Theory]
        [InlineData(Argon2.Argon2Algorithm.Argon2id)]
        [InlineData(Argon2.Argon2Algorithm.Argon2i)]
        [InlineData(Argon2.Argon2Algorithm.Argon2d)]
        public void HashRawToHex_Produces_CorrectLengthAndFormat(Argon2.Argon2Algorithm algo)
        {
            Argon2.Init();

            byte[] password = Encoding.UTF8.GetBytes("hexpass");
            byte[] salt = Encoding.UTF8.GetBytes("hexsaltsalt");

            int hashLength = 32;
            string hex = Argon2.Argon2HashRawToHex(algo, 2, 65536, 2, password, salt, hashLength);

            // Assert: length in characters = bytes * 2
            Assert.Equal(hashLength * 2, hex.Length);

            // Assert: valid hex characters only (0-9A-F)
            Assert.Matches("^[A-F0-9]+$", hex);
        }

        [Theory]
        [InlineData(Argon2.Argon2Algorithm.Argon2id)]
        [InlineData(Argon2.Argon2Algorithm.Argon2i)]
        [InlineData(Argon2.Argon2Algorithm.Argon2d)]
        public void FastPath_EncodedHash_Roundtrip_Succeeds(Argon2.Argon2Algorithm algo)
        {
            Argon2.Init();

            var password = Encoding.UTF8.GetBytes("fast-horse-battery-staple");
            var salt = Encoding.UTF8.GetBytes("reliablesalt");
            int hashLength = 32;

            Span<byte> buffer = stackalloc byte[Argon2.GetEncodedSizeEstimate(salt.Length, hashLength)];

            bool success = Argon2.TryArgon2HashEncodedFast(
                algo, 2, 65536, 2,
                password, salt,
                buffer, out int written,
                hashLength);

            Assert.True(success);
            Assert.True(written > 0);

            string encoded = Encoding.UTF8.GetString(buffer[..written]);

            bool verified = Argon2.VerifyEncoded(algo, encoded, password);
            Assert.True(verified);
        }

        [Theory]
        [InlineData(Argon2.Argon2Algorithm.Argon2id)]
        [InlineData(Argon2.Argon2Algorithm.Argon2i)]
        [InlineData(Argon2.Argon2Algorithm.Argon2d)]
        public void VerifyEncoded_WithWrongPassword_ReturnsFalse(Argon2.Argon2Algorithm algo)
        {
            Argon2.Init();

            var password = Encoding.UTF8.GetBytes("correct-password");
            var salt = Encoding.UTF8.GetBytes("samesalt99");

            var encodedBytes = Argon2.Argon2HashEncoded(
                algo, 2, 65536, 2, password, salt);

            var encoded = Encoding.UTF8.GetString(encodedBytes);

            // Use a different password for verification
            var wrongPassword = Encoding.UTF8.GetBytes("wrong-password");

            bool result = Argon2.VerifyEncoded(algo, encoded, wrongPassword);

            Assert.False(result);
        }
    }
}