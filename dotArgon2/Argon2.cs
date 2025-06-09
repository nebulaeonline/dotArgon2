using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace nebulae.dotArgon2
{
    public static class Argon2
    {
        public enum Argon2Algorithm
        {
            /// <summary>
            /// Argon2d: Optimized for GPU resistance and speed.
            /// Suitable for hashing data in non-interactive settings (e.g., back-end services).
            /// </summary>
            Argon2d = 0,

            /// <summary>
            /// Argon2i: Optimized for memory-hardness and side-channel resistance.
            /// Suitable for hashing secrets in potentially untrusted or client-side environments.
            /// </summary>
            Argon2i = 1,

            /// <summary>
            /// Argon2id: A hybrid of Argon2d and Argon2i. Recommended for most general-purpose password hashing.
            /// </summary>
            Argon2id = 2
        }


        /// <summary>
        /// Initializes the Argon2 cryptographic library for use in the application.
        /// </summary>
        /// <remarks>This method must be called before using any functionality provided by the Argon2
        /// library. It ensures that the library is properly set up and ready for cryptographic operations.</remarks>
        public static void Init()
        {
            Argon2Library.Init();
        }

        /// <summary>
        /// Estimates the size, in bytes, of the encoded output for a given salt and hash length.
        /// </summary>
        /// <remarks>The estimate is based on a fixed prefix size and the Base64-encoded lengths of the
        /// salt and hash.</remarks>
        /// <param name="saltLength">The length of the salt, in bytes.</param>
        /// <param name="hashLength">The length of the hash, in bytes. Defaults to 32 if not specified.</param>
        /// <returns>An integer representing the estimated size, in bytes, of the encoded output.</returns>
        public static int GetEncodedSizeEstimate(int saltLength, int hashLength = 32)
        {
            // 108 is a conservative fixed prefix estimate from the reference C header
            return 108 + ((saltLength * 4 + 2) / 3) + ((hashLength * 4 + 2) / 3);
        }

        /// <summary>
        /// Verifies whether the provided password matches the given Argon2-encoded hash.
        /// </summary>
        /// <remarks>This method uses the specified Argon2 algorithm to verify the password against the
        /// encoded hash.  Ensure that the algorithm used for verification matches the one used to generate the encoded
        /// hash.</remarks>
        /// <param name="algorithm">The Argon2 algorithm variant to use for verification. Must be one of the supported values:  <see
        /// cref="Argon2Algorithm.Argon2id"/>, <see cref="Argon2Algorithm.Argon2i"/>, or <see
        /// cref="Argon2Algorithm.Argon2d"/>.</param>
        /// <param name="encoded">The Argon2-encoded hash to verify against. This value cannot be null, empty, or consist only of whitespace.</param>
        /// <param name="password">The password to verify, provided as a byte array. This value cannot be null or empty.</param>
        /// <returns><see langword="true"/> if the password matches the encoded hash; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="encoded"/> is null, empty, or consists only of whitespace,  or if <paramref
        /// name="password"/> is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="algorithm"/> is not a valid <see cref="Argon2Algorithm"/> value.</exception>
        public static bool VerifyEncoded(
            Argon2Algorithm algorithm,
            string encoded,
            byte[] password)
        {
            if (string.IsNullOrWhiteSpace(encoded))
                throw new ArgumentException("Encoded hash cannot be null or empty.", nameof(encoded));
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            return algorithm switch
            {
                Argon2Algorithm.Argon2id => Argon2Interop.argon2id_verify(encoded, password, (UIntPtr)password.Length) == 0,
                Argon2Algorithm.Argon2i => Argon2Interop.argon2i_verify(encoded, password, (UIntPtr)password.Length) == 0,
                Argon2Algorithm.Argon2d => Argon2Interop.argon2d_verify(encoded, password, (UIntPtr)password.Length) == 0,
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), "Invalid Argon2 algorithm")
            };
        }

        /// <summary>
        /// Zero-alloc verifier for whether the provided encoded Argon2 hash matches the given password using the specified Argon2
        /// algorithm.
        /// </summary>
        /// <remarks>This method performs a secure comparison of the password against the encoded Argon2
        /// hash.  Ensure that the <paramref name="password"/> is provided as a <see cref="ReadOnlySpan{T}"/> to avoid
        /// unnecessary memory allocations.</remarks>
        /// <param name="algorithm">The Argon2 algorithm to use for verification. Must be one of <see cref="Argon2Algorithm.Argon2id"/>, <see
        /// cref="Argon2Algorithm.Argon2i"/>, or <see cref="Argon2Algorithm.Argon2d"/>.</param>
        /// <param name="encoded">The encoded Argon2 hash to verify. Cannot be null, empty, or whitespace.</param>
        /// <param name="password">The password to verify against the encoded hash. Cannot be empty.</param>
        /// <returns><see langword="true"/> if the password matches the encoded hash using the specified algorithm; otherwise,
        /// <see langword="false"/>.</returns>
        public static unsafe bool VerifyEncoded(
            Argon2Algorithm algorithm,
            string encoded,
            ReadOnlySpan<byte> password)
        {
            if (string.IsNullOrWhiteSpace(encoded))
                return false;
            if (password.IsEmpty)
                return false;

            fixed (byte* pwd = password)
            {
                return algorithm switch
                {
                    Argon2Algorithm.Argon2id => Argon2Interop.argon2id_verify_ptr(encoded, pwd, (UIntPtr)password.Length) == 0,
                    Argon2Algorithm.Argon2i => Argon2Interop.argon2i_verify_ptr(encoded, pwd, (UIntPtr)password.Length) == 0,
                    Argon2Algorithm.Argon2d => Argon2Interop.argon2d_verify_ptr(encoded, pwd, (UIntPtr)password.Length) == 0,
                    _ => false
                };
            }
        }

        /// <summary>
        /// Computes a raw Argon2 hash using the specified algorithm, parameters, password, and salt.
        /// </summary>
        /// <remarks>Argon2 is a memory-hard key derivation function designed for secure password hashing.
        /// This method provides a low-level interface for computing raw Argon2 hashes. For most use cases, ensure that
        /// the parameters <paramref name="timeCost"/>, <paramref name="memCost"/>, and <paramref name="parallelism"/>
        /// are chosen carefully to balance security and performance.</remarks>
        /// <param name="algorithm">The Argon2 algorithm to use for hashing. Must be one of <see cref="Argon2Algorithm.Argon2id"/>,  <see
        /// cref="Argon2Algorithm.Argon2i"/>, or <see cref="Argon2Algorithm.Argon2d"/>.</param>
        /// <param name="timeCost">The time cost parameter, which defines the number of iterations. Must be greater than zero.</param>
        /// <param name="memCost">The memory cost parameter, which defines the amount of memory (in kibibytes) to use. Must be greater than
        /// zero.</param>
        /// <param name="parallelism">The degree of parallelism, which defines the number of threads to use. Must be greater than zero.</param>
        /// <param name="password">The password to hash. Cannot be <see langword="null"/> or empty.</param>
        /// <param name="salt">The cryptographic salt to use for hashing. Cannot be <see langword="null"/> or empty.</param>
        /// <param name="hashLength">The desired length of the resulting hash, in bytes. Must be greater than zero. Defaults to 32 bytes.</param>
        /// <returns>A byte array containing the computed Argon2 hash of the specified length.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="password"/> is <see langword="null"/> or empty of if the length of the <paramref name="salt"/> is less than 8.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="algorithm"/> is invalid, or if <paramref name="hashLength"/> is less than or equal
        /// to zero.</exception>
        /// <exception cref="InvalidOperationException">Thrown if the Argon2 hashing operation fails. The exception message will include the error code and
        /// description.</exception>
        public static byte[] Argon2HashRaw(
            Argon2Algorithm algorithm,
            uint timeCost,
            uint memCost,
            uint parallelism,
            byte[] password,
            byte[] salt,
            int hashLength = 32)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (salt == null || salt.Length < 8)
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));
            if (hashLength <= 0)
                throw new ArgumentOutOfRangeException(nameof(hashLength), "Hash length must be greater than zero.");

            var buffer = GC.AllocateUninitializedArray<byte>(hashLength);

            int result = algorithm switch
            {
                Argon2Algorithm.Argon2id => Argon2Interop.argon2id_hash_raw(
                    timeCost, memCost, parallelism,
                    password, (UIntPtr)password.Length,
                    salt, (UIntPtr)salt.Length,
                    buffer, (UIntPtr)hashLength),

                Argon2Algorithm.Argon2i => Argon2Interop.argon2i_hash_raw(
                    timeCost, memCost, parallelism,
                    password, (UIntPtr)password.Length,
                    salt, (UIntPtr)salt.Length,
                    buffer, (UIntPtr)hashLength),

                Argon2Algorithm.Argon2d => Argon2Interop.argon2d_hash_raw(
                    timeCost, memCost, parallelism,
                    password, (UIntPtr)password.Length,
                    salt, (UIntPtr)salt.Length,
                    buffer, (UIntPtr)hashLength),

                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), "Invalid Argon2 algorithm.")
            };

            if (result != 0)
                throw new InvalidOperationException($"Argon2 hash failed with error code {result}: {Argon2Interop.GetErrorMessage(result)}");

            return buffer;
        }

        /// <summary>
        /// Zero-alloc no-throw attempt to compute a raw Argon2 hash using the specified algorithm and parameters.
        /// </summary>
        /// <remarks>This method provides a low-level interface for computing Argon2 hashes. It does not
        /// allocate memory for the hash; instead, the caller must provide a sufficiently large buffer in <paramref
        /// name="destination"/>. The caller is responsible for ensuring that the input parameters meet the required
        /// constraints.</remarks>
        /// <param name="algorithm">The Argon2 algorithm variant to use (e.g., Argon2id, Argon2i, or Argon2d).</param>
        /// <param name="timeCost">The time cost parameter, which determines the number of iterations. Must be greater than 0.</param>
        /// <param name="memCost">The memory cost parameter, which specifies the amount of memory (in kibibytes) to use. Must be greater than
        /// 0.</param>
        /// <param name="parallelism">The degree of parallelism, which specifies the number of threads or lanes to use. Must be greater than 0.</param>
        /// <param name="password">The password to hash. Must not be empty.</param>
        /// <param name="salt">The cryptographic salt to use. Must not be empty.</param>
        /// <param name="destination">The buffer to receive the computed hash. Its length must be at least <paramref name="hashLength"/>.</param>
        /// <param name="bytesWritten">When this method returns, contains the number of bytes written to <paramref name="destination"/>, if the
        /// operation succeeds; otherwise, 0.</param>
        /// <param name="hashLength">The desired length of the hash in bytes. Defaults to 32. Must be greater than 0.</param>
        /// <returns><see langword="true"/> if the hash was successfully computed and written to <paramref name="destination"/>;
        /// otherwise, <see langword="false"/>.</returns>
        public static unsafe bool TryArgon2HashRawFast(
            Argon2Algorithm algorithm,
            uint timeCost,
            uint memCost,
            uint parallelism,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> destination,
            out int bytesWritten,
            int hashLength = 32)
        {
            bytesWritten = 0;

            if (password.IsEmpty || salt.Length < 8 || destination.Length < hashLength)
                return false;

            fixed (byte* pwd = password)
            fixed (byte* slt = salt)
            fixed (byte* dest = destination)
            {
                int result = algorithm switch
                {
                    Argon2Algorithm.Argon2id => Argon2Interop.argon2id_hash_raw_ptr(
                        timeCost, memCost, parallelism,
                        pwd, (UIntPtr)password.Length,
                        slt, (UIntPtr)salt.Length,
                        dest, (UIntPtr)hashLength),

                    Argon2Algorithm.Argon2i => Argon2Interop.argon2i_hash_raw_ptr(
                        timeCost, memCost, parallelism,
                        pwd, (UIntPtr)password.Length,
                        slt, (UIntPtr)salt.Length,
                        dest, (UIntPtr)hashLength),

                    Argon2Algorithm.Argon2d => Argon2Interop.argon2d_hash_raw_ptr(
                        timeCost, memCost, parallelism,
                        pwd, (UIntPtr)password.Length,
                        slt, (UIntPtr)salt.Length,
                        dest, (UIntPtr)hashLength),

                    _ => -1
                };

                if (result != 0)
                    return false;

                bytesWritten = hashLength;
                return true;
            }
        }

        /// <summary>
        /// Computes an Argon2 hash of the specified password and salt, and returns the result as a hexadecimal string.
        /// </summary>
        /// <remarks>Argon2 is a memory-hard key derivation function designed for secure password hashing.
        /// This method uses the specified algorithm variant and parameters to compute the hash, ensuring resistance to
        /// brute-force attacks.</remarks>
        /// <param name="algorithm">The Argon2 algorithm variant to use (e.g., Argon2d, Argon2i, or Argon2id).</param>
        /// <param name="timeCost">The number of iterations to perform. Must be greater than 0.</param>
        /// <param name="memCost">The memory cost, in kibibytes, to allocate for the hashing operation. Must be greater than 0.</param>
        /// <param name="parallelism">The degree of parallelism (number of threads) to use. Must be greater than 0.</param>
        /// <param name="password">The password to hash, as a byte array. Cannot be null or empty.</param>
        /// <param name="salt">The cryptographic salt to use, as a byte array. Cannot be null or empty.</param>
        /// <param name="hashLength">The desired length of the resulting hash, in bytes. Must be greater than 0. Defaults to 32.</param>
        /// <returns>A hexadecimal string representation of the computed Argon2 hash. The string is in uppercase format.</returns>
        public static string Argon2HashRawToHex(
            Argon2Algorithm algorithm,
            uint timeCost,
            uint memCost,
            uint parallelism,
            byte[] password,
            byte[] salt,
            int hashLength = 32)
        {
            var hash = Argon2HashRaw(algorithm, timeCost, memCost, parallelism, password, salt, hashLength);
            return Convert.ToHexString(hash); // Returns uppercase hex; .NET 5+
        }

        /// <summary>
        /// Attempts to compute an Argon2 hash of the specified password and salt, and returns the result as a
        /// hexadecimal string.
        /// </summary>
        /// <remarks>This method provides a high-performance implementation of the Argon2 hashing
        /// algorithm, optimized for raw hash computation and conversion to a hexadecimal string. The caller must ensure
        /// that the input parameters meet the specified constraints to avoid failure.</remarks>
        /// <param name="algorithm">The Argon2 algorithm variant to use (e.g., Argon2d, Argon2i, or Argon2id).</param>
        /// <param name="timeCost">The time cost parameter, which determines the number of iterations. Must be greater than 0.</param>
        /// <param name="memCost">The memory cost parameter, which specifies the memory usage in kibibytes. Must be greater than 0.</param>
        /// <param name="parallelism">The degree of parallelism, which specifies the number of threads to use. Must be greater than 0.</param>
        /// <param name="password">The password to hash, provided as a read-only span of bytes. Cannot be empty.</param>
        /// <param name="salt">The cryptographic salt to use, provided as a read-only span of bytes. Cannot be empty.</param>
        /// <param name="result">When this method returns, contains the hexadecimal string representation of the computed hash, if the
        /// operation was successful; otherwise, an empty string.</param>
        /// <param name="hashLength">The desired length of the hash in bytes. Must be greater than 0. Defaults to 32.</param>
        /// <returns><see langword="true"/> if the hash was successfully computed and converted to a hexadecimal string;
        /// otherwise, <see langword="false"/>.</returns>
        public static bool TryArgon2HashRawFastToHex(
            Argon2Algorithm algorithm,
            uint timeCost,
            uint memCost,
            uint parallelism,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            out string result,
            int hashLength = 32)
        {
            result = string.Empty;

            if (password.IsEmpty || salt.Length < 8 || hashLength <= 0)
                return false;

            Span<byte> buffer = hashLength <= 512
                ? stackalloc byte[hashLength]
                : new byte[hashLength];

            if (!TryArgon2HashRawFast(algorithm, timeCost, memCost, parallelism, password, salt, buffer, out int written, hashLength))
                return false;

            result = Convert.ToHexString(buffer[..written]);
            return true;
        }

        /// <summary>
        /// Generates an encoded Argon2 hash using the specified algorithm and parameters.
        /// </summary>
        /// <remarks>Argon2 is a memory-hard key derivation function designed for secure password hashing.
        /// This method produces an encoded hash that includes the algorithm parameters, salt, and hash in a single
        /// string, suitable for storage or verification.</remarks>
        /// <param name="algorithm">The Argon2 algorithm to use. Must be one of <see cref="Argon2Algorithm.Argon2id"/>, <see
        /// cref="Argon2Algorithm.Argon2i"/>, or <see cref="Argon2Algorithm.Argon2d"/>.</param>
        /// <param name="timeCost">The time cost parameter, which determines the number of iterations. Must be greater than zero.</param>
        /// <param name="memCost">The memory cost parameter, which specifies the amount of memory (in kibibytes) to use. Must be greater than
        /// zero.</param>
        /// <param name="parallelism">The degree of parallelism, which specifies the number of threads to use. Must be greater than zero.</param>
        /// <param name="password">The password to hash. Cannot be null or empty.</param>
        /// <param name="salt">The cryptographic salt to use. Cannot be null or empty.</param>
        /// <param name="hashLength">The desired length of the resulting hash, in bytes. Must be greater than zero. Defaults to 32 bytes.</param>
        /// <returns>A byte array containing the encoded Argon2 hash.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="password"/> is <see langword="null"/> or empty of if the length of the <paramref name="salt"/> is less than 8.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="hashLength"/> is less than or equal to zero, or if <paramref name="algorithm"/> is
        /// invalid.</exception>
        /// <exception cref="InvalidOperationException">Thrown if the Argon2 hashing operation fails. The exception message will include the error code and
        /// description.</exception>
        public static byte[] Argon2HashEncoded(
            Argon2Algorithm algorithm,
            uint timeCost,
            uint memCost,
            uint parallelism,
            byte[] password,
            byte[] salt,
            int hashLength = 32)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (salt == null || salt.Length < 8)
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));
            if (hashLength <= 0)
                throw new ArgumentOutOfRangeException(nameof(hashLength), "Hash length must be greater than zero.");

            int estimatedSize = GetEncodedSizeEstimate(salt.Length, hashLength);
            StringBuilder sb = new StringBuilder(estimatedSize);

            int result = algorithm switch
            {
                Argon2Algorithm.Argon2id => Argon2Interop.argon2id_hash_encoded(
                    timeCost, memCost, parallelism,
                    password, (UIntPtr)password.Length,
                    salt, (UIntPtr)salt.Length,
                    (UIntPtr)hashLength,
                    sb, (UIntPtr)estimatedSize), // This line gets replaced in the fast-path (#6)

                Argon2Algorithm.Argon2i => Argon2Interop.argon2i_hash_encoded(
                    timeCost, memCost, parallelism,
                    password, (UIntPtr)password.Length,
                    salt, (UIntPtr)salt.Length,
                    (UIntPtr)hashLength,
                    sb, (UIntPtr)estimatedSize),

                Argon2Algorithm.Argon2d => Argon2Interop.argon2d_hash_encoded(
                    timeCost, memCost, parallelism,
                    password, (UIntPtr)password.Length,
                    salt, (UIntPtr)salt.Length,
                    (UIntPtr)hashLength,
                    sb, (UIntPtr)estimatedSize),

                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), "Invalid Argon2 algorithm.")
            };

            if (result != 0)
                throw new InvalidOperationException($"Argon2 encoded hash failed with error code {result}: {Argon2Interop.GetErrorMessage(result)}");

            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        /// <summary>
        /// Computes an encoded Argon2 hash and returns it as a UTF-8 string.
        /// </summary>
        /// <param name="algorithm">The Argon2 algorithm variant to use.</param>
        /// <param name="timeCost">The number of iterations to perform.</param>
        /// <param name="memCost">The memory cost in kibibytes.</param>
        /// <param name="parallelism">The degree of parallelism (number of threads).</param>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The cryptographic salt.</param>
        /// <param name="hashLength">Desired length of the hash, in bytes. Defaults to 32.</param>
        /// <returns>A UTF-8 encoded string representing the Argon2 hash.</returns>
        public static string Argon2HashEncodedToString(
            Argon2Algorithm algorithm,
            uint timeCost,
            uint memCost,
            uint parallelism,
            byte[] password,
            byte[] salt,
            int hashLength = 32)
        {
            var bytes = Argon2HashEncoded(algorithm, timeCost, memCost, parallelism, password, salt, hashLength);
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Zero-alloc no-throw attempt to compute an Argon2 hash using the specified parameters and encode it as a string.
        /// </summary>
        /// <remarks>This method uses the specified Argon2 variant to compute a password hash and encodes
        /// the result as a string.  The caller must ensure that the <paramref name="destination"/> buffer is large
        /// enough to hold the encoded hash.  If the buffer is too small or any of the input parameters are invalid, the
        /// method returns <see langword="false"/>.</remarks>
        /// <param name="algorithm">The Argon2 algorithm variant to use (e.g., Argon2id, Argon2i, or Argon2d).</param>
        /// <param name="timeCost">The time cost parameter, which determines the number of iterations. Must be greater than 0.</param>
        /// <param name="memCost">The memory cost parameter, which specifies the memory usage in kibibytes. Must be greater than 0.</param>
        /// <param name="parallelism">The degree of parallelism, which specifies the number of threads to use. Must be greater than 0.</param>
        /// <param name="password">The password to hash. Cannot be empty.</param>
        /// <param name="salt">The cryptographic salt to use. Cannot be empty.</param>
        /// <param name="destination">A buffer to receive the encoded hash string. The buffer must be large enough to hold the encoded result.</param>
        /// <param name="bytesWritten">When this method returns, contains the number of bytes written to <paramref name="destination"/>,  or 0 if
        /// the operation fails.</param>
        /// <param name="hashLength">The desired length of the hash in bytes. Defaults to 32. Must be greater than 0.</param>
        /// <returns><see langword="true"/> if the hash was successfully computed and encoded; otherwise, <see
        /// langword="false"/>.</returns>
        public static unsafe bool TryArgon2HashEncodedFast(
            Argon2Algorithm algorithm,
            uint timeCost,
            uint memCost,
            uint parallelism,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> destination,
            out int bytesWritten,
            int hashLength = 32)
        {
            bytesWritten = 0;

            if (password.IsEmpty || salt.Length < 8 || destination.IsEmpty || hashLength <= 0)
                return false;

            fixed (byte* pwd = password)
            fixed (byte* slt = salt)
            fixed (byte* dest = destination)
            {
                int result = algorithm switch
                {
                    Argon2Algorithm.Argon2id => Argon2Interop.argon2id_hash_encoded_ptr(
                        timeCost, memCost, parallelism,
                        pwd, (UIntPtr)password.Length,
                        slt, (UIntPtr)salt.Length,
                        (UIntPtr)hashLength,
                        dest, (UIntPtr)destination.Length),

                    Argon2Algorithm.Argon2i => Argon2Interop.argon2i_hash_encoded_ptr(
                        timeCost, memCost, parallelism,
                        pwd, (UIntPtr)password.Length,
                        slt, (UIntPtr)salt.Length,
                        (UIntPtr)hashLength,
                        dest, (UIntPtr)destination.Length),

                    Argon2Algorithm.Argon2d => Argon2Interop.argon2d_hash_encoded_ptr(
                        timeCost, memCost, parallelism,
                        pwd, (UIntPtr)password.Length,
                        slt, (UIntPtr)salt.Length,
                        (UIntPtr)hashLength,
                        dest, (UIntPtr)destination.Length),

                    _ => -1
                };

                if (result != 0)
                    return false;

                int len = destination.IndexOf((byte)0);
                bytesWritten = (len >= 0) ? len : destination.Length;
                return true;
            }
        }

    }
}
