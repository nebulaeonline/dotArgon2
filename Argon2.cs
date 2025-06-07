using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace nebulae.dotArgon2
{
    public static class Argon2
    {
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
        /// Computes a raw Argon2id hash for the specified password and salt using the given parameters.
        /// </summary>
        /// <remarks>Argon2id is a memory-hard password hashing algorithm designed to resist brute-force
        /// attacks. Ensure that the <paramref name="timeCost"/>, <paramref name="memCost"/>, and <paramref
        /// name="parallelism"/> parameters are chosen appropriately for your security requirements and system
        /// capabilities.</remarks>
        /// <param name="timeCost">The number of iterations to perform. Higher values increase computation time and security.</param>
        /// <param name="memCost">The amount of memory, in kilobytes, to use during hashing. Higher values increase memory usage and security.</param>
        /// <param name="parallelism">The degree of parallelism to use during hashing. Must be greater than 0.</param>
        /// <param name="password">The password to hash. Cannot be null or empty.</param>
        /// <param name="salt">The cryptographic salt to use for hashing. Cannot be null or empty.</param>
        /// <param name="hashLength">Length of the resulting hash in bytes. Must be greater than 0.</param>
        /// <returns>A byte array containing the Argon2id hash.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the hashing operation fails.</exception>
        public static byte[] Argon2idHashRaw(
            uint timeCost, uint memCost, uint parallelism,
            byte[] password, byte[] salt, int hashLength)
        {
            var hash = new byte[hashLength];
            var result = Argon2Interop.argon2id_hash_raw(timeCost, memCost, parallelism, password, (UIntPtr)password.Length, salt, (UIntPtr)salt.Length, hash, (UIntPtr)hashLength);
            if (result != 0)
            {
                throw new InvalidOperationException($"Argon2id hash failed with error code {result}: {Argon2Interop.GetErrorMessage(result)}");
            }
            return hash;
        }

        /// <summary>
        /// Generates an Argon2id hash encoded as a string using the specified parameters.
        /// </summary>
        /// <remarks>Argon2id is a memory-hard password hashing algorithm designed to resist brute-force
        /// attacks.  Ensure that the <paramref name="timeCost"/>, <paramref name="memCost"/>, and <paramref
        /// name="parallelism"/> parameters  are chosen carefully to balance security and performance based on your
        /// application's requirements.</remarks>
        /// <param name="timeCost">The time cost parameter, which defines the number of iterations. Must be greater than 0.</param>
        /// <param name="memCost">The memory cost parameter, which defines the amount of memory (in kibibytes) to use. Must be greater than 0.</param>
        /// <param name="parallelism">The degree of parallelism, which defines the number of threads to use. Must be greater than 0.</param>
        /// <param name="password">The password to hash, provided as a byte array. Cannot be null or empty.</param>
        /// <param name="salt">The cryptographic salt to use, provided as a byte array. Cannot be null or empty.</param>
        /// <returns>A string containing the encoded Argon2id hash.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the Argon2id hash encoding fails. The exception message includes the error code returned by the
        /// underlying implementation.</exception>
        public static string Argon2idHashEncoded(
            uint timeCost, uint memCost, uint parallelism,
            byte[] password, byte[] salt)
        {
            var encoded = new StringBuilder(256);
            var result = Argon2Interop.argon2id_hash_encoded(timeCost, memCost, parallelism, password, (UIntPtr)password.Length, salt, (UIntPtr)salt.Length, (UIntPtr)32, encoded, (UIntPtr)encoded.Capacity);
            if (result != 0)
                throw new InvalidOperationException($"Argon2id hash encoding failed with error code {result}: {Argon2Interop.GetErrorMessage(result)}");
            return encoded.ToString();
        }

        /// <summary>
        /// Verifies a password against an Argon2id-encoded hash.
        /// </summary>
        /// <remarks>This method uses the Argon2id algorithm to verify the provided password against the
        /// given encoded hash. Ensure that the <paramref name="password"/> is provided as a byte array and matches the
        /// expected format for the encoded hash.</remarks>
        /// <param name="encoded">The Argon2id-encoded hash to verify against.</param>
        /// <param name="password">The password, as a byte array, to verify.</param>
        /// <returns><see langword="true"/> if the password matches the encoded hash, false otherwise</returns>
        public static bool Argon2idVerify(string encoded, byte[] password)
        {
            var result = Argon2Interop.argon2id_verify(encoded, password, (UIntPtr)password.Length);
            if (result != 0)
                return false;
            return true;
        }

        /// <summary>
        /// Computes a raw Argon2i hash using the specified parameters.
        /// </summary>
        /// <remarks>Argon2i is a memory-hard password hashing algorithm designed to resist brute-force
        /// attacks.  Ensure that the <paramref name="salt"/> is unique for each password to maximize
        /// security.</remarks>
        /// <param name="timeCost">The number of iterations to perform. Higher values increase computation time and security.</param>
        /// <param name="memCost">The amount of memory, in kilobytes, to use during hashing. Higher values increase memory usage and security.</param>
        /// <param name="parallelism">The degree of parallelism to use, representing the number of threads or lanes.</param>
        /// <param name="password">The password to hash. Cannot be null or empty.</param>
        /// <param name="salt">The cryptographic salt to use. Cannot be null or empty.</param>
        /// <param name="hashLength">The length of the resulting hash in bytes. Must be greater than 0.</param>
        /// <returns>A byte array containing the raw Argon2i hash.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the hashing operation fails. The exception message includes the error code returned by the
        /// underlying implementation.</exception>
        public static byte[] Argon2iHashRaw(
            uint timeCost, uint memCost, uint parallelism,
            byte[] password, byte[] salt, int hashLength)
        {
            var hash = new byte[hashLength];
            var result = Argon2Interop.argon2i_hash_raw(timeCost, memCost, parallelism, password, (UIntPtr)password.Length, salt, (UIntPtr)salt.Length, hash, (UIntPtr)hashLength);
            if (result != 0)
                throw new InvalidOperationException($"Argon2i hash failed with error code {result}: {Argon2Interop.GetErrorMessage(result)}");
            return hash;
        }

        /// <summary>
        /// Generates an Argon2i hash encoded as a string using the specified parameters.
        /// </summary>
        /// <remarks>Argon2i is a memory-hard password hashing algorithm designed to resist side-channel
        /// attacks. Ensure that the <paramref name="password"/> and <paramref name="salt"/> are securely generated and
        /// stored.</remarks>
        /// <param name="timeCost">The time cost parameter, which defines the number of iterations. Must be greater than 0.</param>
        /// <param name="memCost">The memory cost parameter, which defines the amount of memory (in kibibytes) to use. Must be greater than 0.</param>
        /// <param name="parallelism">The degree of parallelism, which defines the number of threads to use. Must be greater than 0.</param>
        /// <param name="password">The password to hash, provided as a byte array. Cannot be null or empty.</param>
        /// <param name="salt">The cryptographic salt, provided as a byte array. Cannot be null or empty.</param>
        /// <returns>A string containing the encoded Argon2i hash.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the Argon2i hash encoding process fails.</exception>
        public static string Argon2iHashEncoded(
            uint timeCost, uint memCost, uint parallelism,
            byte[] password, byte[] salt)
        {
            var encoded = new StringBuilder(256);
            var result = Argon2Interop.argon2i_hash_encoded(timeCost, memCost, parallelism, password, (UIntPtr)password.Length, salt, (UIntPtr)salt.Length, (UIntPtr)32, encoded, (UIntPtr)encoded.Capacity);
            if (result != 0)
                throw new InvalidOperationException($"Argon2id hash encoding failed with error code {result}: {Argon2Interop.GetErrorMessage(result)}");
            return encoded.ToString();
        }

        /// <summary>
        /// Verifies whether the provided password matches the encoded Argon2i hash.
        /// </summary>
        /// <param name="encoded">The encoded Argon2i hash to verify against.</param>
        /// <param name="password">The password, as a byte array, to verify.</param>
        /// <returns><see langword="true"/> if the password matches the encoded hash, <see langword="false"/> otherwise</returns>
        public static bool Argon2iVerify(string encoded, byte[] password)
        {
            var result = Argon2Interop.argon2i_verify(encoded, password, (UIntPtr)password.Length);
            if (result != 0)
                return false;
            return true;
        }

        /// <summary>
        /// Computes a raw Argon2d hash using the specified parameters.
        /// </summary>
        /// <remarks>Argon2d is a memory-hard key derivation function designed for secure password
        /// hashing. Ensure that the <paramref name="password"/> and <paramref name="salt"/> are securely generated and
        /// stored. The <paramref name="memCost"/> parameter should be chosen carefully to balance security and
        /// performance.</remarks>
        /// <param name="timeCost">The number of iterations to perform. Higher values increase computation time and security.</param>
        /// <param name="memCost">The amount of memory, in kilobytes, to use for the hashing process. Must be a power of two.</param>
        /// <param name="parallelism">The degree of parallelism, specifying the number of threads to use. Must be greater than zero.</param>
        /// <param name="password">The password to hash. Cannot be null or empty.</param>
        /// <param name="salt">The cryptographic salt to use for the hash. Cannot be null or empty.</param>
        /// <param name="hashLength">The length of the resulting hash in bytes. Must be greater than zero.</param>
        /// <returns>A byte array containing the raw Argon2d hash.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the hashing operation fails.</exception>
        public static byte[] Argon2dHashRaw(
            uint timeCost, uint memCost, uint parallelism,
            byte[] password, byte[] salt, int hashLength)
        {
            var hash = new byte[hashLength]; 
            var result = Argon2Interop.argon2d_hash_raw(timeCost, memCost, parallelism, password, (UIntPtr)password.Length, salt, (UIntPtr)salt.Length, hash, (UIntPtr)hashLength);
            if (result != 0)
                throw new InvalidOperationException($"Argon2d hash failed with error code {result}: {Argon2Interop.GetErrorMessage(result)}");
            return hash;
        }

        /// <summary>
        /// Generates an Argon2d hash encoded as a string using the specified parameters.
        /// </summary>
        /// <remarks>Argon2d is a memory-hard key derivation function designed for secure password
        /// hashing.  Ensure that the <paramref name="password"/> and <paramref name="salt"/> are securely generated and
        /// managed.</remarks>
        /// <param name="timeCost">The time cost parameter, which defines the number of iterations. Must be greater than 0.</param>
        /// <param name="memCost">The memory cost parameter, which defines the amount of memory (in kibibytes) to use. Must be greater than 0.</param>
        /// <param name="parallelism">The degree of parallelism, which defines the number of threads to use. Must be greater than 0.</param>
        /// <param name="password">The password to hash, provided as a byte array. Cannot be null or empty.</param>
        /// <param name="salt">The cryptographic salt, provided as a byte array. Cannot be null or empty.</param>
        /// <returns>A string containing the encoded Argon2d hash.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the Argon2d hash encoding process fails.</exception>
        public static string Argon2dHashEncoded(
            uint timeCost, uint memCost, uint parallelism,
            byte[] password, byte[] salt)
        {
            var encoded = new StringBuilder(128); // Adjust size as needed
            var result = Argon2Interop.argon2d_hash_encoded(timeCost, memCost, parallelism, password, (UIntPtr)password.Length, salt, (UIntPtr)salt.Length, (UIntPtr)32, encoded, (UIntPtr)encoded.Capacity);
            if (result != 0)
                throw new InvalidOperationException($"Argon2d hash encoding failed with error code {result}: {Argon2Interop.GetErrorMessage(result)}");
            return encoded.ToString();
        }

        /// <summary>
        /// Verifies whether the provided password matches the encoded Argon2d hash.
        /// </summary>
        /// <remarks>This method uses the Argon2d algorithm to verify the password against the provided
        /// encoded hash. Ensure that the <paramref name="password"/> is provided as a byte array and matches the
        /// expected format and length for the Argon2d hash.</remarks>
        /// <param name="encoded">The encoded Argon2d hash to verify against.</param>
        /// <param name="password">The password, as a byte array, to verify.</param>
        /// <returns><see langword="true"/> if the password matches the encoded hash, <see langword="false"/> otherwise</returns>
        public static bool Argon2dVerify(string encoded, byte[] password)
        {
            var result = Argon2Interop.argon2d_verify(encoded, password, (UIntPtr)password.Length);
            if (result != 0)
                return false;
            return true;
        }
    }
}
