using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace nebulae.dotArgon2
{
    internal static class Argon2Interop
    {
        // 2id hash_raw
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2id_hash_raw(
            uint t_cost, uint m_cost, uint parallelism,
            byte[] pwd, UIntPtr pwdlen,
            byte[] salt, UIntPtr saltlen,
            byte[] hash, UIntPtr hashlen);

        // 2id hash_raw_ptr
        [DllImport("argon2", EntryPoint = "argon2id_hash_raw", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2id_hash_raw_ptr(
            uint t_cost, uint m_cost, uint parallelism,
            byte* pwd, UIntPtr pwdlen,
            byte* salt, UIntPtr saltlen,
            byte* hash, UIntPtr hashlen);

        // 2id hash_encoded
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2id_hash_encoded(
            uint t_cost,
            uint m_cost,
            uint parallelism,
            byte[] pwd, UIntPtr pwdlen,
            byte[] salt, UIntPtr saltlen,
            UIntPtr hashlen,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder encoded, UIntPtr encodedlen);

        // 2id hash_encoded_ptr
        [DllImport("argon2", EntryPoint = "argon2id_hash_encoded", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2id_hash_encoded_ptr(
            uint t_cost, uint m_cost, uint parallelism,
            byte* pwd, UIntPtr pwdlen,
            byte* salt, UIntPtr saltlen,
            UIntPtr hashlen,
            byte* encoded, UIntPtr encodedlen);

        // 2id verify
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2id_verify(
            [MarshalAs(UnmanagedType.LPStr)] string encoded,
            byte[] pwd, UIntPtr pwdlen);

        // 2id verify_ptr
        [DllImport("argon2", EntryPoint = "argon2id_verify", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2id_verify_ptr(
            [MarshalAs(UnmanagedType.LPStr)] string encoded,
            byte* pwd, UIntPtr pwdlen);

        // 2i hash_raw
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2i_hash_raw(
            uint t_cost, uint m_cost, uint parallelism,
            byte[] pwd, UIntPtr pwdlen,
            byte[] salt, UIntPtr saltlen,
            byte[] hash, UIntPtr hashlen);

        // 2i hash_raw_ptr
        [DllImport("argon2", EntryPoint = "argon2i_hash_raw", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2i_hash_raw_ptr(
            uint t_cost, uint m_cost, uint parallelism,
            byte* pwd, UIntPtr pwdlen,
            byte* salt, UIntPtr saltlen,
            byte* hash, UIntPtr hashlen);

        // 2i hash_encoded
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2i_hash_encoded(
            uint t_cost,
            uint m_cost,
            uint parallelism,
            byte[] pwd, UIntPtr pwdlen,
            byte[] salt, UIntPtr saltlen,
            UIntPtr hashlen,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder encoded, UIntPtr encodedlen);

        // 2i hash_encoded_ptr
        [DllImport("argon2", EntryPoint = "argon2i_hash_encoded", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2i_hash_encoded_ptr(
            uint t_cost, uint m_cost, uint parallelism,
            byte* pwd, UIntPtr pwdlen,
            byte* salt, UIntPtr saltlen,
            UIntPtr hashlen,
            byte* encoded, UIntPtr encodedlen);

        // 2i verify
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2i_verify(
            [MarshalAs(UnmanagedType.LPStr)] string encoded,
            byte[] pwd, UIntPtr pwdlen);

        // 2i verify_ptr
        [DllImport("argon2", EntryPoint = "argon2i_verify", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2i_verify_ptr(
            [MarshalAs(UnmanagedType.LPStr)] string encoded,
            byte* pwd, UIntPtr pwdlen);

        // 2d hash_raw
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2d_hash_raw(
            uint t_cost, uint m_cost, uint parallelism,
            byte[] pwd, UIntPtr pwdlen,
            byte[] salt, UIntPtr saltlen,
            byte[] hash, UIntPtr hashlen);

        // 2d hash_raw_ptr
        [DllImport("argon2", EntryPoint = "argon2d_hash_raw", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2d_hash_raw_ptr(
            uint t_cost, uint m_cost, uint parallelism,
            byte* pwd, UIntPtr pwdlen,
            byte* salt, UIntPtr saltlen,
            byte* hash, UIntPtr hashlen);

        // 2d hash_encoded
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2d_hash_encoded(
            uint t_cost,
            uint m_cost,
            uint parallelism,
            byte[] pwd, UIntPtr pwdlen,
            byte[] salt, UIntPtr saltlen,
            UIntPtr hashlen,
            [MarshalAs(UnmanagedType.LPStr)] StringBuilder encoded, UIntPtr encodedlen);

        // 2d hash_encoded_ptr
        [DllImport("argon2", EntryPoint = "argon2d_hash_encoded", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2d_hash_encoded_ptr(
            uint t_cost, uint m_cost, uint parallelism,
            byte* pwd, UIntPtr pwdlen,
            byte* salt, UIntPtr saltlen,
            UIntPtr hashlen,
            byte* encoded, UIntPtr encodedlen);

        // 2d verify
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2d_verify(
            [MarshalAs(UnmanagedType.LPStr)] string encoded,
            byte[] pwd, UIntPtr pwdlen);

        // 2d verify_ptr
        [DllImport("argon2", EntryPoint = "argon2d_verify", CallingConvention = CallingConvention.Cdecl)]
        public static extern unsafe int argon2d_verify_ptr(
            [MarshalAs(UnmanagedType.LPStr)] string encoded,
            byte* pwd, UIntPtr pwdlen);

        // Error handling
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr argon2_error_message(int error_code);

        public static string GetErrorMessage(int errorCode)
        {
            var ptr = argon2_error_message(errorCode);
            return Marshal.PtrToStringAnsi(ptr)!;
        }
    }
}
