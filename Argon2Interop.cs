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
        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2id_hash_raw(
        uint t_cost, uint m_cost, uint parallelism,
        byte[] pwd, UIntPtr pwdlen,
        byte[] salt, UIntPtr saltlen,
        byte[] hash, UIntPtr hashlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2id_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        byte[] pwd, UIntPtr pwdlen,
        byte[] salt, UIntPtr saltlen,
        UIntPtr hashlen,
        [MarshalAs(UnmanagedType.LPStr)] StringBuilder encoded, UIntPtr encodedlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2id_verify(
        [MarshalAs(UnmanagedType.LPStr)] string encoded,
        byte[] pwd, UIntPtr pwdlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2i_hash_raw(
        uint t_cost, uint m_cost, uint parallelism,
        byte[] pwd, UIntPtr pwdlen,
        byte[] salt, UIntPtr saltlen,
        byte[] hash, UIntPtr hashlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2i_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        byte[] pwd, UIntPtr pwdlen,
        byte[] salt, UIntPtr saltlen,
        UIntPtr hashlen,
        [MarshalAs(UnmanagedType.LPStr)] StringBuilder encoded, UIntPtr encodedlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2i_verify(
        [MarshalAs(UnmanagedType.LPStr)] string encoded,
        byte[] pwd, UIntPtr pwdlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2d_hash_raw(
        uint t_cost, uint m_cost, uint parallelism,
        byte[] pwd, UIntPtr pwdlen,
        byte[] salt, UIntPtr saltlen,
        byte[] hash, UIntPtr hashlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2d_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        byte[] pwd, UIntPtr pwdlen,
        byte[] salt, UIntPtr saltlen,
        UIntPtr hashlen,
        [MarshalAs(UnmanagedType.LPStr)] StringBuilder encoded, UIntPtr encodedlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        public static extern int argon2d_verify(
        [MarshalAs(UnmanagedType.LPStr)] string encoded,
        byte[] pwd, UIntPtr pwdlen);

        [DllImport("argon2", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr argon2_error_message(int error_code);

        public static string GetErrorMessage(int errorCode)
        {
            var ptr = argon2_error_message(errorCode);
            return Marshal.PtrToStringAnsi(ptr)!;
        }
    }
}
