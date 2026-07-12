using System;
using System.Security.Cryptography;
using System.Text;

namespace DevilGuard.Core.Security
{
    internal static class Protector
    {
        public static byte[] Protect(byte[] input, out byte[] entropy)
        {
            ArgumentNullException.ThrowIfNull(input);
            entropy = RandomNumberGenerator.GetBytes(16);
            return ProtectedData.Protect(input, entropy, DataProtectionScope.CurrentUser);
        }

        public static byte[] Unprotect(byte[] input, byte[] entropy)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(entropy);
            return ProtectedData.Unprotect(input, entropy, DataProtectionScope.CurrentUser);
        }

        public static string Protect(string input)
        {
            ArgumentNullException.ThrowIfNull(input);
            byte[] protectedData = Protect(Encoding.UTF8.GetBytes(input), out byte[] entropy);
            return $"{Convert.ToBase64String(entropy)}.{Convert.ToBase64String(protectedData)}";
        }

        public static string Unprotect(string input)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(input);
            string[] parts = input.Split('.', 2);
            if (parts.Length != 2)
                throw new FormatException("The protected value is not in Devil-Guard format.");

            byte[] entropy = Convert.FromBase64String(parts[0]);
            byte[] protectedData = Convert.FromBase64String(parts[1]);
            return Encoding.UTF8.GetString(Unprotect(protectedData, entropy));
        }
    }
}
