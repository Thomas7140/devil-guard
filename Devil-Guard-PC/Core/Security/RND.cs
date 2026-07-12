using System;
using System.Security.Cryptography;
using System.Text;

namespace DevilGuard.Core.Security
{
    internal static class RND
    {
        private const string Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

        public static int Next()
        {
            return RandomNumberGenerator.GetInt32(int.MaxValue);
        }

        public static int Next(int maxValue)
        {
            return maxValue <= 0 ? 0 : RandomNumberGenerator.GetInt32(maxValue);
        }

        public static int Next(int minValue, int maxValue)
        {
            if (minValue < 0 || maxValue < 0 || minValue >= maxValue)
                return minValue;

            return RandomNumberGenerator.GetInt32(minValue, maxValue);
        }

        public static double NextDouble()
        {
            Span<byte> bytes = stackalloc byte[sizeof(uint)];
            RandomNumberGenerator.Fill(bytes);
            uint value = BitConverter.ToUInt32(bytes);
            return value / (1.0 + uint.MaxValue);
        }

        public static void NextBytes(byte[] buffer)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            RandomNumberGenerator.Fill(buffer);
        }

        public static string NextString(int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException(nameof(length));

            StringBuilder builder = new StringBuilder(length);
            for (int i = 0; i < length; i++)
                builder.Append(Characters[RandomNumberGenerator.GetInt32(Characters.Length)]);

            return builder.ToString();
        }
    }
}
