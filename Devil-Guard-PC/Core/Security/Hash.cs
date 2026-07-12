using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace DevilGuard.Core.Security
{
    internal static class Hash
    {
        public static string TextToSHA512(string input)
        {
            ArgumentNullException.ThrowIfNull(input);
            return Convert.ToHexString(SHA512.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
        }

        internal static string FileToSHA512(string filePath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
            using FileStream file = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA512.HashData(file)).ToLowerInvariant();
        }

        internal static string BytesToSHA512(byte[] input)
        {
            ArgumentNullException.ThrowIfNull(input);
            return Convert.ToHexString(SHA512.HashData(input)).ToLowerInvariant();
        }

        public static string GetProgramIconHash(string filePath)
        {
            return BytesToSHA512(GetProgramIconBytes(filePath));
        }

        private static byte[] GetProgramIconBytes(string filePath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

            using Icon icon = Icon.ExtractAssociatedIcon(filePath);
            if (icon == null)
                return Array.Empty<byte>();

            using Bitmap bitmap = icon.ToBitmap();
            BitmapData data = bitmap.LockBits(
                new Rectangle(Point.Empty, bitmap.Size),
                ImageLockMode.ReadOnly,
                PixelFormat.Format32bppPArgb);

            try
            {
                int byteCount = Math.Abs(data.Stride) * bitmap.Height;
                byte[] bytes = new byte[byteCount];
                Marshal.Copy(data.Scan0, bytes, 0, byteCount);
                return bytes;
            }
            finally
            {
                bitmap.UnlockBits(data);
            }
        }
    }
}
