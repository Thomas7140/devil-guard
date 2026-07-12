using DevilGuard.Core.Misc;
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

namespace DevilGuard.Core.Drawing
{
    internal static class Converter
    {
        public static string GetString(Image image)
        {
            ArgumentNullException.ThrowIfNull(image);
            using MemoryStream stream = new MemoryStream();
            image.Save(stream, ImageFormat.Jpeg);
            return Encode.TextToBase64(stream.ToArray());
        }

        public static Image Resize(Image image, Size size)
        {
            ArgumentNullException.ThrowIfNull(image);
            if (size.Width <= 0 || size.Height <= 0)
                throw new ArgumentOutOfRangeException(nameof(size));

            float scale = Math.Min((float)size.Width / image.Width, (float)size.Height / image.Height);
            if (scale >= 1.0f)
                return new Bitmap(image);

            int width = Math.Max(1, (int)Math.Round(image.Width * scale));
            int height = Math.Max(1, (int)Math.Round(image.Height * scale));
            Bitmap result = new Bitmap(width, height, PixelFormat.Format32bppArgb);

            using Graphics graphics = Graphics.FromImage(result);
            graphics.CompositingQuality = CompositingQuality.HighQuality;
            graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
            graphics.SmoothingMode = SmoothingMode.HighQuality;
            graphics.DrawImage(image, 0, 0, width, height);
            return result;
        }
    }
}
