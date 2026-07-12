using DevilGuard.Core.Misc;
using System;
using System.Drawing;
using System.Drawing.Imaging;

namespace DevilGuard.Core.Drawing
{
    internal static class ScreenCapture
    {
        public static Bitmap CaptureScreen(IntPtr windowHandle)
        {
            if (!Win32.GetWindowRect(windowHandle, out Win32.RECT rectangle))
                return null;

            int width = rectangle.Right - rectangle.Left;
            int height = rectangle.Bottom - rectangle.Top;
            if (width < 100 || height < 100)
                return null;

            Bitmap bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb);
            using Graphics graphics = Graphics.FromImage(bitmap);
            graphics.CopyFromScreen(
                rectangle.Left,
                rectangle.Top,
                0,
                0,
                new Size(width, height),
                CopyPixelOperation.SourceCopy);

            return bitmap;
        }
    }
}
