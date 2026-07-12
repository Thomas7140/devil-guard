using System;
using System.IO;
using System.Text;

namespace DevilGuard.Logging
{
    public static class FileLog
    {
        private static readonly object SyncRoot = new object();

        public static string GetLogDirectory(bool machineWide = false)
        {
            Environment.SpecialFolder folder = machineWide
                ? Environment.SpecialFolder.CommonApplicationData
                : Environment.SpecialFolder.LocalApplicationData;

            string root = Environment.GetFolderPath(folder);
            return Path.Combine(root, "DevilGuard", "Logs");
        }

        public static string Write(string source, string message, Exception exception = null, bool machineWide = false)
        {
            string directory = GetLogDirectory(machineWide);
            Directory.CreateDirectory(directory);

            string safeSource = string.IsNullOrWhiteSpace(source) ? "application" : SanitizeFileName(source);
            string path = Path.Combine(directory, safeSource + "-" + DateTime.UtcNow.ToString("yyyyMMdd") + ".log");

            StringBuilder entry = new StringBuilder();
            entry.Append(DateTimeOffset.UtcNow.ToString("O"));
            entry.Append(" [");
            entry.Append(safeSource);
            entry.Append("] ");
            entry.AppendLine(message ?? string.Empty);

            if (exception != null)
                entry.AppendLine(exception.ToString());

            lock (SyncRoot)
                File.AppendAllText(path, entry.ToString(), new UTF8Encoding(false));

            return path;
        }


        public static bool TryWrite(string source, string message, Exception exception = null, bool machineWide = false)
        {
            try
            {
                Write(source, message, exception, machineWide);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static string SanitizeFileName(string value)
        {
            foreach (char invalid in Path.GetInvalidFileNameChars())
                value = value.Replace(invalid, '-');

            return value.Trim();
        }
    }
}
