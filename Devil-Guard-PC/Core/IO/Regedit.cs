using Microsoft.Win32;
using System;

namespace DevilGuard.Core.IO
{
    internal static class Regedit
    {
        private const string RegistryPath = @"Software\DevilGuard";

        public static void SetValue(string name, string value)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            using RegistryKey key = Registry.CurrentUser.CreateSubKey(RegistryPath, writable: true)
                ?? throw new InvalidOperationException("Unable to open the Devil-Guard registry key.");
            key.SetValue(name, value ?? string.Empty, RegistryValueKind.String);
        }

        public static string GetValue(string name)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            using RegistryKey key = Registry.CurrentUser.OpenSubKey(RegistryPath, writable: false);
            return key?.GetValue(name) as string ?? string.Empty;
        }

        public static bool RemoveValue(string name)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(name);
            using RegistryKey key = Registry.CurrentUser.OpenSubKey(RegistryPath, writable: true);
            if (key == null)
                return false;

            key.DeleteValue(name, throwOnMissingValue: false);
            return true;
        }

        public static bool RemoveFolder()
        {
            using RegistryKey software = Registry.CurrentUser.OpenSubKey("Software", writable: true);
            if (software == null)
                return false;

            software.DeleteSubKeyTree("DevilGuard", throwOnMissingSubKey: false);
            return true;
        }
    }
}
