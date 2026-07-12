using DevilGuard.Core.Security;
using System;
using System.Management;

namespace DevilGuard.Core.IO
{
    internal static class Hardware
    {
        public static string Get(string wmiClass, string property)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(wmiClass);
            ArgumentException.ThrowIfNullOrWhiteSpace(property);

            try
            {
                using ManagementObjectSearcher searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
                using ManagementObjectCollection results = searcher.Get();
                foreach (ManagementObject item in results)
                {
                    using (item)
                    {
                        object value = item[property];
                        if (value != null)
                            return Convert.ToString(value) ?? string.Empty;
                    }
                }
            }
            catch (ManagementException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }

            return string.Empty;
        }

        internal static string GetID()
        {
            const string valueName = "InstallId";
            string installationId = Regedit.GetValue(valueName);
            if (string.IsNullOrWhiteSpace(installationId))
            {
                installationId = Guid.NewGuid().ToString("N");
                Regedit.SetValue(valueName, installationId);
            }

            return Hash.TextToSHA512("DevilGuard:" + installationId);
        }


    }
}
