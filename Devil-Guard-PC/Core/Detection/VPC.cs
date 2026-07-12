using DevilGuard.Core.IO;
using System;

namespace DevilGuard.Core.Detection
{
    public static class VPC
    {
        public static bool DetectVPC()
        {
            string manufacturer = Hardware.Get("Win32_ComputerSystem", "Manufacturer");
            string model = Hardware.Get("Win32_ComputerSystem", "Model");
            string bios = Hardware.Get("Win32_BIOS", "SMBIOSBIOSVersion");
            string combined = (manufacturer + " " + model + " " + bios).ToLowerInvariant();

            string[] indicators =
            {
                "virtual machine",
                "vmware",
                "virtualbox",
                "vbox",
                "qemu",
                "kvm",
                "xen",
                "hyper-v"
            };

            foreach (string indicator in indicators)
            {
                if (combined.Contains(indicator, StringComparison.Ordinal))
                    return true;
            }

            return false;
        }
    }
}
