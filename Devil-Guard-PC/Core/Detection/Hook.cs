using DevilGuard.Core.IO;
using DevilGuard.Core.Misc;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace DevilGuard.Core.Detection
{
    internal static class Hook
    {
        public static bool CheckD3D(int processId, string directXVersion, byte[] expectedBytes, out string detectedBytes)
        {
            detectedBytes = string.Empty;
            if (expectedBytes == null || expectedBytes.Length == 0)
                throw new ArgumentException("Expected Direct3D bytes are required.", nameof(expectedBytes));

            string moduleName = "d3d" + directXVersion + ".dll";
            string exportName = "Direct3DCreate" + directXVersion;
            string localModulePath = Path.Combine(Environment.SystemDirectory, moduleName);
            IntPtr localModule = Win32.LoadLibrary(localModulePath);
            if (localModule == IntPtr.Zero)
                return false;

            try
            {
                IntPtr localExport = Win32.GetProcAddress(localModule, exportName);
                if (localExport == IntPtr.Zero)
                    return false;

                long exportOffset = localExport.ToInt64() - localModule.ToInt64();
                using Process process = Process.GetProcessById(processId);
                ProcessModule remoteModule = process.Modules
                    .Cast<ProcessModule>()
                    .FirstOrDefault(module => string.Equals(
                        Path.GetFileName(module.FileName),
                        moduleName,
                        StringComparison.OrdinalIgnoreCase));

                if (remoteModule == null)
                    return false;

                IntPtr remoteExport = new IntPtr(remoteModule.BaseAddress.ToInt64() + exportOffset);
                using Memory memory = new Memory(processId);
                byte[] actualBytes = memory.ReadBytes(remoteExport, checked((uint)expectedBytes.Length));

                bool matches = actualBytes.Length == expectedBytes.Length &&
                    actualBytes.SequenceEqual(expectedBytes);

                if (!matches)
                    detectedBytes = Convert.ToHexString(actualBytes);

                return !matches;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return false;
            }
            finally
            {
                Win32.FreeLibrary(localModule);
            }
        }
    }
}
