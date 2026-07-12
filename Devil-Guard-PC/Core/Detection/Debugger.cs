using System;
using System.Diagnostics;

namespace DevilGuard.Core.Detection
{
    internal static class Debugger
    {
        public static bool IsCurrentProcessDebugged()
        {
            if (System.Diagnostics.Debugger.IsAttached)
                return true;

            if (Misc.Win32.IsDebuggerPresent())
                return true;

            using Process process = Process.GetCurrentProcess();
            bool remoteDebuggerPresent = false;
            return Misc.Win32.CheckRemoteDebuggerPresent(process.Handle, ref remoteDebuggerPresent) &&
                   remoteDebuggerPresent;
        }

        public static bool IsProcessDebugged(Process process)
        {
            ArgumentNullException.ThrowIfNull(process);
            bool debuggerPresent = false;
            return Misc.Win32.CheckRemoteDebuggerPresent(process.Handle, ref debuggerPresent) &&
                   debuggerPresent;
        }
    }
}
