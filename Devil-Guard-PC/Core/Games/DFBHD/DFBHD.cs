using DevilGuard.Core.Detection;
using DevilGuard.Core.IO;
using DevilGuard.Core.Security;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace DevilGuard.Core.Games.DFBHD
{
    internal sealed class DFBHD : IGame
    {
        private static readonly string[] SupportedProcessNames = { "dfbhd", "dfbhdlc" };

        public string DisplayName => Base.DisplayName;
        public string GameName => Base.GameName;
        public bool Notified { get; set; }
        public IntPtr ProcessHandle { get; set; }
        public string ProcessHash { get; set; } = string.Empty;
        public int ProcessId { get; set; }

        public bool IsGameRunning()
        {
            Process process = SupportedProcessNames
                .SelectMany(Process.GetProcessesByName)
                .FirstOrDefault(candidate => !candidate.HasExited);

            if (process == null)
            {
                ProcessId = 0;
                ProcessHandle = IntPtr.Zero;
                ProcessHash = string.Empty;
                return false;
            }

            try
            {
                ProcessId = process.Id;
                ProcessHandle = process.Handle;

                string executable = process.MainModule?.FileName;
                if (!string.IsNullOrWhiteSpace(executable) && File.Exists(executable))
                    ProcessHash = Hash.FileToSHA512(executable);
            }
            catch
            {
                // Process metadata can be restricted when the game is elevated.
                ProcessId = process.Id;
            }
            finally
            {
                process.Dispose();
            }

            return true;
        }

        public bool IsInGame()
        {
            if (!EnsureProcess())
                return false;

            try
            {
                return !string.IsNullOrWhiteSpace(GetServerIp()) ||
                       !string.IsNullOrWhiteSpace(GetServerName());
            }
            catch
            {
                return false;
            }
        }

        public bool IsPlaying()
        {
            if (!IsInGame())
                return false;

            try
            {
                return !string.IsNullOrWhiteSpace(GetPlayerName());
            }
            catch
            {
                return false;
            }
        }

        public string GetPlayerName()
        {
            if (!EnsureProcess())
                return string.Empty;

            using Memory memory = new Memory(ProcessId);
            return memory.ReadText(Address.Playername, 16);
        }

        public string GetServerName()
        {
            if (!EnsureProcess())
                return string.Empty;

            using Memory memory = new Memory(ProcessId);
            return memory.ReadText(Address.Servername, 37);
        }

        public string GetServerIp()
        {
            if (!EnsureProcess())
                return string.Empty;

            using Memory memory = new Memory(ProcessId);
            return memory.ReadText(Address.Serverip, 15);
        }

        internal void ResetF4Scope()
        {
            if (!EnsureProcess() || !IsExpectedGameProcess())
                return;

            using Memory memory = new Memory(ProcessId);
            memory.WriteBytes(Address.F4Scope, new byte[] { 0 });
        }

        public bool IsGameHooked()
        {
            if (!EnsureProcess())
                return false;

            string detectedString;
            return Hook.CheckD3D(ProcessId, "8", Base.DefaultD3dMemory, out detectedString);
        }

        private bool EnsureProcess()
        {
            if (ProcessId <= 0)
                return IsGameRunning();

            try
            {
                using Process process = Process.GetProcessById(ProcessId);
                return !process.HasExited;
            }
            catch
            {
                return IsGameRunning();
            }
        }

        private bool IsExpectedGameProcess()
        {
            try
            {
                using Process process = Process.GetProcessById(ProcessId);
                return SupportedProcessNames.Any(name =>
                    string.Equals(name, process.ProcessName, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }
    }
}
