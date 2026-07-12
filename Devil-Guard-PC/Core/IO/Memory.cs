using DevilGuard.Core.Misc;
using System;
using System.ComponentModel;
using System.Text;
using System.Runtime.InteropServices;

namespace DevilGuard.Core.IO
{
    internal sealed class Memory : IDisposable
    {
        private IntPtr _processHandle;
        private bool _disposed;

        [Flags]
        private enum ProcessAccess : uint
        {
            VmOperation = 0x0008,
            VmRead = 0x0010,
            VmWrite = 0x0020
        }

        public Memory()
        {
        }

        public Memory(int processId)
        {
            Open(processId);
        }

        public bool IsOpen => _processHandle != IntPtr.Zero;

        internal void Open(int processId)
        {
            ThrowIfDisposed();
            Close();

            ProcessAccess access = ProcessAccess.VmOperation | ProcessAccess.VmRead | ProcessAccess.VmWrite;
            _processHandle = Win32.OpenProcess((uint)access, false, checked((uint)processId));

            if (_processHandle == IntPtr.Zero)
                throw new Win32Exception($"Unable to open process {processId}.");
        }

        internal void Close()
        {
            if (_processHandle == IntPtr.Zero)
                return;

            Win32.CloseHandle(_processHandle);
            _processHandle = IntPtr.Zero;
        }

        internal byte[] ReadBytes(int processAddress, uint bytesToRead) =>
            ReadBytes(new IntPtr(processAddress), bytesToRead);

        internal byte[] ReadBytes(IntPtr processAddress, uint bytesToRead)
        {
            EnsureOpen();
            ValidateAddress(processAddress);
            if (bytesToRead == 0)
                return Array.Empty<byte>();

            byte[] buffer = new byte[checked((int)bytesToRead)];
            bool succeeded = Win32.ReadProcessMemory(
                _processHandle,
                processAddress,
                buffer,
                bytesToRead,
                out nuint bytesRead);

            if (!succeeded)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to read process memory at 0x{processAddress.ToInt64():X}.");

            int actual = checked((int)bytesRead);
            if (actual == buffer.Length)
                return buffer;

            Array.Resize(ref buffer, Math.Max(actual, 0));
            return buffer;
        }

        internal string ReadInt(int processAddress)
        {
            byte[] bytes = ReadBytes(processAddress, sizeof(short));
            if (bytes.Length < sizeof(short))
                return string.Empty;

            return BitConverter.ToInt16(bytes, 0).ToString();
        }

        internal string ReadText(int processAddress, uint bytesToRead)
        {
            byte[] bytes = ReadBytes(processAddress, bytesToRead);
            int terminator = Array.IndexOf(bytes, (byte)0);
            int length = terminator >= 0 ? terminator : bytes.Length;
            return Encoding.ASCII.GetString(bytes, 0, length).TrimEnd();
        }

        internal void WriteBytes(int processAddress, byte[] bytesToWrite)
        {
            EnsureOpen();
            ArgumentNullException.ThrowIfNull(bytesToWrite);
            if (bytesToWrite.Length == 0)
                throw new ArgumentException("Cannot write an empty byte array.", nameof(bytesToWrite));

            IntPtr address = new IntPtr(processAddress);
            ValidateAddress(address);

            bool succeeded = Win32.WriteProcessMemory(
                _processHandle,
                address,
                bytesToWrite,
                checked((nuint)bytesToWrite.Length),
                out nuint bytesWritten);

            if (!succeeded || bytesWritten != (nuint)bytesToWrite.Length)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to write process memory at 0x{processAddress:X8}.");
        }

        internal void WriteText(int processAddress, string input)
        {
            ArgumentNullException.ThrowIfNull(input);
            WriteBytes(processAddress, Encoding.ASCII.GetBytes(input));
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            Close();
            _disposed = true;
            GC.SuppressFinalize(this);
        }

        private void EnsureOpen()
        {
            ThrowIfDisposed();
            if (_processHandle == IntPtr.Zero)
                throw new InvalidOperationException("No process is open.");
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(Memory));
        }

        private static void ValidateAddress(IntPtr processAddress)
        {
            long address = processAddress.ToInt64();
            if (address <= 0)
                throw new ArgumentOutOfRangeException(nameof(processAddress), "Process address must be greater than zero.");
        }
    }
}
