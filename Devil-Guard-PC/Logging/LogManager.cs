using System;
using System.Collections.Generic;
using System.Linq;

namespace DevilGuard.Logging
{
    public enum LogType
    {
        Info = 0,
        Alert,
        Error,
        Critical
    }

    public sealed class LogItem
    {
        public Guid Id { get; } = Guid.NewGuid();
        public LogType Type { get; set; }
        public DateTime TimeStamp { get; } = DateTime.UtcNow;
        public bool Visible { get; set; } = true;
        public bool Sync { get; set; }
        public bool Synced { get; set; }
        public string Message { get; set; } = string.Empty;
        public string StackTrace { get; set; } = string.Empty;
    }

    public sealed class LogManager : IDisposable
    {
        private readonly List<LogItem> _log = new List<LogItem>();
        private readonly object _syncRoot = new object();
        private bool _disposed;

        public void Add(LogType type, string message)
        {
            Add(type, message, string.Empty, false);
        }

        public void Add(LogType type, string message, string stackTrace, bool sync)
        {
            ThrowIfDisposed();

            lock (_syncRoot)
            {
                _log.Add(new LogItem
                {
                    Type = type,
                    Message = message ?? string.Empty,
                    StackTrace = stackTrace ?? string.Empty,
                    Sync = sync
                });
            }
        }

        public bool Remove(Guid id)
        {
            ThrowIfDisposed();

            lock (_syncRoot)
            {
                int index = _log.FindIndex(item => item.Id == id);
                if (index < 0)
                    return false;

                _log.RemoveAt(index);
                return true;
            }
        }

        public int Purge(TimeSpan? maximumAge = null)
        {
            ThrowIfDisposed();
            TimeSpan age = maximumAge ?? TimeSpan.FromHours(2);
            DateTime threshold = DateTime.UtcNow.Subtract(age);

            lock (_syncRoot)
            {
                return _log.RemoveAll(item =>
                    item.TimeStamp < threshold &&
                    item.Type != LogType.Error &&
                    item.Type != LogType.Critical);
            }
        }

        public void Clear()
        {
            lock (_syncRoot)
                _log.Clear();
        }

        public LogItem Get(Guid id)
        {
            ThrowIfDisposed();

            lock (_syncRoot)
                return _log.FirstOrDefault(item => item.Id == id);
        }

        public IReadOnlyList<LogItem> Snapshot()
        {
            ThrowIfDisposed();

            lock (_syncRoot)
                return _log.ToArray();
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            Clear();
            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(LogManager));
        }
    }
}
