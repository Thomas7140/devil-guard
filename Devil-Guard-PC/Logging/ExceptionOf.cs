using System;

namespace DevilGuard.Logging
{
    public abstract class ExceptionOfBase : Exception
    {
        protected ExceptionOfBase()
        {
        }

        protected ExceptionOfBase(string message)
            : base(message)
        {
        }

        protected ExceptionOfBase(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }

    public class ExceptionOf<T> : ExceptionOfBase
    {
        public ExceptionOf()
        {
        }

        public ExceptionOf(string message)
            : base(message)
        {
        }

        public ExceptionOf(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
