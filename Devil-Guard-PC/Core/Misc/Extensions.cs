using System;
using System.Linq;
using System.Threading;
using System.Windows.Threading;


namespace DevilGuard.Core.Misc
{
    public static class StringExtensions
    {
        /// <summary>
        /// Grab the left part of a string, up to the given character count
        /// </summary>
        /// <param name="length">Character count to substring</param>
        /// <returns>Substring</returns>
        public static string Left(this string str, int length)
        {
            return str.Substring(0, Math.Min(str.Length, length));
        }
    }

    public static class GlobalExtensions
    {
        /// <summary>
        /// Perform an invoke on objects (e.g form controls)
        /// </summary>
        /// <param name="methodcall">Action to perform/value to set</param>
        public static void Invoke(this DispatcherObject control, Action methodcall)
        {
            // See if we need to Invoke the call to the Dispatcher thread
            if (control.Dispatcher.Thread != Thread.CurrentThread)
                control.Dispatcher.Invoke(DispatcherPriority.Send, methodcall);
            else
                methodcall();
        }
    }
}
