using DevilGuard.Logging;
using System;
using System.Windows;
using System.Windows.Threading;

namespace DevilGuard.Overseer
{
    public partial class App : Application
    {
        public App()
        {
            DispatcherUnhandledException += OnDispatcherUnhandledException;
        }

        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            FileLog.TryWrite("overseer", "Unhandled UI exception.", e.Exception);
            MessageBox.Show("An unexpected error was recorded in the Devil-Guard log folder.", "Devil-Guard Overseer", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }
    }
}
