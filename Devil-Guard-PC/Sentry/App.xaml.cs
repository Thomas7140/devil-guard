using DevilGuard.Logging;
using System;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

namespace DevilGuard.Sentry
{
    public partial class App : Application
    {
        private Mutex _singleInstanceMutex;
        private bool _ownsSingleInstanceMutex;

        protected override void OnStartup(StartupEventArgs e)
        {
            _singleInstanceMutex = new Mutex(true, @"Local\DevilGuard.Sentry", out bool createdNew);
            _ownsSingleInstanceMutex = createdNew;
            if (!createdNew)
            {
                MessageBox.Show(
                    "Devil-Guard Sentry is already running.",
                    "Devil-Guard",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                Shutdown();
                return;
            }

            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            DispatcherUnhandledException += App_DispatcherUnhandledException;
            base.OnStartup(e);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            if (_ownsSingleInstanceMutex)
                _singleInstanceMutex?.ReleaseMutex();

            _singleInstanceMutex?.Dispose();
            base.OnExit(e);
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Exception exception = e.ExceptionObject as Exception;
            FileLog.TryWrite("sentry", "Unhandled application-domain exception.", exception);
        }

        private static void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            FileLog.TryWrite("sentry", "Unhandled UI exception.", e.Exception);
            MessageBox.Show(
                "Devil-Guard encountered an unexpected error. Details were written to the local log folder.",
                "Devil-Guard",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            e.Handled = true;
        }
    }
}
