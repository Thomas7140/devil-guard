using DevilGuard.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;

namespace DevilGuard.Sentry
{
    public partial class MainWindow : Window
    {
        private readonly DispatcherTimer _refreshTimer;

        public MainWindow()
        {
            InitializeComponent();
            _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            _refreshTimer.Tick += (_, _) => RefreshStatus();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            FileLog.Write("sentry", "Sentry started.");
            RefreshStatus();
            _refreshTimer.Start();
        }

        private void Window_Closed(object sender, EventArgs e)
        {
            _refreshTimer.Stop();
            FileLog.Write("sentry", "Sentry stopped.");
        }

        private void RefreshStatus()
        {
            ClientStatusText.Text = "Ready";
            OperatingSystemText.Text = RuntimeInformation.OSDescription.Trim() + " (" + RuntimeInformation.OSArchitecture + ")";
            RuntimeText.Text = ".NET " + Environment.Version + " · process " + RuntimeInformation.ProcessArchitecture;

            bool gameRunning = IsAnyProcessRunning("dfbhd", "dfbhdlc");

            GameStatusText.Text = gameRunning ? "Running" : "Not detected";
            GameStatusText.Foreground = gameRunning
                ? System.Windows.Media.Brushes.LightGreen
                : System.Windows.Media.Brushes.LightGray;
            LastRefreshText.Text = DateTimeOffset.Now.ToString("dd MMMM yyyy HH:mm:ss");
        }

        private static bool IsAnyProcessRunning(params string[] processNames)
        {
            foreach (string name in processNames)
            {
                Process[] processes = Process.GetProcessesByName(name);
                try
                {
                    if (processes.Length > 0)
                        return true;
                }
                finally
                {
                    foreach (Process process in processes)
                        process.Dispose();
                }
            }

            return false;
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshStatus();

        private void Minimise_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private void OpenLogs_Click(object sender, RoutedEventArgs e)
        {
            string path = FileLog.GetLogDirectory();
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
    }
}
