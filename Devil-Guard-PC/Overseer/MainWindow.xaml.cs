using DevilGuard.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Windows;
using System.Windows.Media;

namespace DevilGuard.Overseer
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            FileLog.Write("overseer", "Overseer started.");
            RefreshStatus();
        }

        private void RefreshStatus()
        {
            RefreshServiceStatus();
            bool gameRunning = IsAnyProcessRunning("dfbhd", "dfbhdlc");
            GameStatusText.Text = gameRunning ? "Game running" : "Game not detected";
            GameStatusText.Foreground = gameRunning ? Brushes.LightGreen : Brushes.LightGray;
            RefreshTimeText.Text = "Updated " + DateTimeOffset.Now.ToString("dd MMMM yyyy HH:mm:ss");
        }

        private void RefreshServiceStatus()
        {
            try
            {
                using ServiceController service = new ServiceController("DevilGuardSentinel");
                ServiceControllerStatus status = service.Status;
                ServiceStatusText.Text = status.ToString();
                ServiceStatusText.Foreground = status == ServiceControllerStatus.Running ? Brushes.LightGreen : Brushes.Orange;
                ServiceDetailText.Text = "Service name: DevilGuardSentinel";
            }
            catch (InvalidOperationException)
            {
                ServiceStatusText.Text = "Not installed";
                ServiceStatusText.Foreground = Brushes.LightGray;
                ServiceDetailText.Text = "Use Devil-Guard Setup or the included PowerShell installation script.";
            }
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

        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private void OpenLogs_Click(object sender, RoutedEventArgs e)
        {
            string path = FileLog.GetLogDirectory();
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
    }
}
