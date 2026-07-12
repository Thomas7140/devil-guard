using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Windows;
using System.Windows.Media;

namespace DevilGuard.Setup
{
    public partial class MainWindow : Window
    {
        private static readonly System.Collections.Generic.Dictionary<string, string> ExpectedScriptHashes =
            new System.Collections.Generic.Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["install-service.ps1"] = "B0E0B3FACAF9EB7047921ECC6FB59059B95CCFDDFA0D2184D99DA9C454E3B894",
                ["uninstall-service.ps1"] = "9A8A8F3987D3FE66C353AEBD3F1C4C6FD691B799407F1B8229BCF17730F21A0A"
            };

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            LoadGatekeeperConfiguration();
            RefreshStatus();
        }

        private void LoadGatekeeperConfiguration()
        {
            GatekeeperUrlTextBox.Text = Environment.GetEnvironmentVariable("DEVILGUARD_GATEKEEPER_URL", EnvironmentVariableTarget.Machine) ?? string.Empty;
            GatekeeperTokenBox.Password = Environment.GetEnvironmentVariable("DEVILGUARD_GATEKEEPER_TOKEN", EnvironmentVariableTarget.Machine) ?? string.Empty;
        }

        private void RefreshStatus()
        {
            try
            {
                using ServiceController service = new ServiceController("DevilGuardSentinel");
                ServiceStatusText.Text = service.Status.ToString();
                ServiceStatusText.Foreground = service.Status == ServiceControllerStatus.Running ? Brushes.LightGreen : Brushes.Orange;
            }
            catch (InvalidOperationException)
            {
                ServiceStatusText.Text = "Not installed";
                ServiceStatusText.Foreground = Brushes.LightGray;
            }
        }

        private void Install_Click(object sender, RoutedEventArgs e)
        {
            string extraArgs = BuildInstallArguments();
            if (extraArgs == null)
                return;

            RunElevatedScript("install-service.ps1", extraArgs);
        }

        private void Uninstall_Click(object sender, RoutedEventArgs e) => RunElevatedScript("uninstall-service.ps1", string.Empty);

        private string BuildInstallArguments()
        {
            string gatekeeperUrl = (GatekeeperUrlTextBox.Text ?? string.Empty).Trim();
            string gatekeeperToken = (GatekeeperTokenBox.Password ?? string.Empty).Trim();

            if (!string.IsNullOrWhiteSpace(gatekeeperUrl) && !Uri.IsWellFormedUriString(gatekeeperUrl, UriKind.Absolute))
            {
                MessageText.Text = "Gatekeeper URL must be an absolute URL (for example https://example.com/api).";
                MessageText.Foreground = Brushes.Orange;
                return null;
            }

            if (gatekeeperUrl.Contains("\"") || gatekeeperToken.Contains("\""))
            {
                MessageText.Text = "Gatekeeper URL and token cannot contain double-quote characters.";
                MessageText.Foreground = Brushes.Orange;
                return null;
            }

            string args = string.Empty;
            if (!string.IsNullOrWhiteSpace(gatekeeperUrl))
                args += " -GatekeeperUrl \"" + gatekeeperUrl + "\"";

            if (!string.IsNullOrWhiteSpace(gatekeeperToken))
                args += " -GatekeeperToken \"" + gatekeeperToken + "\"";

            return args;
        }

        private void RunElevatedScript(string fileName, string extraArguments)
        {
            string scriptPath = Path.Combine(AppContext.BaseDirectory, "scripts", fileName);
            if (!File.Exists(scriptPath))
            {
                MessageText.Text = "The deployment script was not found: " + scriptPath;
                MessageText.Foreground = Brushes.Orange;
                return;
            }

            if (!VerifyScriptIntegrity(fileName, scriptPath, out string integrityMessage))
            {
                MessageText.Text = integrityMessage;
                MessageText.Foreground = Brushes.OrangeRed;
                return;
            }

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath + "\"" + (extraArguments ?? string.Empty),
                    UseShellExecute = true,
                    Verb = "runas",
                    WorkingDirectory = AppContext.BaseDirectory
                });
                MessageText.Text = "Windows requested administrator approval. Refresh the status after the script completes.";
                MessageText.Foreground = Brushes.LightGreen;
            }
            catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1223)
            {
                MessageText.Text = "Administrator approval was cancelled.";
                MessageText.Foreground = Brushes.Orange;
            }
            catch (Exception exception)
            {
                MessageText.Text = "Could not start the script: " + exception.Message;
                MessageText.Foreground = Brushes.OrangeRed;
            }
        }

        private static bool VerifyScriptIntegrity(string fileName, string scriptPath, out string message)
        {
            if (!ExpectedScriptHashes.TryGetValue(fileName, out string expectedHash))
            {
                message = "The deployment script is not approved for elevation: " + fileName;
                return false;
            }

            using FileStream stream = File.OpenRead(scriptPath);
            string actualHash = Convert.ToHexString(SHA256.HashData(stream));

            if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(actualHash),
                Convert.FromHexString(expectedHash)))
            {
                message = "The deployment script failed integrity verification. Reinstall or restore original scripts before continuing.";
                return false;
            }

            message = string.Empty;
            return true;
        }

        private void OpenFolder_Click(object sender, RoutedEventArgs e) =>
            Process.Start(new ProcessStartInfo(AppContext.BaseDirectory) { UseShellExecute = true });

        private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshStatus();

        private void Close_Click(object sender, RoutedEventArgs e) => Close();
    }
}
