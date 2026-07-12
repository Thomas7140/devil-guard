using System;
using System.ServiceProcess;

namespace DevilGuard.Core.IO
{
    internal static class WMIService
    {
        private const string ServiceName = "winmgmt";

        public static bool EnsureRunning(TimeSpan? timeout = null)
        {
            using ServiceController controller = new ServiceController(ServiceName, Environment.MachineName);
            controller.Refresh();

            if (controller.Status == ServiceControllerStatus.Running)
                return true;

            if (controller.Status == ServiceControllerStatus.Stopped ||
                controller.Status == ServiceControllerStatus.Paused)
            {
                controller.Start();
            }

            controller.WaitForStatus(ServiceControllerStatus.Running, timeout ?? TimeSpan.FromSeconds(15));
            controller.Refresh();
            return controller.Status == ServiceControllerStatus.Running;
        }

        public static bool SortWMI()
        {
            try
            {
                return EnsureRunning();
            }
            catch
            {
                return false;
            }
        }
    }
}
