using System;
using System.Linq;
using System.ServiceProcess;
using System.Threading;

namespace DevilGuard.Sentinel
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (!Environment.UserInteractive && !args.Contains("--console", StringComparer.OrdinalIgnoreCase))
            {
                ServiceBase.Run(new DevilGuardService());
                return 0;
            }

            using DevilGuardService service = new DevilGuardService();
            using ManualResetEventSlim exitSignal = new ManualResetEventSlim(false);

            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                exitSignal.Set();
            };

            Console.WriteLine("Devil-Guard Sentinel is running in console mode.");
            Console.WriteLine("Press Ctrl+C to stop.");

            service.StartInteractive(args);
            exitSignal.Wait();
            service.StopInteractive();
            return 0;
        }
    }
}
