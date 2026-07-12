using System;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;

namespace DevilGuard.WebService.Network
{
    internal static class Check
    {
        public static bool ConnectedState()
        {
            return NetworkInterface.GetIsNetworkAvailable();
        }

        public static bool DetectProxy(string url)
        {
            Uri destination = new Uri(url, UriKind.Absolute);
            IWebProxy proxy = HttpClient.DefaultProxy;
            Uri proxyAddress = proxy.GetProxy(destination);
            return proxyAddress != null && proxyAddress != destination;
        }

        public static bool ServerOnline(string url)
        {
            try
            {
                Uri destination = new Uri(url, UriKind.Absolute);
                bool local = destination.IsLoopback || destination.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
                if (!destination.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                    !(local && HttpOptions.AllowInsecureLocalhost))
                {
                    return false;
                }

                using HttpClient client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Head, destination);
                using HttpResponseMessage response = client.Send(request);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}
