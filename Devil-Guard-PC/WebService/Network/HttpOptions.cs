using System;

namespace DevilGuard.WebService.Network
{
    public static class HttpOptions
    {
        public static Uri BaseAddress { get; set; }
        public static TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
        public static string ApiAuthorization { get; set; } = string.Empty;
        public static string ApiToken { get; set; } = string.Empty;
        public static bool AllowInsecureLocalhost { get; set; } = false;
    }
}
