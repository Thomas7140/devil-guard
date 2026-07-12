namespace DevilGuard.Core.Games.DFBHD
{
    internal static class Base
    {
        public const string DisplayName = "Delta Force: Black Hawk Down";
        public const string GameName = "DFBHD";
        public static readonly byte[] DefaultD3dMemory = { 0x8B, 0xFF, 0x55, 0x8B, 0xEF };

        public static readonly string[] SupportedExecutables =
        {
            "dfbhd.exe",
            "dfbhdlc.exe"
        };
    }
}
