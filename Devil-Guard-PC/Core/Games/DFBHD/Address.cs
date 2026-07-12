namespace DevilGuard.Core.Games.DFBHD
{
    class Address
    {
        public const int Playername = 0xECE2A8; // 16 Text
        public const int Servername = 0xA033CC; // 37 Text
        public const int Serverip = 0x9DDA50; // 15 Text
        public const int Serverport = 0x9DDA70; // 5 Text
        public const int Missiontimer = 0x9F373E; // 8 Bytes
        public const int LastMessage = 0x876008; // 60 Text
        public const int LastAction = 0x71F2A8; // 60 Text
        public const int ChatboxOpen = 0x879B40; // 1 Byte
        public const int ServerPlayerList = 0x7C6574; // 16 Text
        public const int F4Scope = 0xA34338; // 1 Byte

        // In regards to mybase
        public const int MyBase = 0x96C290;
        public const int MyBase_Alive = 0x20; // 1 Byte
        public const int MyBase_Name = 0xC8; // 16 Text
        public const int MyBase_Health = 0xE2; // 1 Byte

        // In regards to hostbase
        public const int HostBase = 0x715900;
        public const int HostBase_SlotDiff = 668;
        public const int HostBase_Playername = 200; // 16 Text
        public const int HostBase_Slot = 292; // 1 Byte

        // In regards to server ip pointer
        public const int ServerIpPointer_Base = 0xECE244;
        public const int ServerIpPointer_SlotDiff = 36;

        // Host screen information
        public const int Host_Servername = 0xA34417; // 37 Text
    }
}
