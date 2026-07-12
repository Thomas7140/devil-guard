using System;

namespace DevilGuard.Core.Games
{
    interface IGame
    {
        /// <summary>
        /// Gets or sets the process ID
        /// </summary>
        int ProcessId { get; set; }

        /// <summary>
        /// Returns the short game name (tag)
        /// </summary>
        string GameName { get; }

        /// <summary>
        /// Returns the full name for display to user
        /// </summary>
        string DisplayName { get; }

        /// <summary>
        /// Gets or sets the process hash
        /// </summary>
        string ProcessHash { get; set; }

        /// <summary>
        /// Gets or sets the process handle
        /// </summary>
        IntPtr ProcessHandle { get; set; }

        /// <summary>
        /// Flag whether the user has been notified of this game being detected/logged
        /// </summary>
        bool Notified { get; set; }

        /// <summary>
        /// Returns a value depicting whether this game is running
        /// </summary>
        /// <returns>True on running</returns>
        bool IsGameRunning();

        /// <summary>
        /// Returns a value indicating whether the user is interacting with this game
        /// </summary>
        /// <returns>True if user is ingame</returns>
        bool IsInGame();

        /// <summary>
        /// Returns a value indicating whether the user is actively playing this game
        /// </summary>
        /// <returns>True if user is actively playing</returns>
        bool IsPlaying();

        /// <summary>
        /// Returns the playername read from this game's memory
        /// </summary>
        /// <returns>Playername as string</returns>
        string GetPlayerName();

        /// <summary>
        /// Returns the servername read from this game's memory
        /// </summary>
        /// <returns>Servername string</returns>
        string GetServerName();

        /// <summary>
        /// Returns the server IP read from this game's memory
        /// </summary>
        /// <returns>Server IP as string</returns>
        string GetServerIp();

        /// <summary>
        /// Returns a value whether the game is being hooked through DirectX
        /// </summary>
        /// <returns>True if game is being hooked</returns>
        bool IsGameHooked();
    }
}
