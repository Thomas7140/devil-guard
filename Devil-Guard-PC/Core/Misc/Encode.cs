using System;
using System.Text;

namespace DevilGuard.Core.Misc
{
    class Encode
    {
        /// <summary>
        /// Base64 encode a string
        /// </summary>
        /// <param name="input">Input text</param>
        /// <returns>Base64 encoded string</returns>
        public static string TextToBase64(string input)
        {
            byte[] b = Encoding.Latin1.GetBytes(input);

            return Convert.ToBase64String(b);
        }

        /// <summary>
        /// Convert a byte array to Base64 string
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <returns>Base64 encoded string</returns>
        public static string TextToBase64(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Convert a byte array to Base64 byte array
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <returns>Base64 encoded byte array</returns>
        public static byte[] BytesToBase64Bytes(byte[] bytes)
        {
            string base64 = Convert.ToBase64String(bytes);

            return Encoding.Latin1.GetBytes(base64);
        }

        /// <summary>
        /// Base64 decode a string
        /// </summary>
        /// <param name="input">Input text</param>
        /// <returns>Base64 decoded string</returns>
        public static string Base64ToText(string input)
        {
            byte[] b = Convert.FromBase64String(input);

            return Encoding.Latin1.GetString(b);
        }

        /// <summary>
        /// Convert a base64 string to a decoded byte array
        /// </summary>
        /// <param name="input">Input text</param>
        /// <returns>Base64 decoded byte array</returns>
        public static byte[] Base64ToBytes(string input)
        {
            return Convert.FromBase64String(input);
        }

        /// <summary>
        /// Convert a base64 byte array to a decoded byte array
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <returns>Base64 decoded byte array</returns>
        public static byte[] Base64BytesToBytes(byte[] bytes)
        {
            string s = Encoding.Latin1.GetString(bytes);

            return Convert.FromBase64String(s);
        }
    }
}
