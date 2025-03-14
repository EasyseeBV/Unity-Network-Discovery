using System;
using System.Security.Cryptography;
using System.Text;

namespace Network_Discovery
{
    /// <summary>
    /// Provides utility methods for network-related operations.
    /// </summary>
    public static class NetworkUtils
    {
        /// <summary>
        /// Computes the SHA-512 hash of a given string and returns the hash as a 128-character hexadecimal string.
        /// </summary>
        /// <param name="key">The input string to be hashed. If the input is null or empty, a default 128-character string of zeroes is returned.</param>
        /// <returns>A 128-character hexadecimal string representing the SHA-512 hash of the input string. If the input is null or empty, it returns the default hash string.</returns>
        public static string HashKey(string key)
        {
            if (string.IsNullOrEmpty(key))
                return new string('0', 128); // Default to a 128-char string of zeroes

            int maxLength = 16;
            if (key.Length > maxLength)
            {
                key = key.Substring(0, maxLength);
            }

            using SHA512 sha512 = SHA512.Create();
            byte[] hashBytes = sha512.ComputeHash(Encoding.UTF8.GetBytes(key));
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower(); // 128-char hex string
        }

    }
}