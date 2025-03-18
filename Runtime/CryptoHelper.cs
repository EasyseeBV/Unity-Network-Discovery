using System;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;

namespace Network_Discovery
{
    public static class CryptoHelper
    {
        public static byte[] PrepareAesKey(string key, int desiredSize)
        {
            byte[] keyBytes = new byte[desiredSize];
            byte[] rawBytes = Encoding.UTF8.GetBytes(key);
            for (int i = 0; i < desiredSize; i++)
            {
                keyBytes[i] = i < rawBytes.Length ? rawBytes[i] : (byte)0;
            }
            return keyBytes;
        }

        public static byte[] EncryptBytes(byte[] data, string key)
        {
            if (data == null || data.Length == 0) return new byte[0];
            using (Aes aes = Aes.Create())
            {
                aes.Key = PrepareAesKey(key, 32); // AES-256
                aes.IV = new byte[16]; // FIXED IV for demonstration; use a random IV in production
                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public static byte[] DecryptBytes(byte[] encryptedData, string key)
        {
            if (encryptedData == null || encryptedData.Length == 0) return new byte[0];
            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = PrepareAesKey(key, 32);
                    aes.IV = new byte[16]; // Must match the IV used in encryption
                    using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                    }
                }
            }
            catch (CryptographicException ex)
            {
                Debug.LogWarning($"[CryptoHelper] Decryption failed: {ex.Message}");
                return null; // Return null to signal decryption failure.
            }
        }

        public static string EncryptString(string text, string key)
        {
            byte[] encryptedBytes = EncryptBytes(Encoding.UTF8.GetBytes(text), key);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static string DecryptString(string encryptedText, string key)
        {
            byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
            byte[] decryptedBytes = DecryptBytes(encryptedBytes, key);
            return decryptedBytes != null ? Encoding.UTF8.GetString(decryptedBytes) : null;
        }
    }
}
