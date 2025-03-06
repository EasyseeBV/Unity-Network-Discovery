using System.IO;
using System.Security.Cryptography;

/// <summary>
/// Provides utilities for encryption and decryption of data using AES.
/// </summary>
public static class EncryptionUtils
{
    // 32-byte (256-bit) key
    /// <summary>
    /// A cryptographic key consisting of 32 bytes (256 bits) utilized for AES encryption and decryption.
    /// This key plays a critical role in securing data by transforming it into a format unreadable without the correct decryption.
    /// It should be safeguarded to prevent unauthorized access and ensure encryption integrity.
    /// </summary>
    private static readonly byte[] Key = new byte[32]
    {
        0x3f, 0x8a, 0x9c, 0x6d, 0x4b, 0x2e, 0x7f, 0x1a,
        0x8d, 0x9c, 0x0b, 0x3e, 0x5f, 0x7a, 0x1c, 0x2d,
        0x3e, 0x4f, 0x6a, 0x9b, 0x0c, 0x1d, 0x2e, 0x3f,
        0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0x0a, 0x1b
    };

    // 16-byte (128-bit) IV
    /// <summary>
    /// A 16-byte (128-bit) initialization vector used in AES encryption and decryption operations.
    /// This vector ensures that the same plaintext encrypted with the same key will produce unique ciphertext,
    /// enhancing the security of the encryption process. It should be kept constant and confidential
    /// to maintain the integrity of encryption and decryption functions.
    /// </summary>
    private static readonly byte[] IV = new byte[16]
    {
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
        0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d
    };

    /// <summary>
    /// Encrypts the specified data using AES encryption with a predefined key and initialization vector.
    /// </summary>
    /// <param name="data">The byte array containing the data to be encrypted.</param>
    /// <returns>A byte array containing the encrypted representation of the input data.</returns>
    public static byte[] Encrypt(byte[] data)
    {
        using Aes aes = Aes.Create();
        aes.Key = Key;
        aes.IV = IV;

        using MemoryStream ms = new();
        using CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }

    /// <summary>
    /// Decrypts the given encrypted data using AES decryption with a predefined key and IV.
    /// </summary>
    /// <param name="encryptedData">The byte array of encrypted data to decrypt.</param>
    /// <returns>The decrypted data as a byte array.</returns>
    public static byte[] Decrypt(byte[] encryptedData)
    {
        using Aes aes = Aes.Create();
        aes.Key = Key;
        aes.IV = IV;

        using MemoryStream ms = new(encryptedData);
        using CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using MemoryStream output = new();
        cs.CopyTo(output);
        return output.ToArray();
    }
}