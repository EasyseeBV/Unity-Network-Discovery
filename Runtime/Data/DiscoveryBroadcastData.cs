using System;
using Unity.Collections;
using Unity.Netcode;
using UnityEngine;

namespace Network_Discovery
{
    public struct DiscoveryBroadcastData : INetworkSerializable
    {
        public string AuthTokenHash;
        public long Timestamp;
        public string Nonce;
        public string MacAddress;

        public DiscoveryBroadcastData(string rawKey)
        {
            // Instead of hashing, we encrypt "authToken" with the shared key.
            AuthTokenHash = CryptoHelper.EncryptString("authToken", rawKey);
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Nonce = Guid.NewGuid().ToString();
            MacAddress = string.Empty;
            _encryptedPayload = null;
        }

        public DiscoveryBroadcastData(string rawKey, string macAddress)
        {
            AuthTokenHash = CryptoHelper.EncryptString("authToken", rawKey);
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Nonce = Guid.NewGuid().ToString();
            MacAddress = macAddress;
            _encryptedPayload = null;
        }

        private byte[] _encryptedPayload;

        public void NetworkSerialize<T>(BufferSerializer<T> serializer) where T : IReaderWriter
        {
            string key = NetworkDiscovery.SharedKey;
            if (serializer.IsWriter)
            {
                using (FastBufferWriter tempWriter = new FastBufferWriter(256, Allocator.Temp))
                {
                    tempWriter.WriteValueSafe(AuthTokenHash);
                    tempWriter.WriteValueSafe(Timestamp);
                    tempWriter.WriteValueSafe(Nonce);
                    tempWriter.WriteValueSafe(MacAddress);

                    byte[] plainData = tempWriter.ToArray();

                    _encryptedPayload = CryptoHelper.EncryptBytes(plainData, key);

                    int length = _encryptedPayload.Length;
                    serializer.SerializeValue(ref length);
                    serializer.SerializeValue(ref _encryptedPayload);
                }
            }
            else
            {
                int length = 0;
                serializer.SerializeValue(ref length);
                if (_encryptedPayload == null || _encryptedPayload.Length != length)
                    _encryptedPayload = new byte[length];
                serializer.SerializeValue(ref _encryptedPayload);

                byte[] plainData = CryptoHelper.DecryptBytes(_encryptedPayload, key);
                if (plainData == null)
                {
                    // Gracefully set default values if decryption fails.
                    AuthTokenHash = "";
                    Timestamp = 0;
                    Nonce = "";
                    MacAddress = "";
                    Debug.LogWarning("[DiscoveryBroadcastData] Decryption returned null; using default values.");
                    return;
                }

                using (FastBufferReader tempReader = new FastBufferReader(plainData, Allocator.Temp))
                {
                    tempReader.ReadValueSafe(out AuthTokenHash);
                    tempReader.ReadValueSafe(out Timestamp);
                    tempReader.ReadValueSafe(out Nonce);
                    tempReader.ReadValueSafe(out MacAddress);
                }
            }
        }
    }
}
