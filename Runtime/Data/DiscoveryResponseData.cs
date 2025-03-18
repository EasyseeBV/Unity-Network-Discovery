using System;
using Unity.Collections;
using Unity.Netcode;
using UnityEngine;

namespace Network_Discovery
{
    public struct DiscoveryResponseData : INetworkSerializable
    {
        public ushort Port;
        public string AuthTokenHash;

        public DiscoveryResponseData(string rawKey, ushort port)
        {
            AuthTokenHash = CryptoHelper.EncryptString("authToken", rawKey);
            Port = port;
            _encryptedPayload = null;
        }

        private byte[] _encryptedPayload;

        public void NetworkSerialize<T>(BufferSerializer<T> serializer) where T : IReaderWriter
        {
            string key = NetworkDiscovery.SharedKey;
            if (serializer.IsWriter)
            {
                using (FastBufferWriter tempWriter = new FastBufferWriter(64, Allocator.Temp))
                {
                    tempWriter.WriteValueSafe(Port);
                    tempWriter.WriteValueSafe(AuthTokenHash);

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
                    Port = 0;
                    AuthTokenHash = "";
                    Debug.LogWarning("[DiscoveryResponseData] Decryption returned null; using default values.");
                    return;
                }

                using (FastBufferReader tempReader = new FastBufferReader(plainData, Allocator.Temp))
                {
                    tempReader.ReadValueSafe(out Port);
                    tempReader.ReadValueSafe(out AuthTokenHash);
                }
            }
        }
    }
}
