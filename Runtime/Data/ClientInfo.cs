using System;
using Unity.Collections;
using Unity.Netcode;
using UnityEngine;

namespace Network_Discovery
{
    public struct ClientInfo : INetworkSerializable
    {
        // Plaintext fields (in memory)
        public string MacAddress;
        public long LastSeenTicks; // stores DateTime.Now.Ticks
        public ulong CurrentClientId;

        // Property to get LastSeen as DateTime
        public DateTime LastSeen => new DateTime(LastSeenTicks);

        public ClientInfo(string mac)
        {
            MacAddress = mac;
            LastSeenTicks = DateTime.Now.Ticks;
            CurrentClientId = ulong.MaxValue;
            _encryptedPayload = null;
        }

        // Private field used only during serialization
        private byte[] _encryptedPayload;

        public void NetworkSerialize<T>(BufferSerializer<T> serializer) where T : IReaderWriter
        {
            if (serializer.IsWriter)
            {
                // Write plaintext fields to a temporary buffer
                using (FastBufferWriter tempWriter = new FastBufferWriter(256, Allocator.Temp))
                {
                    tempWriter.WriteValueSafe(MacAddress);
                    tempWriter.WriteValueSafe(LastSeenTicks);
                    tempWriter.WriteValueSafe(CurrentClientId);

                    // Get the raw bytes
                    byte[] plainData = tempWriter.ToArray();

                    // Encrypt the data using the shared key from NetworkDiscovery
                    string key = NetworkDiscovery.SharedKey;
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
                {
                    _encryptedPayload = new byte[length];
                }
                serializer.SerializeValue(ref _encryptedPayload);

                // Decrypt the payload
                string key = NetworkDiscovery.SharedKey;
                byte[] plainData = CryptoHelper.DecryptBytes(_encryptedPayload, key);

                // Read the fields from the decrypted data
                using (FastBufferReader tempReader = new FastBufferReader(plainData, Allocator.Temp))
                {
                    tempReader.ReadValueSafe(out MacAddress);
                    tempReader.ReadValueSafe(out LastSeenTicks);
                    tempReader.ReadValueSafe(out CurrentClientId);
                }
            }
        }
    }
}
