// DiscoveryBroadcastData.cs
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
                using (var tempWriter = new FastBufferWriter(256, Allocator.Temp))
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
                    AuthTokenHash = "";
                    Timestamp = 0;
                    Nonce = "";
                    MacAddress = "";
                    Debug.LogWarning("[DiscoveryBroadcastData] Decryption failed; using defaults.");
                    return;
                }

                using (var tempReader = new FastBufferReader(plainData, Allocator.Temp))
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

/* Huidig systeem:
 * 1. UDP Broadcast Ping De client stuurt een broadcast (255.255.255.255:47777) met daarin het versleuteld AuthToken,
 * een nonce en optioneel zijn MAC.
 *
 * 2. Server luistert op poort 47777 bOmdat de socket gebonden is op 0.0.0.0: 47777 (bindAny) of een specifiek adres:
 * 47777, krijgt hij elke ping binnen, ongeacht welke NIC.
 * 
 * 3. Verwerking door de server AuthToken: klopt het met de SharedKey?
 * Nonce/Timestamp: nog niet gezien en niet te oud? Subnet-keuze:
 * bepaal via GetLocalAddressFor(sender) welke eigen IP in hetzelfde subnet zit als de client.
 *
 * 4. De server stuurt een unicast terug naar het bronadres van de ping, met daarin de IP waarin 'gehost' wordt en de port
 *
 * 5. Client ontvangt de response
 * De client ziet nu exact welk IP en poort hij moet gebruiken om de Netcode-verbinding te maken.
 *
 * 6. Configureer UnityTransport
 * transport.SetConnectionData(ServerAddress, Port)
 *
 * 7. Start Netcode client
 * networkManager.StartClient()
 *
 * 8. Server accepteert verbinding
 * De standaard Netcode handshake vangt daarna de TCP/UDP game-sessie op.
 * 
 */