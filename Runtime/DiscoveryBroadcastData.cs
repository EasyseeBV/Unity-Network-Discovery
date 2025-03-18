using System;
using Unity.Netcode;

namespace Network_Discovery
{
    /// <summary>
    /// Represents the data structure used for broadcasting information during the local network discovery process.
    /// This struct is designed to work with Unity Netcode's networking systems and includes necessary data for secure
    /// and reliable discovery communication, such as an authentication token hash, a UNIX timestamp, a unique nonce,
    /// and an optional MAC address for client registry purposes.
    /// Implements the INetworkSerializable interface to support network serialization.
    /// </summary>
    public struct DiscoveryBroadcastData : INetworkSerializable
    {
        /// <summary>
        /// A hashed authentication token used for validation during network discovery.
        /// </summary>
        public string AuthTokenHash;
        /// <summary>
        /// A UNIX timestamp (seconds elapsed since January 1, 1970 UTC).
        /// </summary>
        public long Timestamp;
        /// <summary>
        /// A unique identifier (GUID) to ensure each broadcast is unique and help mitigate replay attacks.
        /// </summary>
        public string Nonce;
        /// <summary>
        /// (Optional) The client's MAC address. This field is used if the client registry feature is enabled.
        /// Otherwise, it remains an empty string.
        /// </summary>
        public string MacAddress;

        /// <summary>
        /// Constructs a DiscoveryBroadcastData without a MAC address.
        /// </summary>
        /// <param name="rawKey">The raw shared key.</param>
        public DiscoveryBroadcastData(string rawKey)
        {
            AuthTokenHash = NetworkUtils.HashKey(rawKey);
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Nonce = Guid.NewGuid().ToString();
            MacAddress = string.Empty;
        }

        /// <summary>
        /// Constructs a DiscoveryBroadcastData with a MAC address.
        /// Use this constructor when the client registry feature is enabled.
        /// </summary>
        /// <param name="rawKey">The raw shared key.</param>
        /// <param name="macAddress">The client's MAC address.</param>
        public DiscoveryBroadcastData(string rawKey, string macAddress)
        {
            AuthTokenHash = NetworkUtils.HashKey(rawKey);
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Nonce = Guid.NewGuid().ToString();
            MacAddress = macAddress;
        }

        /// <summary>
        /// Serializes or deserializes the DiscoveryBroadcastData structure.
        /// </summary>
        /// <typeparam name="T">The type of the buffer serializer.</typeparam>
        /// <param name="serializer">The buffer serializer used for reading or writing the data.</param>
        public void NetworkSerialize<T>(BufferSerializer<T> serializer) where T : IReaderWriter
        {
            serializer.SerializeValue(ref AuthTokenHash);
            serializer.SerializeValue(ref Timestamp);
            serializer.SerializeValue(ref Nonce);
            serializer.SerializeValue(ref MacAddress);
        }
    }
}