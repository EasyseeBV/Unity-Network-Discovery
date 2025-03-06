using System;
using Unity.Netcode;

/// <summary>
/// Represents the data structure used for broadcasting information during the local network discovery process.
/// This struct is designed to work with Unity Netcode's networking systems and includes necessary data for secure
/// and reliable discovery communication, such as an authentication token hash, a UNIX timestamp, and a unique nonce.
/// Implements the INetworkSerializable interface to support network serialization.
/// </summary>
public struct DiscoveryBroadcastData : INetworkSerializable
{
    /// <summary>
    /// Represents a hashed authentication token used for validation during network discovery.
    /// </summary>
    /// <remarks>
    /// The AuthTokenHash is computed using the shared secret key and a hashing algorithm
    /// (e.g., SHA-512). It is used to verify the authenticity of a broadcast message in
    /// conjunction with a timestamp and nonce to ensure secure communication.
    /// </remarks>
    public string AuthTokenHash;
    /// <summary>
    /// Represents a timestamp, stored as a long integer, typically used to indicate the
    /// Unix time (seconds elapsed since January 1, 1970, UTC). This variable is utilized
    /// to ensure freshness and prevent replay attacks within authentication workflows.
    /// </summary>
    public long Timestamp;
    /// <summary>
    /// A unique identifier used in the discovery process to ensure each broadcast is unique
    /// and to mitigate replay attacks. It is generated as a GUID and helps validate
    /// the authenticity and freshness of the broadcast data.
    /// </summary>
    public string Nonce;

    /// <summary>
    /// A data structure used for discovery broadcast in Unity's network solutions.
    /// This struct contains information for client-server authentication and discovery communication,
    /// such as hashed authentication tokens, timestamps, and unique identifiers (nonces).
    /// Implements <see cref="INetworkSerializable"/> for serialization and deserialization over the network.
    /// </summary>
    public DiscoveryBroadcastData(string rawKey)
    {
        AuthTokenHash = NetworkUtils.HashKey(rawKey);
        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Nonce = Guid.NewGuid().ToString(); // Generate a unique identifier
    }

    /// <summary>
    /// Serializes or deserializes the DiscoveryBroadcastData structure using a buffer serializer.
    /// </summary>
    /// <typeparam name="T">The type of the buffer serializer, which must implement IReaderWriter.</typeparam>
    /// <param name="serializer">The buffer serializer used for reading from or writing to the serialized data.</param>
    public void NetworkSerialize<T>(BufferSerializer<T> serializer) where T : IReaderWriter
    {
        serializer.SerializeValue(ref AuthTokenHash);
        serializer.SerializeValue(ref Timestamp);
        serializer.SerializeValue(ref Nonce);
    }
}