using System;
using Unity.Netcode;

namespace Network_Discovery
{
    /// <summary>
    /// Represents a response structure used in network discovery operations within Unity Netcode solutions.
    /// This struct is utilized for exchanging network information, such as authorization details and connection port,
    /// between devices during discovery processes. It supports serialization for network communication.
    /// </summary>
    public struct DiscoveryResponseData : INetworkSerializable
    {
        /// <summary>
        /// Represents the network port used for communication in a discovery response.
        /// </summary>
        /// <remarks>
        /// This port is specified in the server's response during network discovery and is used
        /// by the client to establish a connection to the server.
        /// </remarks>
        public ushort Port;
        /// <summary>
        /// Represents the hashed authentication token used to validate communication
        /// between clients and servers in a networked environment.
        /// </summary>
        /// <remarks>
        /// The value of this property is generated using the SHA-512 hashing algorithm,
        /// which provides a high level of security by transforming the raw authentication
        /// key into a fixed-length, 128-character hexadecimal string. This ensures
        /// that sensitive keys are never transmitted in their plain form, reducing
        /// the risk of interception or unauthorized access.
        /// </remarks>
        /// <example>
        /// The hash is typically computed using the <c>NetworkUtils.HashKey</c> method
        /// and compared during network communication to verify the authenticity of
        /// the connecting parties.
        /// </example>
        public string AuthTokenHash;

        /// <summary>
        /// Represents the response data structure used in the network discovery process.
        /// This structure is responsible for encapsulating the response information,
        /// which includes the port for network communication and a hashed authentication token.
        /// </summary>
        public DiscoveryResponseData(string rawKey, ushort port)
        {
            AuthTokenHash = NetworkUtils.HashKey(rawKey);
            Port = port;
        }

        /// <summary>
        /// Serializes and deserializes the network data for the DiscoveryResponseData structure.
        /// </summary>
        /// <typeparam name="T">Type that implements IReaderWriter, used for serialization and deserialization.</typeparam>
        /// <param name="serializer">An instance of BufferSerializer used to perform the serialization or deserialization.</param>
        /// <exception cref="OverflowException">Thrown if there is not enough data in the buffer for deserialization</exception>
        public void NetworkSerialize<T>(BufferSerializer<T> serializer) where T : IReaderWriter
        {
            if (serializer.IsReader)
            {
                if (!serializer.GetFastBufferReader().TryBeginRead(128)) // Prevent overflow
                    throw new OverflowException("Not enough data in buffer for string length.");

                serializer.SerializeValue(ref AuthTokenHash);
                serializer.SerializeValue(ref Port);
            }
            else
            {
                serializer.SerializeValue(ref AuthTokenHash);
                serializer.SerializeValue(ref Port);
            }
        }
    }
}