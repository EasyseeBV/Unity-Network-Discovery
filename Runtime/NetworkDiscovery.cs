using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Unity.Collections;
using Unity.Netcode;
using Unity.Netcode.Transports.UTP;
using UnityEngine;

namespace Network_Discovery
{
    public class NetworkDiscovery : MonoBehaviour
    {
        /// <summary>
        /// A static event invoked when a new MAC address is registered or updated in the client registry.
        /// </summary>
        /// <remarks>
        /// Server-only
        /// This event provides a mechanism to notify subscribers whenever a MAC address is successfully
        /// registered or updated in the internal registry. It carries two parameters:
        /// the unique network ID of the client and the MAC address being registered.
        /// </remarks>
        /// <param name="ulong">
        /// The unique network ID of the client associated with the registered MAC address.
        /// </param>
        /// <param name="string">
        /// The MAC address of the client that has been registered or updated.
        /// </param>
        public static event Action<ulong, string> OnMacAddressRegistered;
        
        #region Fields & Properties

        public static string SharedKey { get; private set; } = "mySecretKey";
        public static void SetSharedKey(string key) => SharedKey = key;
        
        

        [Header("Network Role")]
        [Tooltip("Specifies the role of the network (Server or Client).")]
        public NetworkRole role = NetworkRole.Server;

        [Header("Timing")]
        [Tooltip("Interval in seconds at which clients will ping the local network.")]
        [SerializeField] private float clientBroadcastPingInterval = 3f;
        [Tooltip("Delay after server-start that server broadcasts its presence.")]
        [SerializeField] private float serverBroadcastDelay = 3f;
        [Tooltip("Delay after start that client broadcasts, looking for servers.")]
        [SerializeField] private float clientBroadcastDelay = 3f;

        [Header("References")]
        [Tooltip("NetworkManager controlling the netcode behavior.")]
        [SerializeField] private NetworkManager networkManager;
        [Tooltip("UTP transport layer for netcode communication.")]
        [SerializeField] private UnityTransport transport;

        [Header("Broadcast Port")]
        [Tooltip("The port used for sending/receiving network discovery broadcasts.")]
        [SerializeField] private ushort port = 47777;

        [Header("Client Registry (Optional)")]
        [Tooltip("If true, clients will include their MAC address in broadcasts and the server will maintain a registry.")]
        [SerializeField] private bool enableClientRegistry = true;

        private readonly NonceManager _nonceManager = new();
        private UdpClient _client;
        private CancellationTokenSource _cancellationTokenSource;
        private NetworkReachability _lastReachability;
        private readonly Dictionary<string, ClientInfo> _clientRegistry = new();

        public bool IsServer { get; private set; }
        public bool IsClient { get; private set; }
        private ushort Port => port;

        private enum MessageType : byte
        {
            BroadCast = 0,
            Response = 1
        }

        #endregion

        #region Unity Lifecycle Methods

        private void Awake()
        {
            if (!transport) transport = FindFirstObjectByType<UnityTransport>();
            if (!networkManager) networkManager = FindFirstObjectByType<NetworkManager>();
        }

        private void OnEnable()
        {
            networkManager.OnServerStarted += OnServerStarted;
            networkManager.OnConnectionEvent += OnConnectionEvent;
            networkManager.OnServerStopped += HandleConnectionChange;
            networkManager.OnClientStopped += HandleConnectionChange;
        }

        private void Start() => StartConnection();

        private void OnDisable()
        {
            StopAllCoroutines();
            StopDiscovery();
            networkManager.OnServerStarted -= OnServerStarted;
            networkManager.OnConnectionEvent -= OnConnectionEvent;
            networkManager.OnServerStopped -= HandleConnectionChange;
            networkManager.OnClientStopped -= HandleConnectionChange;
        }
        
        #endregion

        #region Event & Connection Handlers

        /// Handles a network connection event, such as a client connecting to the server.
        /// <param name="manager">The NetworkManager instance managing the netcode behavior.</param>
        /// <param name="data">The event data containing information about the connection event, including the client ID and event type.</param>
        private void OnConnectionEvent(NetworkManager manager, ConnectionEventData data)
        {
            if (data.EventType == ConnectionEvent.ClientConnected)
            {
                Debug.Log($"A client has connected with PID {data.ClientId}");

                if (data.ClientId == networkManager.LocalClientId)
                    SendMacHandshake();
            }
        }

        /// <summary>
        /// Called when the network server starts successfully.
        /// This method registers a custom message handler for incoming client handshake messages
        /// and initiates the discovery process for server availability.
        /// </summary>
        private void OnServerStarted()
        {
            NetworkManager.Singleton.CustomMessagingManager
                .RegisterNamedMessageHandler("ClientMacHandshake", OnMacHandshakeMessageReceived);

            StartCoroutine(StartDiscovery(true, serverBroadcastDelay));
        }

        /// Handles the changes in the network connection status for the server or client.
        /// <param name="cleanChange">
        /// A boolean value indicating whether the connection change should be a clean change.
        /// Default is true, meaning the change will be handled cleanly without abrupt disconnections.
        /// </param>
        private void HandleConnectionChange(bool cleanChange = true) => StartConnection();

        /// <summary>
        /// Initiates the network connection process based on the current network role and reachability status.
        /// </summary>
        /// <remarks>
        /// Checks if the local network is reachable and determines whether to start hosting the game
        /// or initiate client broadcasts depending on the assigned network role (Server or Client).
        /// If the network is unreachable, the process terminates prematurely. If the NetworkManager is
        /// already active, it will be stopped before proceeding to ensure a clean transition.
        /// The method also handles restarting the reachability checks and coroutine processes as applicable.
        /// </remarks>
        private void StartConnection()
        {
            if (NetworkManager.Singleton && NetworkManager.Singleton.IsListening)
            {
                Debug.Log("[NetworkDiscovery] Stopping NetworkManager before making changes.");
                NetworkManager.Singleton.Shutdown();
                StopDiscovery();
            }

            StopAllCoroutines();
            _lastReachability = Application.internetReachability;
            StartCoroutine(NetworkReachabilityCheckCR());
            if (_lastReachability == NetworkReachability.NotReachable) return;

            if (role == NetworkRole.Server) HostGame();
            else StartCoroutine(ClientBroadcastCR());
        }

        /// <summary>
        /// Initializes and starts hosting a game on the local network.
        /// </summary>
        /// <remarks>
        /// This method retrieves the local IP address, updates the transport layer connection
        /// data with the IP address and port, and starts a server instance using the NetworkManager.
        /// It is used when the network role is configured as a server in the NetworkDiscovery component.
        /// </remarks>
        private void HostGame()
        {
            var localIp = GetLocalIPAddress();
            transport.SetConnectionData(localIp, transport.ConnectionData.Port);
            Debug.Log($"[LocalNetworkDiscovery] Hosting on IP: {localIp}, Port: {transport.ConnectionData.Port}");
            networkManager.StartServer();
        }

        /// <summary>
        /// Handles client-side network broadcasting to discover available servers on the network.
        /// Continuously sends broadcast messages after an initial delay, attempting to find and establish
        /// a connection with a server.
        /// </summary>
        /// <returns>
        /// An enumerator used to manage the coroutine, which periodically sends broadcasts until a server is discovered.
        /// </returns>
        private IEnumerator ClientBroadcastCR()
        {
            yield return StartCoroutine(StartDiscovery(false, clientBroadcastDelay));
            WaitForSeconds wait = new WaitForSeconds(clientBroadcastPingInterval);
            while (!networkManager.IsConnectedClient)
            {
                Debug.Log("[LocalNetworkDiscovery] Sending client broadcast...");
                ClientBroadcast(CreateBroadcastData());
                yield return wait;
            }

            StopDiscovery();
            Debug.Log("[LocalNetworkDiscovery] Found server, stopped discovery.");
        }

        #endregion

        #region Messaging & Handshake

        /// Handles the reception of a message containing a handshake with a client MAC address.
        /// This method attempts to decrypt the received message using the shared key and then
        /// registers the client's MAC address to associate it with the provided client ID.
        /// If decryption fails or the MAC address is invalid, the message is ignored.
        /// <param name="senderClientId">The unique ID of the client sending the handshake message.</param>
        /// <param name="reader">A FastBufferReader containing the serialized handshake message data.</param>
        private void OnMacHandshakeMessageReceived(ulong senderClientId, FastBufferReader reader)
        {
            try
            {
                reader.ReadValueSafe(out uint payloadSize);
                byte[] encryptedBytes = new byte[payloadSize];

                for (int i = 0; i < payloadSize; i++)
                {
                    reader.ReadValueSafe(out encryptedBytes[i]);
                }

                string decryptedMac = null;
                byte[] decryptedBytes = CryptoHelper.DecryptBytes(encryptedBytes, SharedKey);
                if (decryptedBytes != null)
                {
                    decryptedMac = Encoding.UTF8.GetString(decryptedBytes);
                }
                else
                {
                    Debug.LogWarning("[Server] Decryption failed due to mismatched key. Ignoring message.");
                    return;
                }

                if (!string.IsNullOrEmpty(decryptedMac))
                {
                    RegisterClientMac(senderClientId, decryptedMac);
                }
            }
            catch (Exception ex)
            {
                Debug.LogError($"[Server] Error reading handshake message: {ex}");
            }
        }

        /// Sends a handshake message containing the MAC address of the client to the server in a secure manner.
        /// This method encrypts the MAC address using a shared key and sends it to the server as part of a custom message.
        /// Preconditions:
        /// - The client must be connected (`IsConnectedClient` must be true).
        /// Workflow:
        /// - Retrieves the client’s MAC address.
        /// - Encrypts the MAC address using the shared secret key.
        /// - Serializes the encrypted data into a buffer for transmission.
        /// - Sends the buffer to the server using the "ClientMacHandshake" custom message channel.
        /// Logging:
        /// - Logs warnings if the client is not yet connected.
        /// - Logs the success of the handshake message transmission and the details of the MAC address sent.
        /// Note:
        /// - Ensure that the shared key is correctly set before invoking this method.
        private void SendMacHandshake()
        {
            if (!NetworkManager.Singleton.IsConnectedClient)
            {
                Debug.LogWarning("[Client] Not connected yet; cannot send handshake.");
                return;
            }

            string mac = GetMacAddress();
            byte[] plainData = Encoding.UTF8.GetBytes(mac);
            byte[] encryptedData = CryptoHelper.EncryptBytes(plainData, SharedKey);
            uint size = (uint)encryptedData.Length;
            using FastBufferWriter writer = new FastBufferWriter((int)size + sizeof(uint), Allocator.Temp);
            writer.WriteValueSafe(size);
            writer.WriteBytesSafe(encryptedData, (int)size);
            NetworkManager.Singleton.CustomMessagingManager
                .SendNamedMessage("ClientMacHandshake", NetworkManager.ServerClientId, writer);
            Debug.Log($"{networkManager.LocalClientId} sent handshake message to server with MAC {mac}");
        }

        /// Registers a client's MAC address to the client registry.
        /// If the MAC address already exists in the registry, updates the corresponding client information
        /// with the new network ID and timestamp. If it does not exist, creates a new entry in the registry
        /// with the provided client ID and MAC address.
        /// <param name="clientId">
        /// The unique client network ID to associate with the provided MAC address.
        /// </param>
        /// <param name="mac">
        /// The unique MAC address of the client to be registered or updated in the registry.
        /// </param>
        private void RegisterClientMac(ulong clientId, string mac)
        {
            // If _clientRegistry already knows of this MAC-address...
            if (_clientRegistry.TryGetValue(mac, out ClientInfo info))
            {
                string previous = info.CurrentClientId == ulong.MaxValue ? "Unassigned" : info.CurrentClientId.ToString();
        
                Debug.Log($"Old network-id for MAC {mac} was {previous}, new id is {clientId}.");
                info = new ClientInfo(info.MacAddress)
                {
                    LastSeenTicks = DateTime.Now.Ticks,
                    CurrentClientId = clientId
                };
                _clientRegistry[mac] = info;
                Debug.Log($"[ClientRegistry] MAC address recognized from broadcast- or previous connection. " +
                          $"Linked MAC={mac} to PID={clientId}.");
            }
            else
            {
                var newInfo = new ClientInfo(mac)
                {
                    CurrentClientId = clientId
                };
                _clientRegistry[mac] = newInfo;
                Debug.Log($"[ClientRegistry] Registered new MAC={mac} and assigned PID={clientId}.");
            }
        
            OnMacAddressRegistered?.Invoke(clientId, mac);
        }

        #endregion

        #region Network Discovery & Broadcast

        /// <summary>
        /// Starts the network discovery process, allowing for either server or client discovery mode.
        /// </summary>
        /// <param name="serverMode">Indicates whether the discovery process is running as a server (true) or as a client (false).</param>
        /// <param name="initialDelay">The initial delay in seconds before the discovery process starts. Default is 0f.</param>
        /// <returns>An IEnumerator used for coroutine execution to manage the discovery process.</returns>
        private IEnumerator StartDiscovery(bool serverMode, float initialDelay = 0f)
        {
            StopDiscovery();
            IsServer = serverMode;
            IsClient = !serverMode;
            yield return new WaitForSeconds(initialDelay);
            _cancellationTokenSource = new CancellationTokenSource();
            
            // Create the UDP socket manually to set options
            Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            // Set options to allow reuse of address and port
            udpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udpSocket.ExclusiveAddressUse = false; // Ensures other sockets can bind if needed

            // Bind socket to the appropriate endpoint
            udpSocket.Bind(new IPEndPoint(IPAddress.Any, serverMode ? port : 0));

            // Assign socket to UdpClient
            _client = new UdpClient { Client = udpSocket, EnableBroadcast = true, MulticastLoopback = false};
            
            _ = ListenAsync(_cancellationTokenSource.Token, serverMode ? ReceiveBroadcastAsync : ReceiveResponseAsync);
            Debug.Log($"[NetworkDiscovery] Started in {(serverMode ? "Server" : "Client")} mode on port {Port}.");
        }

        /// <summary>
        /// Stops the network discovery process for both server and client modes.
        /// This method will cancel any active discovery tasks, release resources associated with
        /// the UDP client, and reset the discovery status flags (<c>IsServer</c> and <c>IsClient</c>)
        /// to false.
        /// </summary>
        /// <remarks>
        /// If neither the UDP client nor the cancellation token source is initialized,
        /// the method will perform no operation. This method ensures that resources used for network
        /// broadcasts and listening are properly disposed of to prevent resource leaks or unexpected behavior.
        /// </remarks>
        private void StopDiscovery()
        {
            if (_client != null)
            {
                _client.Close();
                _client.Dispose();
                _client = null;
            }
    
            if (_cancellationTokenSource != null)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
                _cancellationTokenSource = null;
            }
    
            IsServer = false;
            IsClient = false;
        }

        /// Sends a client broadcast message over the network to discover available servers.
        /// <param name="broadcast">
        /// The data to include with the broadcast message. This should be an instance of
        /// the DiscoveryBroadcastData struct containing the necessary network information.
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// Thrown when attempting to send a client broadcast while not in client mode.
        /// </exception>
        /// The method sends a broadcast to the network using UDP. It can only be called
        /// when the network discovery component is in client mode. The broadcast data is
        /// serialized and sent to all devices in the network's broadcast domain.
        private void ClientBroadcast(DiscoveryBroadcastData broadcast)
        {
            if (!IsClient)
                throw new InvalidOperationException("Cannot send client broadcast while not running in client mode.");
            IPEndPoint endPoint = new IPEndPoint(IPAddress.Broadcast, port);
            using FastBufferWriter writer = new FastBufferWriter(1024, Allocator.Temp, 64 * 1024);
            WriteHeader(writer, MessageType.BroadCast);
            writer.WriteNetworkSerializable(broadcast);
            byte[] data = writer.ToArray();
            _client?.SendAsync(data, data.Length, endPoint);
        }

        /// <summary>
        /// Continuously listens for incoming network communication or responses, using the provided method for processing received data.
        /// </summary>
        /// <param name="token">A cancellation token used to cancel the listening operation.</param>
        /// <param name="onReceiveTask">A function to invoke when data is received.</param>
        /// <returns>A task that completes once the listening operation is canceled or an error occurs.</returns>
        private async Task ListenAsync(CancellationToken token, Func<Task> onReceiveTask)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await onReceiveTask();
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Debug.LogError($"[NetworkDiscovery] Error in ListenAsync: {ex}");
                }
            }
        }

        /// Asynchronously handles the reception of network discovery response messages.
        /// Processes the received data, verifies the header, and parses the response data.
        /// If a valid response is received, it triggers the appropriate response handling logic.
        /// <returns>
        /// A Task representing the asynchronous operation of receiving and processing responses.
        /// </returns>
        private async Task ReceiveResponseAsync()
        {
            UdpReceiveResult udpResult = await _client.ReceiveAsync();
            var segment = new ArraySegment<byte>(udpResult.Buffer, 0, udpResult.Buffer.Length);
            using FastBufferReader reader = new FastBufferReader(segment, Allocator.Persistent);
            try
            {
                if (!ReadAndCheckHeader(reader, MessageType.Response))
                    return;
                reader.ReadNetworkSerializable(out DiscoveryResponseData receivedResponse);
                ResponseReceived(udpResult.RemoteEndPoint, receivedResponse);
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to receive response: {e}");
            }
        }

        /// <summary>
        /// Asynchronously receives broadcast packets sent over the network during the discovery process.
        /// Parses and validates the received broadcast data, and sends a response if necessary based
        /// on the processing result.
        /// </summary>
        /// <returns>A task representing the asynchronous operation for receiving and processing broadcasts.</returns>
        private async Task ReceiveBroadcastAsync()
        {
            UdpReceiveResult udpResult = await _client.ReceiveAsync();
            var segment = new ArraySegment<byte>(udpResult.Buffer, 0, udpResult.Buffer.Length);
            using FastBufferReader reader = new FastBufferReader(segment, Allocator.Persistent);
            try
            {
                if (!ReadAndCheckHeader(reader, MessageType.BroadCast))
                    return;
                reader.ReadNetworkSerializable(out DiscoveryBroadcastData receivedBroadcast);
                if (ProcessBroadcastImpl(udpResult.RemoteEndPoint, receivedBroadcast, out DiscoveryResponseData response))
                    SendResponse(response, udpResult.RemoteEndPoint);
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to receive broadcast: {e}");
            }
        }

        /// Sends a response message containing discovery response data to a specified remote endpoint.
        /// <param name="response">The discovery response data to send.</param>
        /// <param name="endPoint">The remote endpoint to which the response will be sent.</param>
        private void SendResponse(DiscoveryResponseData response, IPEndPoint endPoint)
        {
            using FastBufferWriter writer = new FastBufferWriter(1024, Allocator.Temp, 64 * 1024);
            WriteHeader(writer, MessageType.Response);
            writer.WriteNetworkSerializable(response);
            byte[] data = writer.ToArray();
            _client?.SendAsync(data, data.Length, endPoint);
        }

        /// Processes a received broadcast message, validates its authenticity, and optionally updates the client registry.
        /// <param name="sender">
        /// The endpoint address of the sender of the broadcast.
        /// </param>
        /// <param name="broadcast">
        /// The broadcast data received, containing authentication, timestamp, nonce, and optional MAC address.
        /// </param>
        /// <param name="response">
        /// An output parameter to store the constructed response data if the broadcast is valid.
        /// </param>
        /// <returns>
        /// True if the broadcast message is valid and successfully processed, false otherwise.
        /// </returns>
        private bool ProcessBroadcastImpl(IPEndPoint sender, DiscoveryBroadcastData broadcast,
            out DiscoveryResponseData response)
        {
            string expectedToken = CryptoHelper.EncryptString("authToken", SharedKey);
            if (broadcast.AuthTokenHash != expectedToken)
            {
                Debug.Log("[Authentication] Invalid key, ignoring client broadcast.");
                response = default;
                return false;
            }

            if (!_nonceManager.ValidateAndStoreNonce(broadcast.Nonce, broadcast.Timestamp))
            {
                Debug.Log("[Authentication] Nonce/timestamp check failed, ignoring client broadcast.");
                response = default;
                return false;
            }

            if (enableClientRegistry)
            {
                string mac = broadcast.MacAddress;
                if (!string.IsNullOrEmpty(mac))
                {
                    if (_clientRegistry.ContainsKey(mac))
                    {
                        var clientInfo = _clientRegistry[mac];
                        clientInfo.LastSeenTicks = DateTime.Now.Ticks;
                        _clientRegistry[mac] = clientInfo;
                        Debug.Log($"[ClientRegistry] Updated client with MAC: {mac}");
                    }
                    else
                    {
                        var info = new ClientInfo(mac);
                        _clientRegistry.Add(mac, info);
                        Debug.Log($"[ClientRegistry] Registered new client with MAC: {mac}, PID {info.CurrentClientId}");
                    }
                }
            }

            response = new DiscoveryResponseData(SharedKey, transport.ConnectionData.Port);
            return true;
        }

        /// Handles the response received during the network discovery process.
        /// Validates the response authentication token and configures the transport layer
        /// for establishing a connection to the discovered server. If the authentication
        /// token is invalid, the response is ignored.
        /// <param name="sender">The IPEndPoint of the sender of the discovery response.</param>
        /// <param name="response">The response data received during the discovery process.</param>
        private void ResponseReceived(IPEndPoint sender, DiscoveryResponseData response)
        {
            string expectedToken = CryptoHelper.EncryptString("authToken", SharedKey);
            if (response.AuthTokenHash != expectedToken)
            {
                Debug.Log($"[Authentication] Invalid server key token from {sender}, ignoring response.");
                return;
            }

            transport.SetConnectionData(sender.Address.ToString(), response.Port);
            networkManager.StartClient();
        }

        #endregion

        #region Utility Functions

        /// Retrieves the local machine's IPv4 address suitable for network communication.
        /// If no valid IPv4 address is found, it defaults to "127.0.0.1".
        /// <returns>The local IPv4 address as a string or "127.0.0.1" if no valid address is found.</returns>
        private string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ip = host.AddressList.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (ip == null)
            {
                Debug.LogWarning("[NetworkDiscovery] Could not find a valid IPv4 address, defaulting to localhost.");
                return "127.0.0.1";
            }

            return ip.ToString();
        }

        /// Creates a broadcast data instance based on the current network discovery settings.
        /// This method generates a `DiscoveryBroadcastData` object to be sent in broadcast messages.
        /// If client registry is enabled, the returned data includes the MAC address of the client.
        /// <returns>
        /// A `DiscoveryBroadcastData` instance containing the generated broadcast information,
        /// including an authentication token hash, timestamp, nonce, and optionally the MAC address.
        /// </returns>
        private DiscoveryBroadcastData CreateBroadcastData()
        {
            if (enableClientRegistry)
            {
                string mac = GetMacAddress();
                return new DiscoveryBroadcastData(SharedKey, mac);
            }
            else
            {
                return new DiscoveryBroadcastData(SharedKey);
            }
        }

        /// Retrieves the MAC address of the current machine's active network interface that is operational
        /// and not of type Loopback. If no suitable network interface is found, or if an error occurs,
        /// an empty string is returned.
        /// <returns>The MAC address as a string or an empty string if not found or any error occurs.</returns>
        private string GetMacAddress()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var nic in interfaces)
                {
                    if (nic.OperationalStatus == OperationalStatus.Up &&
                        nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                        return nic.GetPhysicalAddress().ToString();
                }
            }
            catch (Exception ex)
            {
                Debug.LogError("Failed to get MAC address: " + ex.Message);
            }

            return "";
        }

        /// <summary>
        /// Writes a message header to the specified FastBufferWriter.
        /// The header contains the type of the message being written.
        /// </summary>
        /// <param name="writer">The FastBufferWriter to write the header to.</param>
        /// <param name="type">The type of the message to include in the header.</param>
        private void WriteHeader(FastBufferWriter writer, MessageType type)
        {
            writer.WriteValueSafe((byte)type);
        }

        /// <summary>
        /// Reads a message header from the provided buffer and verifies that the message type matches the expected type.
        /// </summary>
        /// <param name="reader">The buffer reader instance from which the message header is read.</param>
        /// <param name="expectedType">The expected type of the message.</param>
        /// <returns>Returns true if the message type matches the expected type; otherwise, false.</returns>
        private bool ReadAndCheckHeader(FastBufferReader reader, MessageType expectedType)
        {
            reader.ReadValueSafe(out byte msgType);
            return msgType == (byte)expectedType;
        }

        #endregion

        /// Coroutine that monitors the current network reachability status and triggers a reconnection process
        /// when the network reachability status changes.
        /// The method continuously checks the current internet reachability status using Unity's
        /// `Application.internetReachability` property. If there is a change detected in the network
        /// reachability compared to the last known state, it will trigger the `StartConnection` method
        /// to handle the reconnection process, ensuring the network state is either adjusted or restarted
        /// accordingly.
        /// <return>
        /// Returns an IEnumerator, allowing this method to be used as a coroutine in Unity's MonoBehaviour
        /// for repeated asynchronous execution over time.
        /// </return>
        private IEnumerator NetworkReachabilityCheckCR()
        {
            while (true)
            {
                NetworkReachability currentReachability = Application.internetReachability;
                if (currentReachability != _lastReachability)
                {
                    _lastReachability = currentReachability;
                    StartConnection();
                }

                yield return new WaitForSecondsRealtime(1f);
            }
        }
    }
}
