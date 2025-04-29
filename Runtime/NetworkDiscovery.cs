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
using UnityEngine.Serialization;

namespace Network_Discovery
{
    public class NetworkDiscovery : MonoBehaviour
    {
        public static NetworkDiscovery SingletonInstance { get; private set; }

        //========================================
        // Events (Server-only)
        //========================================
        /// <summary>
        /// An event triggered when a client connects to the server. Invoked locally & on the server.
        /// </summary>
        /// <remarks>
        /// This event is invoked with the client's unique ID and MAC address when a client establishes
        /// a connection with the server. It can be used to handle custom behavior for newly connected clients,
        /// such as updating client registries or initiating specific server-side operations related to the client.
        /// </remarks>
        /// <param name="clientId">
        /// The unique identifier of the client assigned by the network manager.
        /// </param>
        /// <param name="macAddress">
        /// The MAC address or unique network identifier associated with the connected client.
        /// </param>
        public static event Action<ulong, string> OnClientConnection;

        /// <summary>
        /// Event triggered upon the disconnection of a client from the network.
        /// </summary>
        /// <remarks>
        /// The event is invoked with the MAC address of the client as a parameter.
        /// It allows listeners to handle cleanup, update client states, or log disconnection activity.
        /// </remarks>
        public static event Action<string> OnClientDisconnection;

        //========================================
        // Serialized Inspector Fields
        //========================================
        [SerializeField] private bool singleton = false;

        [Header("Network Role")]
        [SerializeField] private NetworkRole role = NetworkRole.Server;

        [Header("Broadcast Port")]
        [SerializeField] private ushort port = 47777;

        [Header("Timing")]
        [SerializeField] private float serverBroadcastDelay = 3f;
        [SerializeField] private float clientBroadcastDelay = 3f;
        [SerializeField] private float clientBroadcastPingInterval = 3f;

        [Header("Discovery Options")]
        [SerializeField] private bool autoStart = true;
        [SerializeField] private bool autoReconnect = true;
        [SerializeField] private bool stopDiscoveryOnConnect = true;
        [SerializeField] private int maxBroadcastAttempts = 0;

        [Header("Client Registry (Optional)")]
        [SerializeField] private bool enableClientRegistry = true;

        [Header("References")]
        [SerializeField] private NetworkManager networkManager;
        [SerializeField] private UnityTransport transport;

#if UNITY_EDITOR
        [SerializeField] private List<ClientInfo> editorClientRegistry;
#endif

        //========================================
        // Public Properties
        //========================================
        public bool Singleton
        {
            get => singleton;
            set => singleton = value;
        }

        /// <summary>
        /// Gets or sets the role of the network instance, defining whether it functions as a "Client" or "Server".
        /// </summary>
        /// <remarks>
        /// The role determines the behavior of the network instance within a multiplayer setup.
        /// When set to "Server", the instance hosts the network and manages client connections.
        /// When set to "Client", the instance performs broadcasting to attempt connecting to a server.
        /// </remarks>
        public NetworkRole Role
        {
            get => role;
            set => role = value;
        }

        /// <summary>
        /// A reference to the <see cref="Unity.Netcode.NetworkManager"/> instance.
        /// </summary>
        /// <remarks>
        /// This property represents the instance of the Network Manager used to control and manage network-related functionality,
        /// such as starting and stopping network sessions, managing connected clients, and handling networked messages. It can
        /// be assigned or retrieved in order to integrate or customize behavior related to the Network Manager within the application.
        /// </remarks>
        public NetworkManager NetworkManager
        {
            get => networkManager;
            set => networkManager = value;
        }

        /// <summary>
        /// The transport layer used for network communication in the application.
        /// </summary>
        /// <remarks>
        /// This property provides access to the configured UnityTransport instance, responsible for handling
        /// low-level networking functionality such as data transmission, connection management, and transport-specific settings.
        /// It is utilized by the NetworkManager to manage networked communication between clients and servers.
        /// </remarks>
        public UnityTransport Transport
        {
            get => transport;
            set => transport = value;
        }

        /// <summary>
        /// A shared key used for encryption and decryption of sensitive data during the network discovery process.
        /// </summary>
        /// <remarks>
        /// The shared key is a crucial component for secure communication between clients and servers.
        /// It is used in various cryptographic operations, such as encrypting broadcast tokens, handshake messages,
        /// and validating authentication data during network discovery and connection procedures.
        /// Updating this key requires synchronizing it across all participating clients and the server to ensure compatibility.
        /// </remarks>
        /// <value>
        /// A string representing the shared encryption key. This key must remain consistent across the networked components
        /// to ensure secure data exchange.
        /// </value>
        public static string SharedKey { get; set; } = "mySecretKey";

        /// <summary>
        /// Gets or sets the port number used for network discovery broadcasts and communication.
        /// </summary>
        /// <remarks>
        /// This property specifies the port on which the application listens for or sends network discovery
        /// broadcasts. The port is used both in server and client modes to facilitate communication between
        /// peers. It must match between clients and the server for successful discovery and connection.
        /// </remarks>
        public ushort Port
        {
            get => port;
            set => port = value;
        }

        /// <summary>
        /// Determines whether the network discovery process starts automatically upon initialization.
        /// </summary>
        /// <remarks>
        /// When set to true, the network discovery component will immediately begin either hosting or
        /// broadcasting based on the assigned network role (Server or Client) as soon as it is initialized.
        /// This property allows for a hands-free configuration where the discovery process starts without requiring
        /// manual intervention via code or user input.
        /// </remarks>
        public bool AutoStart
        {
            get => autoStart;
            set => autoStart = value;
        }

        /// <summary>
        /// A property that determines whether the network system should automatically attempt
        /// to reconnect upon detecting network interruptions or disconnections.
        /// </summary>
        /// <remarks>
        /// If enabled, the system will monitor network reachability and attempt to restore the
        /// network connection when interruptions are resolved. This can be useful for maintaining
        /// persistent network connections in environments with unstable connectivity.
        /// </remarks>
        public bool AutoReconnect
        {
            get => autoReconnect;
            set => autoReconnect = value;
        }

        /// <summary>
        /// Determines whether the client registry feature is enabled for tracking connected clients.
        /// </summary>
        /// <remarks>
        /// When enabled, the system maintains a registry of connected clients, allowing for the storage
        /// and retrieval of client information such as connection details or custom data associated with
        /// each client. This feature can be useful for implementing more complex networking functionality
        /// that depends on client-specific records or states.
        /// </remarks>
        public bool EnableClientRegistry
        {
            get => enableClientRegistry;
            set => enableClientRegistry = value;
        }

        /// <summary>
        /// Determines whether network discovery should stop broadcasting or listening
        /// when the client establishes a connection to the server.
        /// </summary>
        /// <remarks>
        /// Setting this property to <c>true</c> will automatically stop the discovery process
        /// on a successful connection. This is useful in scenarios where continuous broadcasting
        /// or discovery after connection is unnecessary or may cause conflicts.
        /// If set to <c>false</c>, network discovery will continue even after a successful connection.
        /// </remarks>
        /// <value>
        /// A boolean value that controls the behavior of the discovery process upon connection.
        /// </value>
        public bool StopDiscoveryOnConnect
        {
            get => stopDiscoveryOnConnect;
            set => stopDiscoveryOnConnect = value;
        }

        /// <summary>
        /// Specifies the delay interval in seconds between successive broadcast attempts made by the client during network discovery.
        /// </summary>
        /// <remarks>
        /// This property defines the duration that the client waits before sending another broadcast message to discover servers
        /// on the network. It is primarily used in the client role to manage broadcast frequency and can be adjusted to balance
        /// network efficiency and discovery speed.
        /// </remarks>
        public float ClientBroadcastDelay
        {
            get => clientBroadcastDelay;
            set => clientBroadcastDelay = value;
        }

        /// <summary>
        /// The interval, in seconds, at which the client sends broadcast ping messages to discover a server.
        /// </summary>
        /// <remarks>
        /// This property defines the frequency with which the client broadcasts pings to detect servers
        /// available on the network. Reducing the interval may result in faster discovery but can increase
        /// network traffic, while increasing the interval can reduce traffic at the cost of slower detection.
        /// </remarks>
        public float ClientBroadcastPingInterval
        {
            get => clientBroadcastPingInterval;
            set => clientBroadcastPingInterval = value;
        }

        /// <summary>
        /// The interval, in seconds, at which the server broadcasts presence information to clients.
        /// </summary>
        /// <remarks>
        /// This property determines how frequently the server will emit broadcast messages to facilitate
        /// network discovery by clients. The value should be set carefully to balance discovery responsiveness
        /// and network traffic. Shorter intervals provide quicker discovery for clients but may increase
        /// network load. Longer intervals reduce network load but may delay client discovery.
        /// </remarks>
        public float ServerBroadcastDelay
        {
            get => serverBroadcastDelay;
            set => serverBroadcastDelay = value;
        }

        /// <summary>
        /// Specifies the maximum number of broadcast attempts a client will make when attempting to discover a server.
        /// </summary>
        /// <remarks>
        /// This property is used to limit the number of broadcast retries made by the client when attempting to connect
        /// to a server in the network discovery process. A value of 0 indicates no limit, meaning the client will continue
        /// to broadcast until either a connection is established or the process is manually stopped.
        /// </remarks>
        public int MaxBroadcastAttempts
        {
            get => maxBroadcastAttempts;
            set => maxBroadcastAttempts = value;
        }

        /// <summary>
        /// Indicates whether the current instance of the network discovery is operating in client mode.
        /// </summary>
        /// <remarks>
        /// This property is set internally when starting or stopping the network discovery process.
        /// Its value determines if the instance is functioning as a client, primarily listening for server broadcasts,
        /// sending client-specific broadcasts, or managing client-specific behavior.
        /// </remarks>
        public bool IsClient { get; private set; }

        /// <summary>
        /// Indicates whether the network discovery instance is currently operating in server mode.
        /// </summary>
        /// <remarks>
        /// This property is set internally when starting or stopping network discovery. It determines whether the
        /// instance is acting as a server. When true, the instance is configured to broadcast data and listen for client responses.
        /// When false, the instance operates in client mode, sending discovery requests and waiting for responses from servers.
        /// </remarks>
        public bool IsServer { get; private set; }


        //========================================
        // Private Fields
        //========================================
        private readonly Dictionary<ulong, string> _pidToMac = new();
        private readonly Dictionary<string, ClientInfo> _clientRegistry = new();
        private readonly NonceManager _nonceManager = new();
        private CancellationTokenSource _cancellationTokenSource;
        private UdpClient _client;
        private NetworkReachability _lastReachability;

        //////////////////////////////////////////////////////////////////////////////////
        // Unity Lifecycle Methods
        //////////////////////////////////////////////////////////////////////////////////

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
            
            if (singleton)
            {
                if (SingletonInstance)
                {
                    return;
                }
                
                SingletonInstance = this;
                DontDestroyOnLoad(gameObject);
            }
        }

        private void Start()
        {
            if (autoStart)
            {
                StartConnection();
            }
        }

        private void OnDisable()
        {
            StopAllCoroutines();
            StopDiscovery();

            networkManager.OnServerStarted -= OnServerStarted;
            networkManager.OnConnectionEvent -= OnConnectionEvent;
            networkManager.OnServerStopped -= HandleConnectionChange;
            networkManager.OnClientStopped -= HandleConnectionChange;
        }

        //////////////////////////////////////////////////////////////////////////////////
        // Event & Connection Handlers
        //////////////////////////////////////////////////////////////////////////////////

        private void OnConnectionEvent(NetworkManager manager, ConnectionEventData data)
        {
            if (!enableClientRegistry) return; // Skip if registry not in use

            switch (data.EventType)
            {
                case ConnectionEvent.ClientConnected:
                    Debug.Log($"A client has connected with PID {data.ClientId}");
                    if (data.ClientId == networkManager.LocalClientId)
                    {
                        SendMacHandshake();
                        OnClientConnection?.Invoke(data.ClientId, GetMacAddress());
                    }

                    break;

                case ConnectionEvent.ClientDisconnected:
                    if (networkManager.IsServer)
                    {
                        if (TryGetClientInfoById(data.ClientId, out ClientInfo info))
                        {
                            info.IsConnected = false;
                            info.LastSeenTicks = DateTime.Now.Ticks;
                            _clientRegistry[info.MacAddress] = info;
                            OnClientDisconnection?.Invoke(info.MacAddress);

                            Debug.Log(
                                $"[ClientRegistry] Updated registry of {info.MacAddress}: {_clientRegistry[info.MacAddress]}");
#if UNITY_EDITOR
                            editorClientRegistry = _clientRegistry.Values.ToList();
#endif
                        }
                    }

                    break;
            }
        }

        private void OnServerStarted()
        {
            NetworkManager.Singleton.CustomMessagingManager
                .RegisterNamedMessageHandler("ClientMacHandshake", OnMacHandshakeMessageReceived);

            // If the server should broadcast its presence after a delay:
            StartCoroutine(StartDiscovery(true, serverBroadcastDelay));
        }

        private void HandleConnectionChange(bool cleanChange = true)
        {
            // The user can decide if they want an immediate reconnection attempt:
            if (autoReconnect)
            {
                StartConnection();
            }
        }

        /// <summary>
        /// Initiates hosting (if server) or broadcasting (if client).
        /// </summary>
        public void StartConnection()
        {
            // If NetworkManager is listening, shut it down before re-configuring:
            if (NetworkManager.Singleton && NetworkManager.Singleton.IsListening)
            {
                Debug.Log("[NetworkDiscovery] Stopping NetworkManager before making changes.");
                NetworkManager.Singleton.Shutdown();
                StopDiscovery();
            }

            StopAllCoroutines(); // Stop any previous routines
            _lastReachability = Application.internetReachability;

            // Only check for changes if user wants auto-reconnect:
            if (autoReconnect) StartCoroutine(NetworkReachabilityCheckCR());

            if (_lastReachability == NetworkReachability.NotReachable)
            {
                Debug.LogWarning("There is no active internet connection");
            }

            if (role == NetworkRole.Server)
            {
                HostGame();
            }
            else
            {
                StartCoroutine(ClientBroadcastCR());
            }
        }

        private void HostGame()
        {
            var localIp = GetLocalIPAddress();
            transport.SetConnectionData(localIp, transport.ConnectionData.Port);
            Debug.Log($"[LocalNetworkDiscovery] Hosting on IP: {localIp}, Port: {transport.ConnectionData.Port}");
            networkManager.StartServer();
        }

        private IEnumerator ClientBroadcastCR()
        {
            // Let the client wait a bit before first broadcast.
            yield return StartCoroutine(StartDiscovery(false, clientBroadcastDelay));

            WaitForSeconds wait = new WaitForSeconds(clientBroadcastPingInterval);

            int attemptCounter = 0;
            while (!networkManager.IsConnectedClient)
            {
                // If maxBroadcastAttempts is set and reached, break out.
                if (maxBroadcastAttempts > 0 && attemptCounter >= maxBroadcastAttempts)
                {
                    Debug.Log("[LocalNetworkDiscovery] Max broadcast attempts reached, giving up.");
                    break;
                }

                attemptCounter++;
                Debug.Log($"[LocalNetworkDiscovery] Sending client broadcast (attempt #{attemptCounter})...");
                ClientBroadcast(CreateBroadcastData());

                yield return wait;
            }

            if (stopDiscoveryOnConnect && networkManager.IsConnectedClient)
            {
                StopDiscovery();
                Debug.Log("[LocalNetworkDiscovery] Found server; discovery stopped.");
            }
        }

        //////////////////////////////////////////////////////////////////////////////////
        // Messaging & Handshake
        //////////////////////////////////////////////////////////////////////////////////

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

                byte[] decryptedBytes = CryptoHelper.DecryptBytes(encryptedBytes, SharedKey);
                if (decryptedBytes == null)
                {
                    Debug.LogWarning("[Server] Decryption failed. Possibly wrong key. Ignoring.");
                    return;
                }

                string decryptedMac = Encoding.UTF8.GetString(decryptedBytes);
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

        private void RegisterClientMac(ulong clientId, string mac)
        {
            if (_clientRegistry.TryGetValue(mac, out ClientInfo info))
            {
                info.LastSeenTicks = DateTime.Now.Ticks;
                info.CurrentClientId = clientId;
                info.IsConnected = true;
                _clientRegistry[mac] = info;
            }
            else
            {
                // Newly discovered MAC
                var newInfo = new ClientInfo(mac)
                {
                    LastSeenTicks = DateTime.Now.Ticks,
                    CurrentClientId = clientId,
                    IsConnected = true
                };
                _clientRegistry[mac] = newInfo;
            }

            _pidToMac[clientId] = mac;
            Debug.Log($"Updated client registry: {_clientRegistry[mac]}");
            OnClientConnection?.Invoke(clientId, mac);

#if UNITY_EDITOR
            editorClientRegistry = _clientRegistry.Values.ToList();
#endif
        }

        //////////////////////////////////////////////////////////////////////////////////
        // Network Discovery & Broadcast
        //////////////////////////////////////////////////////////////////////////////////

        private IEnumerator StartDiscovery(bool serverMode, float initialDelay = 0f)
        {
            StopDiscovery();
            IsServer = serverMode;
            IsClient = !serverMode;

            yield return new WaitForSeconds(initialDelay);
            _cancellationTokenSource = new CancellationTokenSource();

            // Create the UDP socket manually so we can set options.
            Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udpSocket.ExclusiveAddressUse = false;
            udpSocket.Bind(new IPEndPoint(IPAddress.Any, serverMode ? port : 0));

            _client = new UdpClient { Client = udpSocket, EnableBroadcast = true, MulticastLoopback = false };
            _ = ListenAsync(_cancellationTokenSource.Token, serverMode ? ReceiveBroadcastAsync : ReceiveResponseAsync);

            Debug.Log($"[NetworkDiscovery] Started in {(serverMode ? "Server" : "Client")} mode on port {Port}.");
        }

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

        private void ClientBroadcast(DiscoveryBroadcastData broadcast)
        {
            if (!IsClient)
                throw new InvalidOperationException("Cannot send client broadcast when not in client mode.");

            IPEndPoint endPoint = new IPEndPoint(IPAddress.Broadcast, port);
            using FastBufferWriter writer = new FastBufferWriter(1024, Allocator.Temp, 64 * 1024);
            WriteHeader(writer, MessageType.BroadCast);
            writer.WriteNetworkSerializable(broadcast);
            byte[] data = writer.ToArray();

            _client?.SendAsync(data, data.Length, endPoint);
        }

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
                if (ProcessBroadcastImpl(udpResult.RemoteEndPoint, receivedBroadcast,
                        out DiscoveryResponseData response))
                {
                    SendResponse(response, udpResult.RemoteEndPoint);
                }
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to receive broadcast: {e}");
            }
        }

        private void SendResponse(DiscoveryResponseData response, IPEndPoint endPoint)
        {
            using FastBufferWriter writer = new FastBufferWriter(1024, Allocator.Temp, 64 * 1024);
            WriteHeader(writer, MessageType.Response);
            writer.WriteNetworkSerializable(response);
            byte[] data = writer.ToArray();

            _client?.SendAsync(data, data.Length, endPoint);
        }

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
                        Debug.Log($"[ClientRegistry] Previously connected client tries to reconnect: {mac}");
                    }
                    else
                    {
                        var info = new ClientInfo(mac);
                        _clientRegistry.Add(mac, info);
                        Debug.Log(
                            $"[ClientRegistry] Registered new client with MAC: {mac}, PID {info.CurrentClientId}");
#if UNITY_EDITOR
                        editorClientRegistry = _clientRegistry.Values.ToList();
#endif
                    }
                }
            }

            response = new DiscoveryResponseData(SharedKey, transport.ConnectionData.Port);
            return true;
        }

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

        //////////////////////////////////////////////////////////////////////////////////
        // Utility Functions
        //////////////////////////////////////////////////////////////////////////////////

        private string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ip = host.AddressList.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (ip == null)
            {
                Debug.LogWarning("[NetworkDiscovery] Could not find a valid IPv4 address; defaulting to localhost.");
                return "127.0.0.1";
            }

            return ip.ToString();
        }

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

        private string GetMacAddress()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var nic in interfaces)
                {
                    if (nic.OperationalStatus == OperationalStatus.Up &&
                        nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        return nic.GetPhysicalAddress().ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.LogError("Failed to get MAC address: " + ex.Message);
            }

            return "";
        }

        private void WriteHeader(FastBufferWriter writer, MessageType type)
        {
            writer.WriteValueSafe((byte)type);
        }

        private bool ReadAndCheckHeader(FastBufferReader reader, MessageType expectedType)
        {
            reader.ReadValueSafe(out byte msgType);
            return msgType == (byte)expectedType;
        }

        public bool TryGetClientInfoById(ulong clientId, out ClientInfo clientInfo)
        {
            clientInfo = default;
            if (_pidToMac.TryGetValue(clientId, out string mac) && _clientRegistry.TryGetValue(mac, out clientInfo))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Periodically checks for changes in network reachability and attempts to reconnect if lost.
        /// Only runs if 'autoReconnect' is true.
        /// </summary>
        private IEnumerator NetworkReachabilityCheckCR()
        {
            while (true)
            {
                NetworkReachability currentReachability = Application.internetReachability;
                if (currentReachability != _lastReachability)
                {
                    _lastReachability = currentReachability;
                    if (autoReconnect && currentReachability != NetworkReachability.NotReachable)
                    {
                        StartConnection();
                    }
                }

                yield return new WaitForSecondsRealtime(1f);
            }
        }

        private enum MessageType : byte
        {
            BroadCast,
            Response
        }
    }
}