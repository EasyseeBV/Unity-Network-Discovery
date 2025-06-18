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
using Unity.Multiplayer.Playmode;
using Unity.Netcode;
using Unity.Netcode.Transports.UTP;
using UnityEngine;

namespace Network_Discovery
{
    [DefaultExecutionOrder(-100)]
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
        public static event Action OnServerDisconnection;

        public static event Action<ulong, string> OnClientReconnection;

        //========================================
        // Serialized Inspector Fields
        //========================================
        [SerializeField]
        private bool singleton = false;

        [Header("Network Role")]
        [SerializeField]
        private NetworkRole role = NetworkRole.Server;

        [Header("Host Selection")]
        [Tooltip("Laat leeg voor auto-detect, gebruik 0.0.0.0 om op alle adapters te binden, "
                 + "of vul het exacte IPv4-adres in dat de server moet gebruiken.")]
        [SerializeField]
        public string specificHostIP = "0.0.0.0";

        [Header("Broadcast Port")]
        [SerializeField]
        private ushort port = 47777;

        [Header("Timing")]
        [SerializeField]
        private float serverBroadcastDelay = 3f;

        [SerializeField]
        private float clientBroadcastDelay = 3f;

        [SerializeField]
        private float clientBroadcastPingInterval = 3f;

        [Header("Discovery Options")]
        [SerializeField]
        private bool autoStart = true;

        [SerializeField]
        private bool autoReconnect = true;

        [SerializeField]
        private bool stopDiscoveryOnConnect = true;

        [SerializeField]
        private int maxBroadcastAttempts = 0;

        [Header("Client Registry (Optional)")]
        [SerializeField]
        private bool enableClientRegistry = true;

        [Header("References")]
        [SerializeField]
        private NetworkManager networkManager;

        [SerializeField]
        private UnityTransport transport;

#if UNITY_EDITOR
        [SerializeField]
        private List<ClientInfo> editorClientRegistry;
#endif

        private CancellationTokenSource _reachabilityCts; // voor netwerk-monitoring (auto-reconnect)
        private string hostingIPAddress; // IP waarop de server daadwerkelijk luistert

        #region Public Properties

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

        #endregion

        //========================================
        // Private Fields
        //========================================
        private readonly Dictionary<ulong, string> _pidToMac = new();
        private readonly Dictionary<string, ClientInfo> _clientRegistry = new();
        private readonly NonceManager _nonceManager = new();
        private CancellationTokenSource _cancellationTokenSource;
        private UdpClient _client;
        private NetworkReachability _lastReachability;
        private static bool _localHasConnected;

        //////////////////////////////////////////////////////////////////////////////////
        // Unity Lifecycle Methods
        //////////////////////////////////////////////////////////////////////////////////

        private void Awake()
        {
            if (!transport) transport = FindFirstObjectByType<UnityTransport>();
            if (!networkManager) networkManager = FindFirstObjectByType<NetworkManager>();
            
            if (CurrentPlayer.ReadOnlyTags().Contains("client")) role = NetworkRole.Client;
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
                    if (data.ClientId == networkManager.LocalClientId) // Is the connected client the local?
                    {
                        // Double verification of MAC address for safety.
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
                    else
                    {
                        OnServerDisconnection?.Invoke();
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

            if (role == NetworkRole.Server || role == NetworkRole.Host)
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
            // ❶ inspector-waarde
            string hostIp = specificHostIP?.Trim();

            // ❷ bind *alleen* op alle adapters wanneer 0.0.0.0 is opgegeven
            bool bindAny = hostIp == "0.0.0.0";

            // ❸ auto-detect wanneer leeg of ongeldig
            if (string.IsNullOrWhiteSpace(hostIp) || (!bindAny && !IPAddress.TryParse(hostIp, out _)))
                hostIp = GetLocalIPAddress();
            else if (!IPAddress.TryParse(hostIp, out _))
            {
                Debug.LogWarning($"[NetworkDiscovery] '{hostIp}' is geen geldig IPv4-adres → fallback auto-detect.");
                hostIp = GetLocalIPAddress();
            }

            // ❸   Configureer transport  (0.0.0.0 == IPAddress.Any)
            transport.SetConnectionData(bindAny ? "0.0.0.0" : hostIp, transport.ConnectionData.Port);
            hostingIPAddress = hostIp; // voor GetLocalAddressFor-fallback

            Debug.Log($"[NetworkDiscovery] Hosting op {(bindAny ? "ALLE" : hostIp)}:{transport.ConnectionData.Port}");
            
            if (role == NetworkRole.Server) networkManager.StartServer();
            else if (role == NetworkRole.Host) networkManager.StartHost();
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
        /// <summary>
        /// Handles the reception of a MAC handshake message from a client on the server.
        /// </summary>
        /// <param name="senderClientId">The ID of the client sending the handshake message.</param>
        /// <param name="reader">The message payload received from the client.</param>
        private void OnMacHandshakeMessageReceived(ulong senderClientId, FastBufferReader reader)
        {
            if (!NetworkManager.IsServer || !enableClientRegistry) return;

            try
            {
                if (!reader.TryBeginRead(sizeof(uint))) return;
                reader.ReadValueSafe(out uint payloadSize);

                if (payloadSize == 0 || payloadSize > 1024) return;
                if (!reader.TryBeginRead((int)payloadSize)) return;

                byte[] enc = new byte[payloadSize];
                reader.ReadBytesSafe(ref enc, (int)payloadSize);

                byte[] dec = CryptoHelper.DecryptBytes(enc, SharedKey);
                if (dec == null || dec.Length == 0) return;

                string mac = Encoding.UTF8.GetString(dec).Trim();
                if (IsValidMacAddress(mac)) RegisterClientMac(senderClientId, mac);
            }
            catch (Exception ex)
            {
                Debug.LogError($"[Server Handshake] {ex}");
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

            if (_localHasConnected)
            {
                Debug.Log($"Local client has reconnected to the server.");
                OnClientReconnection?.Invoke(networkManager.LocalClientId, mac);
            }

            _localHasConnected = true;
            Debug.Log($"{networkManager.LocalClientId} sent handshake message to server with MAC {mac}");
        }

        private void RegisterClientMac(ulong clientId, string mac)
        {
            if (_clientRegistry.TryGetValue(mac, out var info))
            {
                Debug.Log($"[SERVER] Client {clientId} reconnected.");
                
                info.LastSeenTicks = DateTime.UtcNow.Ticks;
                info.CurrentClientId = clientId;
                info.IsConnected = true;
                _clientRegistry[mac] = info;
                
                OnClientReconnection?.Invoke(clientId, mac);
            }
            else
            {
                _clientRegistry[mac] = new ClientInfo(mac)
                {
                    LastSeenTicks = DateTime.UtcNow.Ticks,
                    CurrentClientId = clientId,
                    IsConnected = true
                };
            }

            // oude PID-mapping opruimen als dezelfde client opnieuw verbindt
            if (_pidToMac.TryGetValue(clientId, out var oldMac) && oldMac != mac) _clientRegistry.Remove(oldMac);

            _pidToMac[clientId] = mac;

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
            Debug.Log("Broadcast received");
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

        private bool ProcessBroadcastImpl(IPEndPoint sender,
            DiscoveryBroadcastData broadcast,
            out DiscoveryResponseData response)
        {
            // 1) auth-token
            string expected = CryptoHelper.EncryptString("authToken", SharedKey);
            if (broadcast.AuthTokenHash != expected)
            {
                response = default;
                return false;
            }

            // 2) nonce / timestamp
            if (!_nonceManager.ValidateAndStoreNonce(broadcast.Nonce, broadcast.Timestamp))
            {
                response = default;
                return false;
            }
            
            string replyIp = transport.ConnectionData.Address != "0.0.0.0"
                ? transport.ConnectionData.Address
                : GetLocalAddressFor(sender);

            response = new DiscoveryResponseData(SharedKey, transport.ConnectionData.Port, replyIp);

            // 5) bouw response
            response = new DiscoveryResponseData(SharedKey, transport.ConnectionData.Port, replyIp);
            return true;
        }

        private void ResponseReceived(IPEndPoint sender, DiscoveryResponseData response)
        {
            string expected = CryptoHelper.EncryptString("authToken", SharedKey);
            if (response.AuthTokenHash != expected) return;

            if (networkManager.IsConnectedClient || networkManager.IsListening) return;

            if (string.IsNullOrEmpty(response.ServerAddress) ||
                !IPAddress.TryParse(response.ServerAddress, out _))
                return;

            transport.SetConnectionData(response.ServerAddress, response.Port);
            networkManager.StartClient(); // resultaat komt via OnConnectionEvent
        }

        private void StartNetworkReachabilityCheck()
        {
            StopNetworkReachabilityCheck();
            _reachabilityCts = new CancellationTokenSource();
            StartCoroutine(NetworkReachabilityCheckCR(_reachabilityCts.Token));
        }

        private void StopNetworkReachabilityCheck()
        {
            if (_reachabilityCts != null)
            {
                if (!_reachabilityCts.IsCancellationRequested)
                    _reachabilityCts.Cancel();
                _reachabilityCts.Dispose();
                _reachabilityCts = null;
            }
        }

        private IEnumerator NetworkReachabilityCheckCR(CancellationToken token)
        {
            var wait = new WaitForSecondsRealtime(2f);

            while (!token.IsCancellationRequested)
            {
                var current = Application.internetReachability;

                if (current != _lastReachability)
                {
                    var previous = _lastReachability;
                    _lastReachability = current;

                    // netwerk viel weg en komt terug → opnieuw verbinden
                    if (autoReconnect &&
                        role == NetworkRole.Client &&
                        previous == NetworkReachability.NotReachable &&
                        current != NetworkReachability.NotReachable)
                    {
                        if (!networkManager.IsConnectedClient && !networkManager.IsListening)
                        {
                            yield return new WaitForSeconds(0.5f); // kleine stabilisatie-pauze
                            if (!token.IsCancellationRequested)
                                StartConnection();
                        }
                    }
                }

                yield return wait;
            }
        }


        //////////////////////////////////////////////////////////////////////////////////
        // Utility Functions
        //////////////////////////////////////////////////////////////////////////////////
        private string GetLocalIPAddress()
        {
            try
            {
                var nics = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                n.NetworkInterfaceType != NetworkInterfaceType.Tunnel);

                // ❶   Eerst een adapter zoeken met een default-gateway (≠ 0.0.0.0)
                var gwNic = nics.FirstOrDefault(n =>
                    n.GetIPProperties().GatewayAddresses
                        .Any(g => g?.Address?.AddressFamily == AddressFamily.InterNetwork &&
                                  !g.Address.Equals(IPAddress.Any)));

                IEnumerable<NetworkInterface> ordered =
                    gwNic != null ? new[] { gwNic } : nics;

                ordered = ordered.OrderByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                    .ThenByDescending(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                    .ThenByDescending(n => n.Speed);

                foreach (var nic in ordered)
                {
                    var ip = nic.GetIPProperties().UnicastAddresses
                        .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (ip != null)
                        return ip.Address.ToString();
                }
            }
            catch (Exception ex)
            {
                Debug.LogWarning($"[NetworkDiscovery] IP-detectie faalde: {ex.Message}");
            }

            return "127.0.0.1"; // ultimate fallback
        }

        /// <summary>
        /// Validates whether a given string conforms to a valid MAC address format.
        /// </summary>
        /// <param name="mac">The string representation of the MAC address to validate.</param>
        /// <returns>True if the string is a valid MAC address, otherwise false.</returns>
        private static bool IsValidMacAddress(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return false;

            // accepteert zowel “A1-B2-C3-D4-E5-F6” als “A1:B2:C3:D4:E5:F6” of “A1B2C3D4E5F6”
            return System.Text.RegularExpressions.Regex.IsMatch(
                mac,
                @"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^([0-9A-Fa-f]{12})$");
        }


        private string GetLocalAddressFor(IPEndPoint remote)
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                     n.Supports(NetworkInterfaceComponent.IPv4)))
            {
                var props = nic.GetIPProperties();
                foreach (var uni in props.UnicastAddresses)
                {
                    if (uni.Address.AddressFamily != AddressFamily.InterNetwork || uni.IPv4Mask == null)
                        continue;

                    byte[] addr = uni.Address.GetAddressBytes();
                    byte[] mask = uni.IPv4Mask.GetAddressBytes();
                    byte[] rem = remote.Address.GetAddressBytes();

                    bool sameSubnet = true;
                    for (int i = 0; i < 4; i++)
                    {
                        if ((addr[i] & mask[i]) != (rem[i] & mask[i]))
                        {
                            sameSubnet = false;
                            break;
                        }
                    }

                    if (sameSubnet)
                        return uni.Address.ToString();
                }
            }

            // fallback – gebruik het IP waarop je in HostGame() gebonden hebt
            return hostingIPAddress;
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