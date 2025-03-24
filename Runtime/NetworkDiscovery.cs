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
        //////////////////////////////////////////////////////////////////////////////////
        // Events
        //////////////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// A static event invoked when a new MAC address is registered or updated in the client registry.
        /// </summary>
        /// <remarks>
        /// Server-only
        /// This event provides a mechanism to notify subscribers whenever a MAC address is successfully
        /// registered or updated in the internal registry. It carries two parameters:
        /// the unique network ID of the client and the MAC address being registered.
        /// </remarks>
        public static event Action<ulong, string> OnClientConnection;

        /// <summary>
        /// A static event invoked when a client's disconnection is detected and logged in the client registry.
        /// </summary>
        /// <remarks>
        /// Server-only
        /// This event notifies subscribers whenever a client disconnects. It provides the MAC address
        /// of the client that has been disconnected, enabling updates to the client registry or triggering
        /// additional logic based on the disconnection event.
        /// </remarks>
        public static event Action<string> OnClientDisconnection;

        //////////////////////////////////////////////////////////////////////////////////
        // Fields & Properties
        //////////////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// This key is used to encrypt/decrypt handshake tokens and broadcast messages.
        /// </summary>
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

        [Header("Discovery Options")]
        [Tooltip("If enabled, discovery starts automatically on Start().")]
        [SerializeField] private bool autoStart = true;

        [Tooltip("If enabled, will attempt to re-start connection or re-broadcast if connection is lost.")]
        [SerializeField] private bool autoReconnect = true;

        [Tooltip("If > 0, the client broadcast will stop after this many attempts if no server is found. 0 = unlimited.")]
        [SerializeField] private int maxBroadcastAttempts = 0;

        [Tooltip("If true, discovery will stop once the client successfully connects.")]
        [SerializeField] private bool stopDiscoveryOnConnect = true;

        // Nonce manager for broadcast messages
        private readonly NonceManager _nonceManager = new();
        // Underlying UDP client
        private UdpClient _client;
        private CancellationTokenSource _cancellationTokenSource;
        private NetworkReachability _lastReachability;

        // Primary client registry structures
        private readonly Dictionary<string, ClientInfo> _clientRegistry = new();
        private readonly Dictionary<ulong, string> _pidToMac = new();

        public bool IsServer { get; private set; }
        public bool IsClient { get; private set; }
        private ushort Port => port;

        private enum MessageType : byte
        {
            BroadCast = 0,
            Response = 1
        }

#if UNITY_EDITOR
        // This list shows all ClientInfo values from _clientRegistry in the Inspector (Editor-only).
        [Space(10), SerializeField, Tooltip("Editor-only view of the current client registry.")]
        private List<ClientInfo> editorClientRegistry = new();

        // Keep the dictionary mirrored into a list for inspector debug.
        private void OnValidate()
        {
            // If you only want to see registry if 'enableClientRegistry' is on, you can do:
            // if (!enableClientRegistry) { editorClientRegistry.Clear(); return; }
            editorClientRegistry = _clientRegistry.Values.ToList();
        }
#endif

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
                    if (data.ClientId == networkManager.LocalClientId) SendMacHandshake();
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

                            Debug.Log($"[ClientRegistry] Updated registry of {info.MacAddress}: {_clientRegistry[info.MacAddress]}");
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
                throw new InvalidOperationException("Cannot start network discovery: no network reachable.");
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
                if (ProcessBroadcastImpl(udpResult.RemoteEndPoint, receivedBroadcast, out DiscoveryResponseData response))
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
                        Debug.Log($"[ClientRegistry] Registered new client with MAC: {mac}, PID {info.CurrentClientId}");
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
    }
}
