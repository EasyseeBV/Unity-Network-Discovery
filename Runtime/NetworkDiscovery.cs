using System;
using System.Collections;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Unity.Collections;
using Unity.Netcode;
using Unity.Netcode.Transports.UTP;
using UnityEngine;

namespace Network_Discovery
{
    /// <summary>
    /// Manages local network discovery for both client and server.
    /// Includes sending and receiving broadcasts, filtering by authentication key,
    /// and handling network connectivity changes.
    /// </summary>
    public class NetworkDiscovery : MonoBehaviour
    {
        #region Constants

        private const int WriterInitialCapacity = 1024;
        private const int WriterMaxCapacity = 64 * 1024;

        #endregion

        #region Configurable Fields

        [Header("Network Role")]
        [Tooltip("Specifies the role of the network (Server or Client).")]
        public NetworkRole role = NetworkRole.Server;

        [Header("Timing")]
        [Tooltip("Interval in seconds at which clients will ping the local network.")]
        [SerializeField]
        private float clientBroadcastPingInterval = 3f;

        [Tooltip("Delay after server-start that server broadcasts its presence.")]
        [SerializeField]
        private float serverBroadcastDelay = 3f;

        [Tooltip("Delay after start that client broadcasts, looking for servers.")]
        [SerializeField]
        private float clientBroadcastDelay = 3f;

        [Header("References")]
        [Tooltip("NetworkManager controlling the netcode behavior.")]
        [SerializeField]
        private NetworkManager networkManager;

        [Tooltip("UTP transport layer for netcode communication.")]
        [SerializeField]
        private UnityTransport transport;

        [Header("Authentication")]
        [Tooltip("A shared secret key. Must match on both client and server.")]
        [SerializeField, TextArea(1, 6)]
        private string sharedKey = "mySecretKey";

        [Header("Broadcast Port")]
        [Tooltip("The port used for sending/receiving network discovery broadcasts.")]
        [SerializeField]
        private ushort port = 47777;

        #endregion

        #region Internal Fields

        private readonly NonceManager nonceManager = new();

        private UdpClient _client;
        private CancellationTokenSource _cancellationTokenSource;
        private NetworkReachability _lastReachability;

        #endregion

        #region State Properties

        /// <summary>
        /// Indicates whether discovery is currently running.
        /// </summary>
        public bool IsRunning { get; private set; }

        /// <summary>
        /// Indicates whether this instance is running in server mode.
        /// </summary>
        public bool IsServer { get; private set; }

        /// <summary>
        /// Indicates whether this instance is running in client mode.
        /// </summary>
        public bool IsClient { get; private set; }

        /// <summary>
        /// Read-only property to get the configured port.
        /// </summary>
        public ushort Port => port;

        #endregion

        #region Private Enum

        private enum MessageType : byte
        {
            BroadCast = 0,
            Response = 1
        }

        #endregion

        #region Unity Lifecycle

        private void Awake()
        {
            if (!transport) transport = FindFirstObjectByType<UnityTransport>();
            if (!networkManager) networkManager = FindFirstObjectByType<NetworkManager>();
            
            // Init value
            _lastReachability = Application.internetReachability;
        }

        private void OnEnable()
        {
            networkManager.OnServerStarted += OnServerStarted;

            networkManager.OnServerStopped += HandleConnectionChange;
            networkManager.OnClientStopped += HandleConnectionChange;
        }

        private void OnDisable()
        {
            StopAllCoroutines();
            StopDiscovery();

            networkManager.OnServerStarted -= OnServerStarted;

            networkManager.OnServerStopped -= HandleConnectionChange;
            networkManager.OnClientStopped -= HandleConnectionChange;
        }

        private void Start()
        {
            StartConnection();
        }

        private void OnApplicationQuit() => StopDiscovery();

        #endregion

        #region Connection and Discovery Initiation

        /// <summary>
        /// Initiates the network connection routine (server or client).
        /// A small delay is used before creating the server or broadcasting as a client.
        /// </summary>
        private void StartConnection()
        {
            // Stop any ongoing connection.
            if (NetworkManager.Singleton && NetworkManager.Singleton.IsListening)
            {
                Debug.Log("[NetworkDiscovery] Stopping NetworkManager before making changes.");
                NetworkManager.Singleton.Shutdown();
            }
            StopAllCoroutines();
            
            // Restart connection
            StartCoroutine(NetworkReachabilityCheckCR());
            if (_lastReachability == NetworkReachability.NotReachable) return;
            StartCoroutine(StartConnectionCR());

            IEnumerator StartConnectionCR()
            {
                yield return new WaitForSeconds(1f);

                if (role == NetworkRole.Server) HostGame();
                else StartCoroutine(ClientBroadcastCR());
            }
        }

        /// <summary>
        /// Sets up the host's IP address and port, then starts the server.
        /// </summary>
        private void HostGame()
        {
            // Retrieve the local IP to bind as the host IP
            var localIp = GetLocalIPAddress();

            transport.SetConnectionData(localIp, transport.ConnectionData.Port);
            Debug.Log($"[LocalNetworkDiscovery] Hosting on IP: {localIp}, Port: {transport.ConnectionData.Port}");
            networkManager.StartServer();
        }

        /// <summary>
        /// Waits a set delay, then repeatedly sends broadcast messages looking for servers,
        /// stopping only once a server connection is established.
        /// </summary>
        private IEnumerator ClientBroadcastCR()
        {
            yield return StartCoroutine(StartDiscovery(false, clientBroadcastDelay));

            WaitForSeconds wait = new WaitForSeconds(clientBroadcastPingInterval);

            while (!networkManager.IsConnectedClient)
            {
                Debug.Log("[LocalNetworkDiscovery] Sending client broadcast...");
                ClientBroadcast(new DiscoveryBroadcastData(sharedKey));
                yield return wait;
            }

            StopDiscovery();
            Debug.Log("[LocalNetworkDiscovery] Found server, stopped discovery.");
        }

        /// <summary>
        /// Once the server is running, start the discovery broadcast with a delay.
        /// </summary>
        private void OnServerStarted()
        {
            StartCoroutine(StartDiscovery(true, serverBroadcastDelay));
        }

        #endregion

        #region Discovery Logic

        /// <summary>
        /// Starts discovery in server mode or client mode, setting up UDP,
        /// beginning asynchronous listening for broadcasts or responses.
        /// </summary>
        private IEnumerator StartDiscovery(bool serverMode, float initialDelay = 0f)
        {
            StopDiscovery(); // Ensure we're not already running

            IsServer = serverMode;
            IsClient = !serverMode;

            yield return new WaitForSeconds(initialDelay);

            _cancellationTokenSource = new CancellationTokenSource();

            // Server binds to the specified port; client binds to 0 (auto-select).
            _client = new UdpClient(serverMode ? port : 0)
            {
                EnableBroadcast = true,
                MulticastLoopback = false
            };

            _ = ListenAsync(
                _cancellationTokenSource.Token,
                serverMode ? ReceiveBroadcastAsync : ReceiveResponseAsync
            );

            IsRunning = true;
            Debug.Log($"[NetworkDiscovery] Started in {(serverMode ? "Server" : "Client")} mode on port {Port}.");
        }

        /// <summary>
        /// Ends discovery, shutting down the UDP client and canceling the async listener.
        /// </summary>
        private void StopDiscovery()
        {
            if (!IsRunning && _client == null && _cancellationTokenSource == null)
            {
                return;
            }

            IsRunning = false;
            IsServer = false;
            IsClient = false;

            if (_cancellationTokenSource != null)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
                _cancellationTokenSource = null;
            }

            if (_client != null)
            {
                try
                {
                    _client.Close();
                }
                catch
                {
                    // Ignored
                }

                _client = null;
            }
        }

        /// <summary>
        /// Broadcasts a message to discover servers. Only works if currently in client mode.
        /// </summary>
        private void ClientBroadcast(DiscoveryBroadcastData broadCast)
        {
            if (!IsClient)
            {
                throw new InvalidOperationException(
                    "Cannot send client broadcast while not running in client mode."
                );
            }

            IPEndPoint endPoint = new IPEndPoint(IPAddress.Broadcast, port);

            using FastBufferWriter writer = new FastBufferWriter(
                WriterInitialCapacity,
                Allocator.Temp,
                WriterMaxCapacity
            );
            WriteHeader(writer, MessageType.BroadCast);
            writer.WriteNetworkSerializable(broadCast);
            byte[] data = writer.ToArray();

            _client?.SendAsync(data, data.Length, endPoint);
        }

        #endregion

        #region Handling Incoming Messages

        /// <summary>
        /// Listens for incoming broadcasts or responses until canceled.
        /// </summary>
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

        /// <summary>
        /// Receiving responses when in client mode: read data, parse, and handle.
        /// </summary>
        private async Task ReceiveResponseAsync()
        {
            UdpReceiveResult udpReceiveResult = await _client.ReceiveAsync();
            var segment = new ArraySegment<byte>(
                udpReceiveResult.Buffer, 0, udpReceiveResult.Buffer.Length
            );

            using var reader = new FastBufferReader(segment, Allocator.Persistent);

            try
            {
                if (!ReadAndCheckHeader(reader, MessageType.Response))
                {
                    return;
                }

                reader.ReadNetworkSerializable(out DiscoveryResponseData receivedResponse);
                ResponseReceived(udpReceiveResult.RemoteEndPoint, receivedResponse);
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to receive response: {e}");
            }
        }

        /// <summary>
        /// Receiving broadcasts when in server mode: read data, process, and possibly respond.
        /// </summary>
        private async Task ReceiveBroadcastAsync()
        {
            UdpReceiveResult udpReceiveResult = await _client.ReceiveAsync();
            var segment = new ArraySegment<byte>(
                udpReceiveResult.Buffer, 0, udpReceiveResult.Buffer.Length
            );

            using var reader = new FastBufferReader(segment, Allocator.Persistent);

            try
            {
                if (!ReadAndCheckHeader(reader, MessageType.BroadCast))
                {
                    return;
                }

                reader.ReadNetworkSerializable(out DiscoveryBroadcastData receivedBroadcast);

                if (ProcessBroadcastImpl(udpReceiveResult.RemoteEndPoint, receivedBroadcast,
                        out DiscoveryResponseData response))
                {
                    SendResponse(response, udpReceiveResult.RemoteEndPoint);
                }
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to receive broadcast: {e}");
            }
        }

        /// <summary>
        /// Sends a response from server to client upon successful broadcast processing.
        /// </summary>
        private void SendResponse(DiscoveryResponseData response, IPEndPoint endPoint)
        {
            using FastBufferWriter writer =
                new FastBufferWriter(WriterInitialCapacity, Allocator.Temp, WriterMaxCapacity);
            WriteHeader(writer, MessageType.Response);
            writer.WriteNetworkSerializable(response);
            byte[] data = writer.ToArray();

            _client?.SendAsync(data, data.Length, endPoint);
        }

        /// <summary>
        /// Validates the broadcast against the shared key and nonce; prepares a response if valid.
        /// </summary>
        private bool ProcessBroadcastImpl(
            IPEndPoint sender,
            DiscoveryBroadcastData broadCast,
            out DiscoveryResponseData response
        )
        {
            string expectedHash = NetworkUtils.HashKey(sharedKey);

            if (broadCast.AuthTokenHash != expectedHash)
            {
                Debug.Log("[Authentication] Invalid key, ignoring client broadcast.");
                response = default;
                return false;
            }

            if (!nonceManager.ValidateAndStoreNonce(broadCast.Nonce, broadCast.Timestamp))
            {
                Debug.Log("[Authentication] Nonce/timestamp check failed, ignoring client broadcast.");
                response = default;
                return false;
            }

            // Build a valid response for client
            response = new DiscoveryResponseData(sharedKey, transport.ConnectionData.Port);
            return true;
        }

        /// <summary>
        /// Handles a valid response from a server once broadcast is picked up.
        /// Validates the server's authenticity, then connects the client.
        /// </summary>
        private void ResponseReceived(IPEndPoint sender, DiscoveryResponseData response)
        {
            string expectedHash = NetworkUtils.HashKey(sharedKey);

            if (response.AuthTokenHash != expectedHash)
            {
                Debug.Log($"[Authentication] Invalid server key hash from {sender}, ignoring response.");
                return;
            }

            // Normal connection process
            transport.SetConnectionData(sender.Address.ToString(), response.Port);
            networkManager.StartClient();
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Retrieve the local IPv4 address (non-loopback) of the current machine.
        /// </summary>
        private string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            var ip = host
                .AddressList
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);

            if (ip == null)
            {
                // Fallback or error handling
                Debug.LogWarning("[NetworkDiscovery] Could not find a valid IPv4 address, defaulting to localhost.");
                return "127.0.0.1";
            }

            return ip.ToString();
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

        #endregion

        #region Network Change Monitoring

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

                yield return new WaitForSeconds(3f);
            }
        }

        private void HandleConnectionChange(bool cleanChange = true) => StartConnection();
        #endregion
    }
}
