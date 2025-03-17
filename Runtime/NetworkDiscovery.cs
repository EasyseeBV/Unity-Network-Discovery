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
        private Coroutine _networkReachabilityCheckCR;
        private Coroutine _broadcastCR;
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
            // Additional reference checks
            if (!transport)
            {
                transport = FindFirstObjectByType<UnityTransport>();
                if (!transport)
                {
                    Debug.LogError("[NetworkDiscovery] UnityTransport not set or found! Discovery cannot run.");
                }
            }

            if (!networkManager)
            {
                networkManager = FindFirstObjectByType<NetworkManager>();
                if (!networkManager)
                {
                    Debug.LogError("[NetworkDiscovery] NetworkManager not set or found! Discovery cannot run.");
                }
            }
        }

        private void OnEnable()
        {
            if (_networkReachabilityCheckCR != null)
            {
                StopCoroutine(_networkReachabilityCheckCR);
            }
            _networkReachabilityCheckCR = StartCoroutine(NetworkReachabilityCheckCR());

            if (networkManager != null)
            {
                networkManager.OnServerStarted += OnServerStarted;
                networkManager.OnServerStopped += HandleConnectionChange;
                networkManager.OnClientStopped += HandleConnectionChange;
            }
        }

        private void OnDisable()
        {
            StopAllCoroutines();
            StopDiscovery();

            if (networkManager != null)
            {
                networkManager.OnServerStarted -= OnServerStarted;
                networkManager.OnServerStopped -= HandleConnectionChange;
                networkManager.OnClientStopped -= HandleConnectionChange;
            }
        }

        private void OnApplicationQuit() => StopDiscovery();

        private void Start()
        {
            // If references are missing, don't attempt discovery.
            if (!networkManager || !transport)
            {
                return;
            }

            StartConnection();
        }

        #endregion

        #region Connection and Discovery Initiation

        /// <summary>
        /// Initiates the network connection routine (server or client).
        /// A small delay is used before creating the server or broadcasting as a client.
        /// </summary>
        private void StartConnection()
        {
            if (!networkManager || !transport) return;

            if (_broadcastCR != null) StopCoroutine(_broadcastCR);
            _broadcastCR = StartCoroutine(StartConnectionCR());

            IEnumerator StartConnectionCR()
            {
                yield return new WaitForSeconds(0.5f);

                // Wait until any network shutdown in progress has completed.
                yield return new WaitUntil(() => !networkManager.ShutdownInProgress);

                if (role == NetworkRole.Server)
                {
                    HostGame();
                }
                else
                {
                    // If not hosting, start broadcasting as a client.
                    StartCoroutine(ClientBroadcastCR());
                }
            }
        }

        /// <summary>
        /// Sets up the host's IP address and port, then starts the server.
        /// </summary>
        private void HostGame()
        {
            if (!transport) return;

            string localIp;

            // Safely try to gather host entry
            try
            {
                localIp = Dns
                    .GetHostEntry(Dns.GetHostName())
                    .AddressList
                    .First(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .ToString();
            }
            catch (Exception e)
            {
                Debug.LogError($"[LocalNetworkDiscovery] Failed to obtain local IP: {e}");
                return;
            }

            Debug.Log($"[LocalNetworkDiscovery] Hosting on IP: {localIp}, Port: {transport.ConnectionData.Port}");
            transport.SetConnectionData(localIp, transport.ConnectionData.Port);
            networkManager.StartServer();
        }

        /// <summary>
        /// Waits a set delay, then repeatedly sends broadcast messages looking for servers,
        /// stopping only once a server connection is established.
        /// </summary>
        private IEnumerator ClientBroadcastCR()
        {
            // StartDiscovery for client mode after clientBroadcastDelay
            yield return StartCoroutine(StartDiscovery(false, clientBroadcastDelay));

            var wait = new WaitForSeconds(clientBroadcastPingInterval);

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

            // If in server mode, bind to the specified port; client binds to 0 (auto-select).
            // Added try-catch in case the port is in use or unavailable.
            try
            {
                _client = new UdpClient(serverMode ? port : 0)
                {
                    EnableBroadcast = true,
                    MulticastLoopback = false
                };
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to create UdpClient: {e}");
                yield break;
            }

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
                    _client.Dispose(); // Additional cleanup
                }
                catch
                {
                    // Intentionally ignore any exceptions during disposal
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
                Debug.LogWarning("[NetworkDiscovery] Attempted client broadcast while not in client mode.");
                return;
            }

            if (_client == null)
            {
                Debug.LogError("[NetworkDiscovery] UDP client is not initialized, cannot broadcast.");
                return;
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

            try
            {
                _client.SendAsync(data, data.Length, endPoint);
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to send broadcast: {e}");
            }
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
                    // Each iteration calls the relevant receive method.
                    await onReceiveTask().ConfigureAwait(false);
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
            if (_client == null) return;

            UdpReceiveResult udpReceiveResult;
            try
            {
                udpReceiveResult = await _client.ReceiveAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Debug.LogError($"[NetworkDiscovery] Error receiving client response: {ex}");
                return;
            }

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
                ResponseReceivedImpl(udpReceiveResult.RemoteEndPoint, receivedResponse);
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to receive response: {e}");
            }
        }

        /// <summary>
        /// Receiving broadcasts when in server mode: read data, process, and possibly respond.
        /// </summary>
        public async Task ReceiveBroadcastAsync()
        {
            if (_client == null)
                return;

            UdpReceiveResult udpReceiveResult;
            try
            {
                udpReceiveResult = await _client.ReceiveAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Debug.LogError($"[NetworkDiscovery] Error receiving server broadcast: {ex}");
                return;
            }

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

                if (ProcessBroadcastImpl(udpReceiveResult.RemoteEndPoint, receivedBroadcast, out DiscoveryResponseData response))
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
        /// Sends a response from the server to the client upon successful broadcast processing.
        /// </summary>
        private void SendResponse(DiscoveryResponseData response, IPEndPoint endPoint)
        {
            if (_client == null) return;

            using FastBufferWriter writer = new FastBufferWriter(
                WriterInitialCapacity,
                Allocator.Temp,
                WriterMaxCapacity
            );
            WriteHeader(writer, MessageType.Response);
            writer.WriteNetworkSerializable(response);
            byte[] data = writer.ToArray();

            try
            {
                _client.SendAsync(data, data.Length, endPoint);
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to send response: {e}");
            }
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
            response = default;

            // Compare hash to ensure the shared keys match
            string expectedHash = NetworkUtils.HashKey(sharedKey);

            if (broadCast.AuthTokenHash != expectedHash)
            {
                Debug.Log("[Authentication] Invalid key, ignoring client broadcast.");
                return false;
            }

            // Check nonce/timestamp to prevent replay attacks
            if (!nonceManager.ValidateAndStoreNonce(broadCast.Nonce, broadCast.Timestamp))
            {
                Debug.Log("[Authentication] Nonce/timestamp check failed, ignoring client broadcast.");
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
        private void ResponseReceivedImpl(IPEndPoint sender, DiscoveryResponseData response)
        {
            // Check the server's authentication hash
            string expectedHash = NetworkUtils.HashKey(sharedKey);

            if (response.AuthTokenHash != expectedHash)
            {
                Debug.Log($"[Authentication] Invalid server key hash from {sender}, ignoring response.");
                return;
            }

            // Then connect the client
            transport.SetConnectionData(sender.Address.ToString(), response.Port);
            networkManager.StartClient();
        }

        #endregion

        #region Helper Methods

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

        /// <summary>
        /// Periodically checks Unity's network reachability status.
        /// If it changes, handles any required reconnection or cleanup logic.
        /// </summary>
        private IEnumerator NetworkReachabilityCheckCR()
        {
            while (true)
            {
                NetworkReachability currentReachability = Application.internetReachability;
                if (currentReachability != _lastReachability)
                {
                    _lastReachability = currentReachability;
                    HandleNetworkChange();
                }

                yield return new WaitForSeconds(3f);
            }
        }

        /// <summary>
        /// Called when the server or client shuts down.
        /// </summary>
        private void HandleConnectionChange(bool cleanChange)
        {
            Debug.Log("Connection state changed.");
            if (NetworkManager.Singleton != null && NetworkManager.Singleton.IsListening)
            {
                Debug.Log("[NetworkDiscovery] Stopping NetworkManager before making changes.");
                NetworkManager.Singleton.Shutdown();
            }

            // Attempt to restart the connection after shutdown
            StartConnection();
        }

        /// <summary>
        /// Monitors changes to the internet reachability. If no network is found,
        /// the manager is shut down. Otherwise, attempts to reconfigure and reconnect.
        /// </summary>
        private void HandleNetworkChange()
        {
            Debug.Log($"Network state changed to: {_lastReachability}");

            if (_lastReachability == NetworkReachability.NotReachable)
            {
                if (NetworkManager.Singleton)
                {
                    Debug.Log("[NetworkDiscovery] Network unreachable, stopping NetworkManager.");
                    NetworkManager.Singleton.Shutdown();
                }
            }

            if (transport != null)
            {
                if (NetworkManager.Singleton != null && NetworkManager.Singleton.IsListening)
                {
                    Debug.Log("[NetworkDiscovery] Network state changed, stopping NetworkManager before reconfiguration.");
                    NetworkManager.Singleton.Shutdown();
                }

                // Example of reconfiguring the transport with a new IP or hostname.
                transport.SetConnectionData("NEW_IP_OR_HOSTNAME", transport.ConnectionData.Port);
                Debug.Log("Transport connection data updated.");

                // Restart discovery/connection under new conditions.
                StartConnection();
            }
        }

        #endregion
    }
}