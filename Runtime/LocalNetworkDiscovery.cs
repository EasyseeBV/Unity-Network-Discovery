using System.Collections;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Unity.Netcode;
using Unity.Netcode.Transports.UTP;
using UnityEngine;

namespace Network_Discovery
{
    /// <summary>
    /// Provides functionalities for discovering and responding to devices on the local network in Unity Netcode projects.
    /// Inherits from NetworkDiscovery, utilizing DiscoveryBroadcastData for sending and DiscoveryResponseData for receiving network data.
    /// Maintains network roles and processes discovery mechanics such as validating authentication tokens and nonces.
    /// </summary>
    public class LocalNetworkDiscovery : NetworkDiscovery<DiscoveryBroadcastData, DiscoveryResponseData>
    {
        public static LocalNetworkDiscovery Instance { get; private set; }

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

        [Header("Authentication")]
        [Tooltip("A shared secret key. Must match on both client and server.")]
        [SerializeField, TextArea(1, 6)]
        private string sharedKey = "mySecretKey";

        // Nonce manager to prevent replay attacks
        private readonly NonceManager nonceManager = new();

        private void Awake()
        {
            if (!transport) transport = FindFirstObjectByType<UnityTransport>();
            if (!networkManager) networkManager = FindFirstObjectByType<NetworkManager>();
        }

        private void OnEnable()
        {
            // Ensure only one instance
            if (Instance != null)
            {
                Destroy(Instance.gameObject);
            }

            Instance = this;

            networkManager.OnServerStarted += OnServerStarted;
            networkManager.OnServerStopped += StartConnection;
            networkManager.OnClientStopped += StartConnection;
        }

        protected override void OnDisable()
        {
            base.OnDisable();

            networkManager.OnServerStarted -= OnServerStarted;
            networkManager.OnServerStopped -= StartConnection;
            networkManager.OnClientStopped -= StartConnection;
        }

        private void Start()
        {
            // Attempt to start right away
            StartConnection(cleanShutdown: true);
        }

        /// <summary>
        /// Handles the initialization of the network connection as either a server or a client
        /// based on the assigned network role. Optionally performs a clean shutdown before starting.
        /// </summary>
        /// <param name="cleanShutdown">Indicates if a clean shutdown should be performed before starting the connection.</param>
        private void StartConnection(bool cleanShutdown)
        {
            StartCoroutine(StartConnectionCR());

            IEnumerator StartConnectionCR()
            {
                yield return new WaitForSeconds(0.5f);

                // If netcode is shutting down, skip
                if (networkManager.ShutdownInProgress)
                    yield break;

                if (role == NetworkRole.Server)
                {
                    HostGame();
                }
                else
                {
                    // Start as client
                    StartCoroutine(ClientBroadcastCR());
                }
            }
        }

        /// <summary>
        /// Configures networking details such as IP address and port, initiates the server mode
        /// by starting the Netcode server, and subsequently begins the discovery broadcast in server mode.
        /// </summary>
        private void HostGame()
        {
            // Retrieve local IP address of host machine
            var localIp = Dns.GetHostEntry(Dns.GetHostName())
                .AddressList
                .First(a => a.AddressFamily == AddressFamily.InterNetwork)
                .ToString();

            Debug.Log($"[LocalNetworkDiscovery] Hosting on IP: {localIp}, Port: {transport.ConnectionData.Port}");

            // Set connection data, then start server
            transport.SetConnectionData(localIp, transport.ConnectionData.Port);
            networkManager.StartServer();
        }

        /// <summary>
        /// Continuously sends client broadcast packets to search for servers on the local network.
        /// Broadcasts begin after an initial delay and occur at a specified interval.
        /// Stops broadcasting when a connection to a server is established.
        /// </summary>
        /// <returns>An IEnumerator for coroutine execution.</returns>
        private IEnumerator ClientBroadcastCR()
        {
            // Start discovery in client mode
            yield return StartCoroutine(StartDiscovery(serverMode: false, initialDelay: clientBroadcastDelay));

            WaitForSeconds wait = new WaitForSeconds(clientBroadcastPingInterval);

            // Repeatedly broadcast until connected
            while (!networkManager.IsConnectedClient)
            {
                Debug.Log("[LocalNetworkDiscovery] Sending client broadcast...");
                ClientBroadcast(new DiscoveryBroadcastData(sharedKey));
                yield return wait;
            }

            // Once connected, we can stop discovery entirely
            StopDiscovery();
            Debug.Log("[LocalNetworkDiscovery] Found server, stopped discovery.");
        }

        /// <summary>
        /// Handles actions to initialize server-specific discovery mechanisms
        /// once the server has successfully started. Incorporates a delay before
        /// initiating discovery broadcasts dependent on the configured broadcast settings.
        /// </summary>
        private void OnServerStarted()
        {
            StartCoroutine(StartDiscovery(serverMode: true, initialDelay: serverBroadcastDelay));
        }

        /// <summary>
        /// Processes an incoming broadcast received by the server, validates it based on
        /// authentication and nonce checks, and generates a response data object for the client.
        /// </summary>
        /// <param name="sender">The endpoint of the sender that broadcasted the message.</param>
        /// <param name="broadCast">The broadcast data received from the client.</param>
        /// <param name="response">The response data to be sent back to the client if the broadcast is valid.</param>
        /// <returns>Returns true if the broadcast is valid and a response is generated; otherwise, false.</returns>
        protected override bool ProcessBroadcast(IPEndPoint sender, DiscoveryBroadcastData broadCast,
            out DiscoveryResponseData response)
        {
            string expectedHash = NetworkUtils.HashKey(sharedKey);

            //Debug.Log($"Expected hash: {expectedHash}, received hash: {broadCast.AuthTokenHash}");
        
            // 1) Check shared key
            if (broadCast.AuthTokenHash != expectedHash)
            {
                Debug.Log("[Authentication] Invalid key, ignoring client broadcast.");
                response = default;
                return false;
            }

            // 2) Validate nonce/timestamp
            if (!nonceManager.ValidateAndStoreNonce(broadCast.Nonce, broadCast.Timestamp))
            {
                Debug.Log("[Authentication] Nonce/timestamp check failed, ignoring client broadcast.");
                response = default;
                return false;
            }

            // 3) Build a valid response with IP/port
            response = new DiscoveryResponseData(sharedKey, transport.ConnectionData.Port);
            return true;
        }

        /// <summary>
        /// Handles the response received from the server during local network discovery in client mode.
        /// Verifies the authentication token and initiates the client connection if validated.
        /// </summary>
        /// <param name="sender">The endpoint of the server sending the response.</param>
        /// <param name="response">The data received from the server in the response.</param>
        protected override void ResponseReceived(IPEndPoint sender, DiscoveryResponseData response)
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
    }
}