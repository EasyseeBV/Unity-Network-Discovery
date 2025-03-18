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

        private void OnApplicationQuit() => StopDiscovery();

        #endregion

        #region Event & Connection Handlers

        private void OnConnectionEvent(NetworkManager manager, ConnectionEventData data)
        {
            if (data.EventType == ConnectionEvent.ClientConnected)
            {
                Debug.Log($"A client has connected with PID {data.ClientId}");

                if (data.ClientId == networkManager.LocalClientId)
                    SendMacHandshake();
            }
        }

        private void OnServerStarted()
        {
            NetworkManager.Singleton.CustomMessagingManager
                .RegisterNamedMessageHandler("ClientMacHandshake", OnMacHandshakeMessageReceived);

            StartCoroutine(StartDiscovery(true, serverBroadcastDelay));
        }

        private void HandleConnectionChange(bool cleanChange = true) => StartConnection();

        private void StartConnection()
        {
            if (NetworkManager.Singleton && NetworkManager.Singleton.IsListening)
            {
                Debug.Log("[NetworkDiscovery] Stopping NetworkManager before making changes.");
                NetworkManager.Singleton.Shutdown();
            }

            StopAllCoroutines();
            _lastReachability = Application.internetReachability;
            StartCoroutine(NetworkReachabilityCheckCR());
            if (_lastReachability == NetworkReachability.NotReachable) return;

            if (role == NetworkRole.Server)
                HostGame();
            else
                StartCoroutine(ClientBroadcastCR());
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
                    Debug.Log($"Received handshake from client {senderClientId} with MAC {decryptedMac}.");
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
                string previous = info.CurrentClientId == ulong.MaxValue ? "Unassigned" : info.CurrentClientId.ToString();

                Debug.Log($"Old network-id for MAC {mac} was {previous}, new id is {clientId}.");
                info = new ClientInfo(info.MacAddress)
                {
                    LastSeenTicks = DateTime.Now.Ticks,
                    CurrentClientId = clientId
                };
                _clientRegistry[mac] = info;
                Debug.Log($"[ClientRegistry] MAC address recognized from broadcast or previous connection! " +
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
        }

        #endregion

        #region Network Discovery & Broadcast

        private IEnumerator StartDiscovery(bool serverMode, float initialDelay = 0f)
        {
            StopDiscovery();
            IsServer = serverMode;
            IsClient = !serverMode;
            yield return new WaitForSeconds(initialDelay);
            _cancellationTokenSource = new CancellationTokenSource();
            _client = new UdpClient(serverMode ? port : 0)
            {
                EnableBroadcast = true,
                MulticastLoopback = false
            };
            _ = ListenAsync(_cancellationTokenSource.Token, serverMode ? ReceiveBroadcastAsync : ReceiveResponseAsync);
            Debug.Log($"[NetworkDiscovery] Started in {(serverMode ? "Server" : "Client")} mode on port {Port}.");
        }

        private void StopDiscovery()
        {
            if (_client == null && _cancellationTokenSource == null)
                return;
            IsServer = false;
            IsClient = false;
            if (_cancellationTokenSource != null)
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
                _cancellationTokenSource = null;
            }
            _client = null;
        }

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
                    SendResponse(response, udpResult.RemoteEndPoint);
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
                        return nic.GetPhysicalAddress().ToString();
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

        #endregion
        
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
