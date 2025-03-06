using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Unity.Collections;
using Unity.Netcode;
using UnityEngine;

namespace Network_Discovery
{
    /// <summary>
    /// Provides functionality for discovering network hosts and clients within the local network.
    /// Designed to be extended for customizing broadcasting and discovery protocols.
    /// </summary>
    /// <typeparam name="TBroadCast">
    ///   The type of the object containing broadcasting data.
    ///   Must implement INetworkSerializable.
    /// </typeparam>
    /// <typeparam name="TResponse">
    ///   The type of the object containing responses to broadcasts.
    ///   Must implement INetworkSerializable.
    /// </typeparam>
    [DisallowMultipleComponent]
    public abstract class NetworkDiscovery<TBroadCast, TResponse> : MonoBehaviour
        where TBroadCast : INetworkSerializable, new()
        where TResponse : INetworkSerializable, new()
    {
        private const int WriterInitialCapacity = 1024;
        private const int WriterMaxCapacity = 64 * 1024;

        [SerializeField, Tooltip("The port used for broadcasting.")]
        private ushort port = 47777;

        private UdpClient _client;
        private CancellationTokenSource _cancellationTokenSource;

        /// <summary>
        /// Indicates whether discovery is running.
        /// </summary>
        public bool IsRunning { get; private set; }

        /// <summary>
        /// Indicates whether this discovery is in server mode.
        /// </summary>
        public bool IsServer { get; private set; }

        /// <summary>
        /// Indicates whether this discovery is in client mode.
        /// </summary>
        public bool IsClient { get; private set; }

        /// <summary>
        /// The port used for sending/receiving broadcasts.
        /// </summary>
        public ushort Port => port;

        private enum MessageType : byte
        {
            BroadCast = 0,
            Response = 1,
        }

        #region Unity Callbacks

        protected virtual void OnDisable() => StopDiscovery();

        protected virtual void OnApplicationQuit() => StopDiscovery();

        #endregion

        #region Abstract Methods

        /// <summary>
        /// Processes a received broadcast message. If a response is needed, return true
        /// and provide the response data via the out parameter.
        /// </summary>
        protected abstract bool ProcessBroadcast(IPEndPoint sender, TBroadCast broadCast, out TResponse response);

        /// <summary>
        /// Called when a discovery response is received (client mode).
        /// </summary>
        protected abstract void ResponseReceived(IPEndPoint sender, TResponse response);

        #endregion

        #region Public/Protected Methods

        /// <summary>
        /// Begins the discovery process in either server or client mode.
        /// This sets up the UDP client and starts listening for broadcasts or responses.
        /// It does not repeatedly send broadcasts automatically (you can do that in the derived class).
        /// </summary>
        protected IEnumerator StartDiscovery(bool serverMode, float initialDelay = 0f)
        {
            StopDiscovery(); // Make sure we aren't already running

            IsServer = serverMode;
            IsClient = !serverMode;

            // Optionally wait a bit before actually starting
            yield return new WaitForSeconds(initialDelay);

            _cancellationTokenSource = new CancellationTokenSource();

            // If server: bind to 'port' (listening for broadcasts).
            // If client: bind to 0 (auto-select port).
            _client = new UdpClient(serverMode ? port : 0)
            {
                EnableBroadcast = true,
                MulticastLoopback = false
            };

            // Start listening for either broadcasts (server mode) or responses (client mode)
            _ = ListenAsync(
                _cancellationTokenSource.Token,
                serverMode ? ReceiveBroadcastAsync : ReceiveResponseAsync
            );

            IsRunning = true;
            Debug.Log($"[NetworkDiscovery] Started in {(serverMode ? "Server" : "Client")} mode on port {Port}.");
        }

        /// <summary>
        /// Stops the discovery process, closes the UDP client, and cancels any listening tasks.
        /// </summary>
        protected void StopDiscovery()
        {
            if (!IsRunning && _client == null && _cancellationTokenSource == null)
                return; // Already stopped

            //Debug.Log("[NetworkDiscovery] Stopping discovery.");

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
                    /* ignored */
                }

                _client = null;
            }
        }

        /// <summary>
        /// Send a broadcast from the client. If not in client mode, this throws an exception.
        /// </summary>
        protected void ClientBroadcast(TBroadCast broadCast)
        {
            if (!IsClient)
                throw new InvalidOperationException(
                    "Cannot send client broadcast while not running in client mode. Call StartClient first."
                );

            IPEndPoint endPoint = new IPEndPoint(IPAddress.Broadcast, port);

            using FastBufferWriter writer = new FastBufferWriter(WriterInitialCapacity, Allocator.Temp, WriterMaxCapacity);
            WriteHeader(writer, MessageType.BroadCast);
            writer.WriteNetworkSerializable(broadCast);
            byte[] data = writer.ToArray();

            _client?.SendAsync(data, data.Length, endPoint);
        }

        #endregion

        #region Internal Async Methods

        private async Task ListenAsync(CancellationToken token, Func<Task> onReceiveTask)
        {
            // Continuously receive data until canceled
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
        /// If in client mode, we wait for a response from the server.
        /// </summary>
        private async Task ReceiveResponseAsync()
        {
            UdpReceiveResult udpReceiveResult = await _client.ReceiveAsync();
            var segment = new ArraySegment<byte>(udpReceiveResult.Buffer, 0, udpReceiveResult.Buffer.Length);

            using var reader = new FastBufferReader(segment, Allocator.Persistent);

            try
            {
                if (!ReadAndCheckHeader(reader, MessageType.Response))
                    return;

                reader.ReadNetworkSerializable(out TResponse receivedResponse);
                ResponseReceived(udpReceiveResult.RemoteEndPoint, receivedResponse);
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to receive response: {e}");
            }
        }

        /// <summary>
        /// If in server mode, we wait for a broadcast from clients and optionally respond.
        /// </summary>
        private async Task ReceiveBroadcastAsync()
        {
            UdpReceiveResult udpReceiveResult = await _client.ReceiveAsync();
            var segment = new ArraySegment<byte>(udpReceiveResult.Buffer, 0, udpReceiveResult.Buffer.Length);

            using var reader = new FastBufferReader(segment, Allocator.Persistent);

            try
            {
                if (!ReadAndCheckHeader(reader, MessageType.BroadCast))
                    return;

                reader.ReadNetworkSerializable(out TBroadCast receivedBroadcast);

                if (ProcessBroadcast(udpReceiveResult.RemoteEndPoint, receivedBroadcast, out TResponse response))
                    SendResponse(response, udpReceiveResult.RemoteEndPoint);
            }
            catch (Exception e)
            {
                Debug.LogError($"[NetworkDiscovery] Failed to receive broadcast: {e}");
            }
        }

        private void SendResponse(TResponse response, IPEndPoint endPoint)
        {
            using FastBufferWriter writer = new FastBufferWriter(WriterInitialCapacity, Allocator.Temp, WriterMaxCapacity);
            WriteHeader(writer, MessageType.Response);
            writer.WriteNetworkSerializable(response);
            byte[] data = writer.ToArray();

            _client?.SendAsync(data, data.Length, endPoint);
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
    }
}