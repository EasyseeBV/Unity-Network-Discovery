using System.Collections.Generic;
using System.Linq;
using Unity.Netcode;
using UnityEngine;

namespace Coordinator.Networking
{
    /// <summary>
    /// Attach this component to a GameObject in your scene that also has (or can find) a NetworkManager.
    /// Displays debug info about NGO in the Inspector.
    /// </summary>
    [DisallowMultipleComponent]
    public class NGODebugger : MonoBehaviour
    {
        [SerializeField] private ulong localId;
        [Header("Runtime Status (Read-Only)")]
        [SerializeField, Tooltip("True if the local instance is acting as a Server.")]
        private bool isServer;
    
        [SerializeField, Tooltip("True if the local instance is acting as a Client.")]
        private bool isClient;
    
        [SerializeField, Tooltip("True if the local instance is acting as a Host.")]
        private bool isHost;

        [SerializeField, Tooltip("Number of currently connected clients, including the server/host if applicable.")]
        private int connectedClientCount;

        [SerializeField, Tooltip("List of all connected ClientIds.")]
        private List<ulong> connectedClientIds = new List<ulong>();

        [Header("Debug Log Settings")]
        [SerializeField, Tooltip("How many logs to keep in the rolling list.")]
        private int maxLogCount = 50;

        [SerializeField, Tooltip("Logs of NGO events (server start, client connect/disconnect, etc.).")]
        private List<string> eventLogs = new List<string>();

        private NetworkManager _networkManager;

        private void Awake()
        {
            // Grab the (singleton) NetworkManager—adjust if you have a different setup
            _networkManager = FindFirstObjectByType<NetworkManager>();
            if (_networkManager == null)
            {
                Debug.LogError("No NetworkManager found in scene. NGODebugger will not function correctly.");
                return;
            }

            // Subscribe to NGO events
            _networkManager.OnServerStarted += HandleServerStarted;
            _networkManager.OnClientConnectedCallback += HandleClientConnected;
            _networkManager.OnClientDisconnectCallback += HandleClientDisconnected;
        }

        private void OnDestroy()
        {
            if (_networkManager != null)
            {
                _networkManager.OnServerStarted -= HandleServerStarted;
                _networkManager.OnClientConnectedCallback -= HandleClientConnected;
                _networkManager.OnClientDisconnectCallback -= HandleClientDisconnected;
            }
        }

        private void Update()
        {
            if (_networkManager == null) return;

            // Update bools
            isServer = _networkManager.IsServer;
            isClient = _networkManager.IsClient;
            isHost   = _networkManager.IsHost;
            localId  = _networkManager.LocalClientId;

            // Update connected client info
            connectedClientCount = _networkManager.ConnectedClientsList.Count;
            connectedClientIds = _networkManager.ConnectedClientsList
                .Select(cc => cc.ClientId)
                .ToList();
        }

        // NGO Event Handlers
        private void HandleServerStarted()
        {
            AddLog("Server started!");
            // The host is also a server, so you might treat them similarly here if needed.
        }

        private void HandleClientConnected(ulong clientId)
        {
            AddLog($"Client connected: {clientId}");
        }

        private void HandleClientDisconnected(ulong clientId)
        {
            AddLog($"Client disconnected: {clientId}");
        }

        /// <summary>
        /// Adds a message to the rolling event log (kept in the Inspector).
        /// </summary>
        private void AddLog(string message)
        {
            if (eventLogs.Count >= maxLogCount)
            {
                eventLogs.RemoveAt(0); // remove oldest
            }
            eventLogs.Add($"[{System.DateTime.Now:HH:mm:ss}] {message}");
        }
    }
}
