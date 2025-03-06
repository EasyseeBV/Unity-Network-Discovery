using System.Collections;
using Autron.Commands;
using Scriptable_Object_Event_Bus.Event_types;
using Unity.Collections;
using Unity.Netcode;
using UnityEngine;

/// <summary>
/// Abstract base class for handling the transmission of command messages within a networked environment.
/// Provides functionality to send commands to all connected clients or specific client IDs, leveraging
/// encryption for secure communication.
/// </summary>
public abstract class CommandMessenger : MonoBehaviour, ICommandMessenger
{
    [SerializeField] protected NetworkManager networkManager;
    [SerializeField] private CommandEvent commandEvent;

    #region Unity lifetime cycle

    private void Awake()
    {
        if (!networkManager) networkManager = FindFirstObjectByType<NetworkManager>();
        ServiceLocator.Register(this);
    }

    private void OnEnable()
    {
        networkManager.OnServerStarted += ListenForMessages;
        networkManager.OnClientStarted += ListenForMessages;
    }

    private void OnDisable()
    {
        networkManager.OnServerStarted -= ListenForMessages;
        networkManager.OnClientStarted -= ListenForMessages;
    }

    private void OnDestroy()
    {
        ServiceLocator.Unregister(this);
    }

    #endregion

    private void ListenForMessages() => StartCoroutine(StartListeningForMessages());

    // Coroutines
    /// <summary>
    /// Continuously listens for incoming messages once the network manager is actively listening.
    /// </summary>
    /// <returns>Yields execution until the network manager starts listening and subscribes to incoming unnamed messages.</returns>
    private IEnumerator StartListeningForMessages()
    {
        yield return new WaitUntil(() => networkManager.IsListening);

        networkManager.CustomMessagingManager.OnUnnamedMessage += OnUnnamedMessageReceived;
        OnConnection();
    }

    /// <summary>
    /// Sends a command to all connected clients in the network. This method should only be called by the coordinator.
    /// </summary>
    /// <param name="commandData">The command data to be sent to all connected clients.</param>
    /// <param name="networkManager">The network manager handling the messaging and client connections.</param>
    public void SendCommandToAll(CommandData commandData)
    {
        if (!networkManager || !networkManager.IsListening) return;
        if (!networkManager.IsServer)
        {
            Debug.LogError("Tried to send command to all from coordinator. This is not allowed.");
            return;
        }

        byte[] messageBytes = CommandData.SerializeCommand(commandData);
        byte[] encryptedMessage = EncryptionUtils.Encrypt(messageBytes);

        using var writer = new FastBufferWriter(FastBufferWriter.GetWriteSize(encryptedMessage), Allocator.Temp);
        writer.WriteBytesSafe(encryptedMessage);
        networkManager.CustomMessagingManager.SendUnnamedMessageToAll(writer);
    }

    /// <summary>
    /// Sends a command to a specific client or coordinator identified by the provided ID.
    /// </summary>
    /// <param name="commandData">The command data to be sent.</param>
    /// <param name="pid">The unique identifier (ID) of the target recipient.</param>
    public void SendCommandToId(CommandData commandData, ulong pid)
    {
        if (!networkManager || !networkManager.IsListening) return;

        byte[] messageBytes = CommandData.SerializeCommand(commandData);
        byte[] encryptedMessage = EncryptionUtils.Encrypt(messageBytes);

        using FastBufferWriter writer =
            new FastBufferWriter(FastBufferWriter.GetWriteSize(encryptedMessage), Allocator.Temp);
        writer.WriteBytesSafe(encryptedMessage);
        networkManager.CustomMessagingManager.SendUnnamedMessage(pid, writer);

        //Debug.Log($"Sent encrypted command to {pid}");
    }


    // Abstract Method invoked when a connection has been established.
    /// <summary>
    /// Abstract method invoked when a connection has been successfully established.
    /// Implementations should define the behavior to execute upon a connection event.
    /// </summary>
    protected abstract void OnConnection();

    // Event handlers
    /// <summary>
    /// Handles the reception of unnamed messages from the network, decrypting the data and raising the corresponding command event.
    /// </summary>
    /// <param name="sourceClientId">The unique ID of the client that sent the unnamed message.</param>
    /// <param name="reader">A FastBufferReader containing the data of the unnamed message.</param>
    private void OnUnnamedMessageReceived(ulong sourceClientId, FastBufferReader reader)
    {
        if (reader.TryBeginRead(reader.Length))
        {
            byte[] encryptedBytes = new byte[reader.Length];
            reader.ReadBytesSafe(ref encryptedBytes, encryptedBytes.Length);

            byte[] decryptedBytes = EncryptionUtils.Decrypt(encryptedBytes);
            CommandData commandData = CommandData.DeserializeCommand(decryptedBytes);

            Debug.Log($"Received decrypted command from {sourceClientId}: {commandData}");
            commandEvent?.Raise(commandData);
        }
        else
        {
            Debug.LogWarning("Could not read unnamed message data.");
        }
    }
}