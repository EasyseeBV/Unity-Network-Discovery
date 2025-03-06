using System.Collections;
using Autron.Commands;
using UnityEngine;

namespace Coordinator.Networking
{
    /// <summary>
    /// CommandsCoordinator is responsible for managing client connection events
    /// and handling delayed messaging for the connected clients. It extends
    /// the functionality of CommandMessenger by subscribing to specific callbacks
    /// defined by the NetworkManager.
    /// </summary>
    public class CommandsCoordinator : CommandMessenger
    {
        /// <summary>
        /// Handles the connection event by subscribing to the network manager's client connection callback.
        /// This method is triggered internally when a connection event occurs.
        /// </summary>
        protected override void OnConnection()
        {
            networkManager.OnClientConnectedCallback += OnClientConnected;
        }

        /// <summary>
        /// Handles actions when a new client connects to the network.
        /// </summary>
        /// <param name="pid">The unique identifier of the connected client.</param>
        private void OnClientConnected(ulong pid)
        {
            StartCoroutine(SendTestMessageDelayed(pid));
        }

        /// <summary>
        /// Sends a test command to a specific client after a delay.
        /// </summary>
        /// <param name="pid">The unique identifier of the client to send the command to.</param>
        /// <returns>An enumerator that handles the delayed sending operation.</returns>
        private IEnumerator SendTestMessageDelayed(ulong pid)
        {
            yield return new WaitForSeconds(2f);
            
            CommandData data = new(
                new CommandKey(420, 69), null,
                new(69, 69));
            SendCommandToId(data, pid);
        }
    }
}