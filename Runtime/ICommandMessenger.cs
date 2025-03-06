using Autron.Commands;
using Unity.Netcode;
using UnityEngine;

namespace Coordinator
{
    public interface ICommandMessenger
    {
        void SendCommandToAll(CommandData commandData);
        void SendCommandToId(CommandData commandData, ulong pid);
    }
}
