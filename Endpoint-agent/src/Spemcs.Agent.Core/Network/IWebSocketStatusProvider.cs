namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Minimal abstraction exposing whether the central WebSocket connection is currently active.
/// Avoids circular dependencies between AgentWorker and CentralWebSocketWorker.
/// </summary>
public interface IWebSocketStatusProvider
{
    bool IsConnected { get; }
}
