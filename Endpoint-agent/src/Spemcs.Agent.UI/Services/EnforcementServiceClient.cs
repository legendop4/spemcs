using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Ipc;

namespace Spemcs.Agent.UI.Services;

public interface IEnforcementServiceClient
{
    /// <param name="targetProfiles">
    /// Bitmask of <c>FirewallProfiles</c>. Defaults to 7 (Domain|Private|Public = All) to match
    /// <see cref="ApplyNetworkPolicyPayload.TargetProfiles"/>. Requirement 6: every profile must be
    /// locked down. The former default of 6 omitted Domain, which is the profile a domain-joined lab
    /// PC actually runs under - so the lockdown silently did not apply there.
    /// </param>
    Task<NetworkPolicyResultPayload> ApplyPolicyAsync(Guid sessionId, Guid examId, SignedPolicyMessagePayload signedMessage, int targetProfiles = 7, CancellationToken cancellationToken = default);
    Task<NetworkPolicyResultPayload> UpdatePolicyAsync(Guid sessionId, Guid examId, SignedPolicyMessagePayload signedMessage, CancellationToken cancellationToken = default);
    Task<NetworkPolicyResultPayload> RemovePolicyAsync(Guid sessionId, string reason = "Exam stopped", CancellationToken cancellationToken = default);
}

public sealed class EnforcementServiceClient : IEnforcementServiceClient
{
    private readonly string _pipeName;

    public EnforcementServiceClient(string pipeName = PipeNames.Control)
    {
        _pipeName = pipeName;
    }

    public async Task<NetworkPolicyResultPayload> ApplyPolicyAsync(
        Guid sessionId,
        Guid examId,
        SignedPolicyMessagePayload signedMessage,
        // 7 == FirewallProfiles.All; see the interface remarks. Must stay in step with the
        // ApplyNetworkPolicyPayload default so an omitted argument and an omitted record
        // parameter cannot disagree about which profiles get locked down.
        int targetProfiles = 7,
        CancellationToken cancellationToken = default)
    {
        var payload = new ApplyNetworkPolicyPayload(sessionId, examId, signedMessage, targetProfiles);
        return await SendRequestAsync(MessageTypes.ApplyNetworkPolicy, payload, cancellationToken);
    }

    public async Task<NetworkPolicyResultPayload> UpdatePolicyAsync(
        Guid sessionId,
        Guid examId,
        SignedPolicyMessagePayload signedMessage,
        CancellationToken cancellationToken = default)
    {
        var payload = new ApplyNetworkPolicyPayload(sessionId, examId, signedMessage);
        return await SendRequestAsync(MessageTypes.UpdateNetworkPolicy, payload, cancellationToken);
    }

    public async Task<NetworkPolicyResultPayload> RemovePolicyAsync(
        Guid sessionId,
        string reason = "Exam stopped",
        CancellationToken cancellationToken = default)
    {
        var payload = new RemoveNetworkPolicyPayload(sessionId, reason);
        return await SendRequestAsync(MessageTypes.RemoveNetworkPolicy, payload, cancellationToken);
    }

    private async Task<NetworkPolicyResultPayload> SendRequestAsync(string messageType, object payload, CancellationToken cancellationToken)
    {
        try
        {
            await using var client = PipeProtocol.CreateClient(_pipeName);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(15));

            await client.ConnectAsync(timeoutCts.Token);
            await PipeProtocol.WriteAsync(client, messageType, payload, timeoutCts.Token);

            var response = await PipeProtocol.ReadAsync(client, timeoutCts.Token);
            if (response != null && response.Type == MessageTypes.NetworkPolicyResult)
            {
                var result = response.Payload.Deserialize<NetworkPolicyResultPayload>();
                if (result != null) return result;
            }

            return new NetworkPolicyResultPayload(false, Guid.Empty, "Failed", "Empty or invalid response from Service");
        }
        catch (Exception ex)
        {
            return new NetworkPolicyResultPayload(false, Guid.Empty, "Failed", $"Service IPC error: {ex.Message}");
        }
    }
}
