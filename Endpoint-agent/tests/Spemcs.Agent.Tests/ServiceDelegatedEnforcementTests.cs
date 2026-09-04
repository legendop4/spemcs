using System;
using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Ipc;
using Spemcs.Agent.UI.Services;
using Xunit;

namespace Spemcs.Agent.Tests;

public class ServiceDelegatedEnforcementTests
{
    [Fact]
    public void ApplyNetworkPolicyPayload_SerializesAndDeserializesAccurately()
    {
        var sessionId = Guid.NewGuid();
        var examId = Guid.NewGuid();
        var signedMsg = new SignedPolicyMessagePayload(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: "{\"exam_id\":\"test\"}",
            SignatureBase64: "c2lnbmF0dXJl"
        );

        var payload = new ApplyNetworkPolicyPayload(sessionId, examId, signedMsg, (int)FirewallProfiles.All);
        var json = JsonSerializer.Serialize(payload);
        var deserialized = JsonSerializer.Deserialize<ApplyNetworkPolicyPayload>(json);

        Assert.NotNull(deserialized);
        Assert.Equal(sessionId, deserialized.SessionId);
        Assert.Equal(examId, deserialized.ExamId);
        Assert.Equal((int)FirewallProfiles.All, deserialized.TargetProfiles);
        Assert.Equal("SIGNED_NETWORK_POLICY", deserialized.SignedMessage.MessageType);
        Assert.Equal(1, deserialized.SignedMessage.ProtocolVersion);
        Assert.Equal("{\"exam_id\":\"test\"}", deserialized.SignedMessage.RawPolicyJson);
        Assert.Equal("c2lnbmF0dXJl", deserialized.SignedMessage.SignatureBase64);
    }

    /// <summary>
    /// Requirement 6: Domain, Private and Public must all be locked down.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every caller that omits <c>targetProfiles</c> must end up requesting all three profiles. The
    /// previous default was 6 - Private|Public with Domain omitted - which is the single most
    /// dangerous value this field can hold: a domain-joined machine (what a university lab PC
    /// actually is) runs under the Domain profile, so the active profile kept its original
    /// <c>DefaultOutboundAction</c> and no allow rule was scoped to it. Enforcement reported success
    /// while the network was completely unrestricted.
    /// </para>
    /// <para>
    /// Both defaults are asserted because they are declared independently - once on the IPC record
    /// and once on the client method - so they can silently drift apart. The expected value is taken
    /// from <see cref="FirewallProfiles.All"/> rather than written as a literal 7, so that adding a
    /// fourth profile to the enum updates this test's meaning instead of quietly invalidating it.
    /// </para>
    /// </remarks>
    [Fact]
    public void ApplyNetworkPolicyPayload_DefaultsToEveryFirewallProfile()
    {
        var signedMsg = new SignedPolicyMessagePayload("SIGNED_NETWORK_POLICY", 1, "{}", "sig");

        var recordDefault = new ApplyNetworkPolicyPayload(Guid.NewGuid(), Guid.NewGuid(), signedMsg);

        Assert.Equal((int)FirewallProfiles.All, recordDefault.TargetProfiles);
        Assert.Equal(7, (int)FirewallProfiles.All);

        // Domain is the profile the old default dropped; name each flag so a regression says which.
        var profiles = (FirewallProfiles)recordDefault.TargetProfiles;
        Assert.True(profiles.HasFlag(FirewallProfiles.Domain), "Domain profile must be enforced");
        Assert.True(profiles.HasFlag(FirewallProfiles.Private), "Private profile must be enforced");
        Assert.True(profiles.HasFlag(FirewallProfiles.Public), "Public profile must be enforced");

        // The client's own optional parameter is a separate declaration of the same default. It is
        // read reflectively because invoking ApplyPolicyAsync here would attempt real IPC.
        var clientDefault = typeof(IEnforcementServiceClient)
            .GetMethod(nameof(IEnforcementServiceClient.ApplyPolicyAsync))!
            .GetParameters()
            .Single(p => p.Name == "targetProfiles")
            .DefaultValue;

        Assert.Equal((int)FirewallProfiles.All, (int)clientDefault!);
    }

    [Fact]
    public void NetworkPolicyResultPayload_RoundtripsSuccessfully()
    {
        var sessionId = Guid.NewGuid();
        var payload = new NetworkPolicyResultPayload(
            Success: true,
            SessionId: sessionId,
            State: "Active",
            FailureReason: null,
            InstalledRuleCount: 3
        );

        var json = JsonSerializer.Serialize(payload);
        var deserialized = JsonSerializer.Deserialize<NetworkPolicyResultPayload>(json);

        Assert.NotNull(deserialized);
        Assert.True(deserialized.Success);
        Assert.Equal(sessionId, deserialized.SessionId);
        Assert.Equal("Active", deserialized.State);
        Assert.Null(deserialized.FailureReason);
        Assert.Equal(3, deserialized.InstalledRuleCount);
    }

    [Fact]
    public async Task PipeProtocol_CanSendAndReceive_EnforcementMessages()
    {
        var testPipeName = "spemcs-test-pipe-" + Guid.NewGuid().ToString("N");
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var serverTask = Task.Run(async () =>
        {
            await using var server = PipeProtocol.CreateServer(testPipeName);
            await server.WaitForConnectionAsync(cts.Token);
            var req = await PipeProtocol.ReadAsync(server, cts.Token);
            Assert.NotNull(req);
            Assert.Equal(MessageTypes.ApplyNetworkPolicy, req.Type);

            var p = req.Payload.Deserialize<ApplyNetworkPolicyPayload>();
            Assert.NotNull(p);

            var reply = new NetworkPolicyResultPayload(true, p.SessionId, "Active", null, 2);
            await PipeProtocol.WriteAsync(server, MessageTypes.NetworkPolicyResult, reply, cts.Token);
        });

        await using var client = PipeProtocol.CreateClient(testPipeName);
        await client.ConnectAsync(cts.Token);

        var applyPayload = new ApplyNetworkPolicyPayload(
            Guid.NewGuid(),
            Guid.NewGuid(),
            new SignedPolicyMessagePayload("SIGNED_NETWORK_POLICY", 1, "{}", "sig"),
            (int)FirewallProfiles.All
        );

        await PipeProtocol.WriteAsync(client, MessageTypes.ApplyNetworkPolicy, applyPayload, cts.Token);
        var resp = await PipeProtocol.ReadAsync(client, cts.Token);

        Assert.NotNull(resp);
        Assert.Equal(MessageTypes.NetworkPolicyResult, resp.Type);
        var result = resp.Payload.Deserialize<NetworkPolicyResultPayload>();
        Assert.NotNull(result);
        Assert.True(result.Success);
        Assert.Equal("Active", result.State);
        Assert.Equal(2, result.InstalledRuleCount);

        await serverTask;
    }
}
