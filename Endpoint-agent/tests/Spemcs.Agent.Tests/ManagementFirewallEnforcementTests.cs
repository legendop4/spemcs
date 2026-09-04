using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class ManagementFirewallEnforcementTests : IDisposable
{
    private readonly string _testJournalDir;

    public ManagementFirewallEnforcementTests()
    {
        _testJournalDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"spemcs_mgmt_fw_test_{Guid.NewGuid():N}");
        System.IO.Directory.CreateDirectory(_testJournalDir);
    }

    public void Dispose()
    {
        try { System.IO.Directory.Delete(_testJournalDir, true); } catch { }
    }

    private static ValidatedPolicy CreateTestPolicy(
        Guid sessionId,
        Guid examId,
        string mgmtIp = "127.0.0.1",
        int mgmtPort = 8002)
    {
        return new ValidatedPolicy(
            SchemaVersion: "1.0",
            KeyId: "dev-key-1",
            ExamId: examId,
            PolicyId: Guid.NewGuid(),
            Version: 1,
            VendorProfileId: null,
            AllowedDestinations: new List<PolicyDestination>
            {
                new PolicyDestination("VendorExam", new List<string> { "vendor.test" }, new List<string> { "192.168.1.50" }, new List<int> { 443 }, new List<int>())
            },
            ManagementServer: new ManagementDestination(new List<string> { mgmtIp }, mgmtPort, UseTls: false),
            NotBefore: DateTimeOffset.UtcNow.AddMinutes(-5),
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(2),
            RawPolicyJson: "{}",
            SignatureBase64: "dGVzdA=="
        );
    }

    [Fact]
    public void ManagementAndLoopbackRules_GeneratedCorrectly_PreservesProperties()
    {
        var sessionId = Guid.NewGuid();
        var examId = Guid.NewGuid();
        var policy = CreateTestPolicy(sessionId, examId, "127.0.0.1", 8002);

        var rules = EnforcementStateMachine.BuildSessionRules(sessionId, policy, FirewallProfiles.All);

        // 1. Loopback IPv4
        var loopbackV4 = rules.FirstOrDefault(r => r.Purpose == "Loopback-IPv4");
        Assert.NotNull(loopbackV4);
        Assert.Equal($"SPEMCS-{sessionId:N}-Loopback-IPv4", loopbackV4.Name);
        Assert.Equal(FirewallRuleModel.SpemcsRuleGroup, loopbackV4.Group);
        Assert.Equal(FirewallDirection.Outbound, loopbackV4.Direction);
        Assert.Equal(FirewallAction.Allow, loopbackV4.Action);
        Assert.Equal(FirewallProtocol.Any, loopbackV4.Protocol);
        Assert.Equal("127.0.0.1", loopbackV4.LocalAddresses);
        Assert.Equal("127.0.0.1", loopbackV4.RemoteAddresses);
        Assert.Equal("*", loopbackV4.LocalPorts);
        Assert.Equal("*", loopbackV4.RemotePorts);
        Assert.Null(loopbackV4.ApplicationPath);
        Assert.Null(loopbackV4.ServiceName);
        Assert.True(loopbackV4.Enabled);

        // 2. Loopback IPv6
        var loopbackV6 = rules.FirstOrDefault(r => r.Purpose == "Loopback-IPv6");
        Assert.NotNull(loopbackV6);
        Assert.Equal($"SPEMCS-{sessionId:N}-Loopback-IPv6", loopbackV6.Name);
        Assert.Equal(FirewallRuleModel.SpemcsRuleGroup, loopbackV6.Group);
        Assert.Equal(FirewallDirection.Outbound, loopbackV6.Direction);
        Assert.Equal(FirewallAction.Allow, loopbackV6.Action);
        Assert.Equal(FirewallProtocol.Any, loopbackV6.Protocol);
        Assert.Equal("::/127", loopbackV6.LocalAddresses);
        Assert.Equal("::/127", loopbackV6.RemoteAddresses);
        Assert.Equal("*", loopbackV6.LocalPorts);
        Assert.Equal("*", loopbackV6.RemotePorts);
        Assert.Null(loopbackV6.ApplicationPath);
        Assert.Null(loopbackV6.ServiceName);
        Assert.True(loopbackV6.Enabled);

        // 3. Mgmt rule
        var mgmtRule = rules.FirstOrDefault(r => r.Purpose == "Mgmt");
        Assert.NotNull(mgmtRule);
        Assert.Equal($"SPEMCS-{sessionId:N}-Mgmt-127.0.0.1-8002", mgmtRule.Name);
        Assert.Equal(FirewallRuleModel.SpemcsRuleGroup, mgmtRule.Group);
        Assert.Equal("SPEMCS_EXAM_LOCKDOWN", mgmtRule.Group);
        Assert.Equal(FirewallDirection.Outbound, mgmtRule.Direction);
        Assert.Equal(FirewallAction.Allow, mgmtRule.Action);
        Assert.Equal(FirewallProtocol.TCP, mgmtRule.Protocol);
        Assert.Equal("127.0.0.1", mgmtRule.RemoteAddresses);
        Assert.Equal("8002", mgmtRule.RemotePorts);
        Assert.Null(mgmtRule.ApplicationPath);
        Assert.Null(mgmtRule.ServiceName);
        Assert.True(mgmtRule.Enabled);
    }

    [Fact]
    public async Task RuleOrdering_LoopbackAndManagementRulesInstalledBeforeDefaultOutboundActionBlock()
    {
        var operations = new List<string>();
        var mockFw = new RecordingMockFirewall(operations);
        var journal = new SqliteRollbackJournal(_testJournalDir);
        var enforcer = new NetworkEnforcer(mockFw, journal);

        var sessionId = Guid.NewGuid();
        var examId = Guid.NewGuid();
        var policy = CreateTestPolicy(sessionId, examId, "127.0.0.1", 8002);
        var rules = EnforcementStateMachine.BuildSessionRules(sessionId, policy, FirewallProfiles.All);

        var session = new EnforcementSession(
            SessionId: sessionId,
            PolicyId: policy.PolicyId,
            PolicyVersion: policy.Version,
            Rules: rules,
            TargetProfiles: FirewallProfiles.All,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        var result = await enforcer.ApplyEnforcementAsync(session);
        Assert.True(result.Success);

        // Verify ordering: Loopback -> Mgmt -> SetDefaultOutboundAction Block
        var loopbackV4AddIndex = operations.FindIndex(op => op.StartsWith("AddRule: SPEMCS-") && op.Contains("-Loopback-IPv4"));
        var loopbackV6AddIndex = operations.FindIndex(op => op.StartsWith("AddRule: SPEMCS-") && op.Contains("-Loopback-IPv6"));
        var mgmtAddIndex = operations.FindIndex(op => op.StartsWith("AddRule: SPEMCS-") && op.Contains("-Mgmt-"));
        var blockIndex = operations.FindIndex(op => op.StartsWith("SetBlock"));

        Assert.True(loopbackV4AddIndex >= 0, "Loopback IPv4 rule must be added");
        Assert.True(loopbackV6AddIndex >= 0, "Loopback IPv6 rule must be added");
        Assert.True(mgmtAddIndex >= 0, "Management rule must be added");
        Assert.True(blockIndex >= 0, "DefaultOutboundAction=Block must be set");

        Assert.True(loopbackV4AddIndex < mgmtAddIndex, "Loopback IPv4 rule must be installed BEFORE management rule");
        Assert.True(loopbackV6AddIndex < mgmtAddIndex, "Loopback IPv6 rule must be installed BEFORE management rule");
        Assert.True(mgmtAddIndex < blockIndex, "Management rule must be installed BEFORE DefaultOutboundAction=Block");
    }

    [Fact]
    public async Task PostEnforcementHealthSuccess_EnforcementBecomesActive()
    {
        var mockFw = new MockFirewallAdapter();
        var journal = new SqliteRollbackJournal(_testJournalDir);
        var keyStore = new TrustedKeyStore();
        using var rsa = RSA.Create(2048);
        keyStore.RegisterPublicKey("dev-key-1", rsa);

        var connectivity = new SequenceManagementConnectivityVerifier(new[] { true, true }); // pre and post pass
        var receiver = new PolicyReceiver(keyStore, journal, connectivity);
        var enforcer = new NetworkEnforcer(mockFw, journal);
        var machine = new EnforcementStateMachine(receiver, enforcer, mockFw, journal, connectivity);

        var sessionId = Guid.NewGuid();
        var examId = Guid.NewGuid();
        var signedMsg = CreateSignedTestMessage(rsa, "dev-key-1", examId, 1, 8002);

        var actResult = await machine.ActivateAsync(sessionId, signedMsg, examId, FirewallProfiles.Private);

        Assert.True(actResult.Success);
        Assert.Equal(EnforcementState.Active, machine.CurrentState);
        Assert.Equal(FirewallAction.Block, mockFw.PrivateDefaultOutbound);
    }

    [Fact]
    public async Task FailedPostEnforcementHealth_TriggersRollback_RestoresBaselineFirst_RemovesOnlySpemcsRules()
    {
        var mockFw = new MockFirewallAdapter();
        // Add an unrelated rule to verify it remains untouched
        var unrelatedRule = "TEMP SPEMCS TCP 8000";
        mockFw.UnrelatedRuleNames.Add(unrelatedRule);

        var journal = new SqliteRollbackJournal(_testJournalDir);
        var keyStore = new TrustedKeyStore();
        using var rsa = RSA.Create(2048);
        keyStore.RegisterPublicKey("dev-key-1", rsa);

        // Pre-enforcement PASSES, Post-enforcement FAILS
        var connectivity = new SequenceManagementConnectivityVerifier(new[] { true, false });
        var receiver = new PolicyReceiver(keyStore, journal, connectivity);
        var enforcer = new NetworkEnforcer(mockFw, journal);
        var machine = new EnforcementStateMachine(receiver, enforcer, mockFw, journal, connectivity);

        var sessionId = Guid.NewGuid();
        var examId = Guid.NewGuid();
        var signedMsg = CreateSignedTestMessage(rsa, "dev-key-1", examId, 1, 8002);

        var actResult = await machine.ActivateAsync(sessionId, signedMsg, examId, FirewallProfiles.Private);

        // Activation must fail due to post-enforcement health failure
        Assert.False(actResult.Success);
        Assert.Equal(EnforcementState.Failed, actResult.State);

        // Baseline must be restored to Allow
        Assert.Equal(FirewallAction.Allow, mockFw.PrivateDefaultOutbound);

        // SPEMCS rules must be removed
        var spemcsRules = mockFw.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup);
        Assert.Empty(spemcsRules);

        // Unrelated rule MUST remain untouched
        Assert.True(mockFw.RuleExists(unrelatedRule));
    }

    [Fact]
    public async Task RemoveEnforcement_WhenActivationNeverOwnedState_NoFalseConflict()
    {
        var mockFw = new MockFirewallAdapter();
        var journal = new SqliteRollbackJournal(_testJournalDir);
        var enforcer = new NetworkEnforcer(mockFw, journal);

        var randomSessionId = Guid.NewGuid();
        var rollbackResult = await enforcer.RemoveEnforcementAsync(randomSessionId);

        Assert.True(rollbackResult.Success);
        Assert.False(rollbackResult.ConflictDetected);
        Assert.False(rollbackResult.BaselineRestored);
        Assert.Equal(0, rollbackResult.RulesRemovedCount);
    }

    [Fact]
    public async Task PartialRuleApplicationFailure_AlwaysRollsBackCleanly_WithNoFalseConflict()
    {
        var operations = new List<string>();
        var failingFw = new FailingOnNthRuleMockFirewall(operations, failOnRuleIndex: 2);
        var journal = new SqliteRollbackJournal(_testJournalDir);
        var enforcer = new NetworkEnforcer(failingFw, journal);

        var sessionId = Guid.NewGuid();
        var examId = Guid.NewGuid();
        var policy = CreateTestPolicy(sessionId, examId, "127.0.0.1", 8002);
        var rules = EnforcementStateMachine.BuildSessionRules(sessionId, policy, FirewallProfiles.All);

        var session = new EnforcementSession(
            SessionId: sessionId,
            PolicyId: policy.PolicyId,
            PolicyVersion: policy.Version,
            Rules: rules,
            TargetProfiles: FirewallProfiles.All,
            CreatedUtc: DateTimeOffset.UtcNow
        );

        var applyResult = await enforcer.ApplyEnforcementAsync(session);

        // Application must fail
        Assert.False(applyResult.Success);
        Assert.Contains("Value does not fall within the expected range", applyResult.ErrorMessage);

        // Check journal record: phase must be RolledBack, NOT Conflict
        var sessionRecord = journal.GetSession(sessionId);
        Assert.NotNull(sessionRecord);
        Assert.Equal(EnforcementPhase.RolledBack, sessionRecord.Phase);

        // Rules installed before failure must be cleanly removed
        var remainingRules = failingFw.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup);
        Assert.Empty(remainingRules);

        // Baseline must remain/be restored without external conflict
        var baseline = failingFw.GetBaseline();
        Assert.Equal(FirewallAction.Allow, baseline.DomainDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, baseline.PrivateDefaultOutbound);
        Assert.Equal(FirewallAction.Allow, baseline.PublicDefaultOutbound);
    }

    private static SignedPolicyMessage CreateSignedTestMessage(RSA rsa, string keyId, Guid examId, int version, int mgmtPort)
    {
        var policyId = Guid.NewGuid();
        var rawJson = $@"{{
            ""allowed_destinations"": [
                {{
                    ""domains"": [""vendor.local""],
                    ""ip_ranges"": [""192.168.10.1""],
                    ""name"": ""VendorExam"",
                    ""tcp_ports"": [443],
                    ""udp_ports"": []
                }}
            ],
            ""exam_id"": ""{examId}"",
            ""expires_at"": ""2035-01-01T00:00:00Z"",
            ""key_id"": ""{keyId}"",
            ""management_server"": {{
                ""ip_addresses"": [""127.0.0.1""],
                ""port"": {mgmtPort}
            }},
            ""not_before"": ""2025-01-01T00:00:00Z"",
            ""policy_id"": ""{policyId}"",
            ""schema_version"": ""1.0"",
            ""vendor_profile_id"": null,
            ""version"": {version}
        }}";

        using var doc = System.Text.Json.JsonDocument.Parse(rawJson);
        using var ms = new System.IO.MemoryStream();
        using (var writer = new System.Text.Json.Utf8JsonWriter(ms))
        {
            doc.WriteTo(writer);
        }
        var canonicalJson = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        var sigBytes = rsa.SignData(System.Text.Encoding.UTF8.GetBytes(canonicalJson), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        return new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: canonicalJson,
            SignatureBase64: Convert.ToBase64String(sigBytes)
        );
    }

    private sealed class SequenceManagementConnectivityVerifier : IManagementConnectivityVerifier
    {
        private readonly Queue<bool> _results;

        public SequenceManagementConnectivityVerifier(IEnumerable<bool> results)
        {
            _results = new Queue<bool>(results);
        }

        public Task<bool> VerifyConnectivityAsync(ManagementDestination destination, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_results.Count > 0 ? _results.Dequeue() : true);
        }
    }

    private sealed class RecordingMockFirewall : IFirewallAdapter
    {
        private readonly List<string> _operations;
        private readonly List<FirewallRuleModel> _rules = new();
        public FirewallAction DomainDefaultOutbound { get; set; } = FirewallAction.Allow;
        public FirewallAction PrivateDefaultOutbound { get; set; } = FirewallAction.Allow;
        public FirewallAction PublicDefaultOutbound { get; set; } = FirewallAction.Allow;

        public RecordingMockFirewall(List<string> operations)
        {
            _operations = operations;
        }

        public FirewallProfileBaseline GetBaseline() => new(
            DomainDefaultOutbound, PrivateDefaultOutbound, PublicDefaultOutbound,
            FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public,
            DateTimeOffset.UtcNow);

        public void SetDefaultOutboundAction(FirewallProfiles profile, FirewallAction action)
        {
            _operations.Add($"SetBlock: {profile} -> {action}");
            if (profile.HasFlag(FirewallProfiles.Domain)) DomainDefaultOutbound = action;
            if (profile.HasFlag(FirewallProfiles.Private)) PrivateDefaultOutbound = action;
            if (profile.HasFlag(FirewallProfiles.Public)) PublicDefaultOutbound = action;
        }

        public void AddRule(FirewallRuleModel rule)
        {
            _operations.Add($"AddRule: {rule.Name}");
            _rules.Add(rule);
        }

        public bool RemoveRule(string ruleName)
        {
            _operations.Add($"RemoveRule: {ruleName}");
            return _rules.RemoveAll(r => r.Name == ruleName) > 0;
        }

        public bool RuleExists(string ruleName) => _rules.Any(r => r.Name == ruleName);

        public IReadOnlyList<string> GetRuleNamesByGroup(string group) =>
            _rules.Where(r => r.Group == group).Select(r => r.Name).ToList();

        public IReadOnlyList<FirewallRuleModel> GetRulesByGroup(string group) =>
            _rules.Where(r => r.Group == group).ToList();
    }

    private sealed class FailingOnNthRuleMockFirewall : IFirewallAdapter
    {
        private readonly List<string> _operations;
        private readonly List<FirewallRuleModel> _rules = new();
        private readonly int _failOnRuleIndex;
        private int _addRuleCalls;

        public FirewallAction DomainDefaultOutbound { get; set; } = FirewallAction.Allow;
        public FirewallAction PrivateDefaultOutbound { get; set; } = FirewallAction.Allow;
        public FirewallAction PublicDefaultOutbound { get; set; } = FirewallAction.Allow;

        public FailingOnNthRuleMockFirewall(List<string> operations, int failOnRuleIndex)
        {
            _operations = operations;
            _failOnRuleIndex = failOnRuleIndex;
        }

        public FirewallProfileBaseline GetBaseline() => new(
            DomainDefaultOutbound, PrivateDefaultOutbound, PublicDefaultOutbound,
            FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public,
            DateTimeOffset.UtcNow);

        public void SetDefaultOutboundAction(FirewallProfiles profile, FirewallAction action)
        {
            _operations.Add($"SetBlock: {profile} -> {action}");
            if (profile.HasFlag(FirewallProfiles.Domain)) DomainDefaultOutbound = action;
            if (profile.HasFlag(FirewallProfiles.Private)) PrivateDefaultOutbound = action;
            if (profile.HasFlag(FirewallProfiles.Public)) PublicDefaultOutbound = action;
        }

        public void AddRule(FirewallRuleModel rule)
        {
            _addRuleCalls++;
            if (_addRuleCalls == _failOnRuleIndex)
            {
                throw new ArgumentException("Value does not fall within the expected range.");
            }
            _operations.Add($"AddRule: {rule.Name}");
            _rules.Add(rule);
        }

        public bool RemoveRule(string ruleName)
        {
            _operations.Add($"RemoveRule: {ruleName}");
            return _rules.RemoveAll(r => r.Name == ruleName) > 0;
        }

        public bool RuleExists(string ruleName) => _rules.Any(r => r.Name == ruleName);

        public IReadOnlyList<string> GetRuleNamesByGroup(string group) =>
            _rules.Where(r => r.Group == group).Select(r => r.Name).ToList();

        public IReadOnlyList<FirewallRuleModel> GetRulesByGroup(string group) =>
            _rules.Where(r => r.Group == group).ToList();
    }
}
