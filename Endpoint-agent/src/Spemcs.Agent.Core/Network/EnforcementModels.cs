using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Spemcs.Agent.Core.Network;

[Flags]
public enum FirewallProfiles
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
    All = Domain | Private | Public
}

public enum FirewallAction
{
    Block = 0,
    Allow = 1
}

public enum FirewallDirection
{
    Inbound = 1,
    Outbound = 2
}

public enum FirewallProtocol
{
    TCP = 6,
    UDP = 17,
    Any = 256
}

public enum EnforcementPhase
{
    Prepared,
    ApplyingRules,
    EnforcingDefaultBlock,
    Active,
    RollingBackDefault,
    RollingBackRules,
    RolledBack,
    Failed,
    Conflict
}

public sealed record FirewallProfileBaseline(
    FirewallAction DomainDefaultOutbound,
    FirewallAction PrivateDefaultOutbound,
    FirewallAction PublicDefaultOutbound,
    FirewallProfiles ActiveProfiles,
    DateTimeOffset CapturedUtc
);

public sealed record FirewallRuleModel(
    string Name,
    string Group,
    FirewallDirection Direction,
    FirewallAction Action,
    FirewallProtocol Protocol,
    string LocalPorts,
    string RemotePorts,
    string RemoteAddresses,
    string LocalAddresses,
    string? ApplicationPath,
    FirewallProfiles Profiles,
    bool Enabled,
    string Purpose,
    Guid SessionId,
    string? ServiceName = null
)
{
    public const string SpemcsRuleGroup = "SPEMCS_EXAM_LOCKDOWN";

    public static string GenerateRuleName(Guid sessionId, string purpose, string remoteAddresses, string remotePorts)
    {
        if (string.Equals(purpose, "Mgmt", StringComparison.OrdinalIgnoreCase))
        {
            var cleanIp = remoteAddresses.Contains('/') ? remoteAddresses.Split('/')[0] : remoteAddresses;
            return $"SPEMCS-{sessionId:N}-Mgmt-{cleanIp}-{remotePorts}";
        }

        var rawKey = $"{sessionId:N}-{purpose}-{remoteAddresses}-{remotePorts}";
        using var sha = SHA256.Create();
        var hashBytes = sha.ComputeHash(Encoding.UTF8.GetBytes(rawKey));
        var hexHash = Convert.ToHexString(hashBytes)[..8];
        return $"SPEMCS-{sessionId:N}-{purpose}-{hexHash}";
    }

    public static FirewallRuleModel CreateOutboundAllow(
        Guid sessionId,
        string purpose,
        FirewallProtocol protocol,
        string remoteAddresses,
        string remotePorts,
        string localAddresses = "*",
        string? applicationPath = null,
        string? serviceName = null,
        FirewallProfiles profiles = FirewallProfiles.All)
    {
        var name = GenerateRuleName(sessionId, purpose, remoteAddresses, remotePorts);
        return new FirewallRuleModel(
            Name: name,
            Group: SpemcsRuleGroup,
            Direction: FirewallDirection.Outbound,
            Action: FirewallAction.Allow,
            Protocol: protocol,
            LocalPorts: "*",
            RemotePorts: string.IsNullOrWhiteSpace(remotePorts) ? "*" : remotePorts,
            RemoteAddresses: string.IsNullOrWhiteSpace(remoteAddresses) ? "*" : remoteAddresses,
            LocalAddresses: string.IsNullOrWhiteSpace(localAddresses) ? "*" : localAddresses,
            ApplicationPath: string.IsNullOrWhiteSpace(applicationPath) ? null : applicationPath,
            Profiles: profiles,
            Enabled: true,
            Purpose: purpose,
            SessionId: sessionId,
            ServiceName: string.IsNullOrWhiteSpace(serviceName) ? null : serviceName
        );
    }

    public static FirewallRuleModel CreateLoopbackIPv4Allow(
        Guid sessionId,
        FirewallProfiles profiles = FirewallProfiles.All)
    {
        return new FirewallRuleModel(
            Name: $"SPEMCS-{sessionId:N}-Loopback-IPv4",
            Group: SpemcsRuleGroup,
            Direction: FirewallDirection.Outbound,
            Action: FirewallAction.Allow,
            Protocol: FirewallProtocol.Any,
            LocalPorts: "*",
            RemotePorts: "*",
            RemoteAddresses: "127.0.0.1",
            LocalAddresses: "127.0.0.1",
            ApplicationPath: null,
            Profiles: profiles,
            Enabled: true,
            Purpose: "Loopback-IPv4",
            SessionId: sessionId,
            ServiceName: null
        );
    }

    public static FirewallRuleModel CreateLoopbackIPv6Allow(
        Guid sessionId,
        FirewallProfiles profiles = FirewallProfiles.All)
    {
        return new FirewallRuleModel(
            Name: $"SPEMCS-{sessionId:N}-Loopback-IPv6",
            Group: SpemcsRuleGroup,
            Direction: FirewallDirection.Outbound,
            Action: FirewallAction.Allow,
            Protocol: FirewallProtocol.Any,
            LocalPorts: "*",
            RemotePorts: "*",
            RemoteAddresses: "::/127",
            LocalAddresses: "::/127",
            ApplicationPath: null,
            Profiles: profiles,
            Enabled: true,
            Purpose: "Loopback-IPv6",
            SessionId: sessionId,
            ServiceName: null
        );
    }

    public static FirewallRuleModel CreateLoopbackAllow(
        Guid sessionId,
        FirewallProfiles profiles = FirewallProfiles.All)
    {
        return CreateLoopbackIPv4Allow(sessionId, profiles);
    }
}

public sealed record EnforcementSession(
    Guid SessionId,
    Guid PolicyId,
    int PolicyVersion,
    IReadOnlyList<FirewallRuleModel> Rules,
    FirewallProfiles TargetProfiles,
    DateTimeOffset CreatedUtc
);

public sealed record JournalRecord(
    Guid SessionId,
    Guid PolicyId,
    int PolicyVersion,
    EnforcementPhase Phase,
    DateTimeOffset StartUtc,
    DateTimeOffset UpdatedUtc,
    FirewallProfileBaseline Baseline,
    FirewallProfiles TargetProfiles,
    IReadOnlyList<FirewallRuleModel> IntendedRules,
    IReadOnlyList<string> AppliedRuleNames,
    string? LastError,
    string? ConflictDetails
);

public sealed record EnforcementStateSnapshot(
    bool IsEnforcing,
    Guid? ActiveSessionId,
    EnforcementPhase CurrentPhase,
    FirewallProfileBaseline? Baseline,
    int ActiveRuleCount,
    IReadOnlyList<string> ActiveRuleNames,
    DateTimeOffset SnapshotUtc
);

public sealed record ApplyResult(
    bool Success,
    Guid SessionId,
    EnforcementPhase Phase,
    int RulesInstalledCount,
    string? ErrorMessage = null
);

public sealed record RollbackResult(
    bool Success,
    Guid SessionId,
    int RulesRemovedCount,
    bool BaselineRestored,
    bool ConflictDetected,
    string? ErrorMessage = null
);

public sealed record RecoveryResult(
    bool RecoveryRequired,
    bool Success,
    Guid? RecoveredSessionId,
    int OrphanRulesCleaned,
    bool BaselineRestored,
    bool ConflictDetected,
    string? Details = null
);

public enum EnforcementState
{
    Idle,
    PolicyPending,
    PolicyValidated,
    Preparing,
    ApplyingRules,
    Enforcing,
    Active,
    Stopping,
    RollingBack,
    RolledBack,
    Failed,
    Conflict
}

public sealed record DurableEnforcementRecord(
    Guid SessionId,
    Guid ExamId,
    Guid PolicyId,
    int PolicyVersion,
    EnforcementState State,
    DateTimeOffset ActivationUtc,
    DateTimeOffset ExpiresAtUtc,
    DateTimeOffset LastTransitionUtc,
    string? FailureReason = null,
    bool RollbackCompleted = false,
    bool ConflictDetected = false
);

public enum PolicyUpdatePhase
{
    UpdatePending,
    UpdateApplying,
    UpdateVerifying,
    UpdateCommitting,
    UpdateCommitted,
    UpdateRollback,
    UpdateFailed
}

public sealed record DurableUpdateJournalRecord(
    Guid UpdateId,
    Guid SessionId,
    Guid ExamId,
    Guid OldPolicyId,
    int OldPolicyVersion,
    Guid NewPolicyId,
    int NewPolicyVersion,
    PolicyUpdatePhase Phase,
    DateTimeOffset StartedUtc,
    DateTimeOffset? CompletedUtc,
    IReadOnlyList<FirewallRuleModel> CandidateRules,
    IReadOnlyList<string> RetiredRuleNames,
    string? FailureReason = null
);

public sealed record PolicyUpdateResult(
    bool Success,
    Guid SessionId,
    int OldVersion,
    int NewVersion,
    string? FailureReason = null
);
