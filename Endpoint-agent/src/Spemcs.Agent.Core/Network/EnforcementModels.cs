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

/// <summary>
/// Turns an untrusted integer profile mask into a profile set that satisfies requirement 6.
/// </summary>
/// <remarks>
/// <para>
/// The profile mask arrives on the control pipe as a plain integer on the ENCLOSING frame - it is
/// not inside the signed policy bytes, so unlike the destinations and the approved browser it is
/// unauthenticated. The pipe's ACL grants <c>AuthenticatedUser</c> read/write (see
/// <c>PipeProtocol.CreateServer</c>) because the interactive agent UI is not elevated, which means
/// any logged-on user can send this field. A cast straight to <see cref="FirewallProfiles"/> would
/// therefore let a candidate request <c>2</c> (Private only) and receive a "successful" lockdown
/// that leaves the Domain profile - the one a domain-joined lab PC actually runs under - at its
/// original <c>DefaultOutboundAction</c>.
/// </para>
/// <para>
/// Requirement 6 makes this an easy decision: all three profiles are always in scope, so the field
/// carries no legitimate variation and does not need to be trusted. Anything that is not the
/// complete set is widened to <see cref="FirewallProfiles.All"/>. Widening rather than rejecting is
/// deliberate - it fails toward MORE restriction, so a malformed or hostile value cannot stop an
/// exam from starting, and it cannot weaken one either. The anomaly is reported so it appears in the
/// service log instead of passing silently.
/// </para>
/// </remarks>
public static class FirewallProfileSet
{
    /// <summary>All bits that correspond to a real profile; anything else is meaningless to Windows.</summary>
    private const int KnownBits = (int)FirewallProfiles.All;

    /// <summary>
    /// Normalizes <paramref name="wireValue"/> to the profile set enforcement will actually use.
    /// </summary>
    /// <param name="wireValue">The raw integer received from the control pipe.</param>
    /// <param name="anomaly">
    /// Human-readable description of why the value was not usable as-is, or <c>null</c> when it
    /// already named every profile. Callers are expected to log this.
    /// </param>
    /// <returns>Always <see cref="FirewallProfiles.All"/>; the return type is explicit for clarity.</returns>
    public static FirewallProfiles FromUntrustedWireValue(int wireValue, out string? anomaly)
    {
        if (wireValue == KnownBits)
        {
            anomaly = null;
            return FirewallProfiles.All;
        }

        var undefinedBits = wireValue & ~KnownBits;
        var missing = (FirewallProfiles)(KnownBits & ~wireValue);

        anomaly = undefinedBits != 0
            ? $"Control-pipe target profile mask {wireValue} sets bits ({undefinedBits}) that match no Windows firewall profile. " +
              $"Widening to {FirewallProfiles.All} per requirement 6."
            : $"Control-pipe target profile mask {wireValue} omits {missing}, which would leave that profile's " +
              $"DefaultOutboundAction untouched. Widening to {FirewallProfiles.All} per requirement 6.";

        return FirewallProfiles.All;
    }
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

    /// <summary>
    /// Produces the deterministic, session-scoped Windows Firewall rule name.
    /// <para>
    /// The name is the rule's PRIMARY KEY everywhere else in the system: the rollback journal
    /// records it, rollback removes by it, and readback verification looks the rule up by it.
    /// Two rules that differ in any enforced property must therefore get different names, or one
    /// will silently shadow the other - AddRule would collide, rollback would remove only one,
    /// and readback would compare a live rule against the wrong model.
    /// </para>
    /// <para>
    /// <paramref name="protocol"/> and <paramref name="applicationPath"/> are part of the hashed
    /// key for exactly that reason. Without the protocol, a destination declaring the same port
    /// for TCP and UDP (e.g. 53) produces two rules with identical names. Without the application
    /// path, a program-scoped rule and an unscoped rule to the same endpoint are
    /// indistinguishable by name.
    /// </para>
    /// <para>
    /// The management branch keeps its human-readable, unhashed form (operators read these names
    /// during incident triage, and there is exactly one management rule per IP - always TCP,
    /// always unscoped - so it cannot collide).
    /// </para>
    /// </summary>
    public static string GenerateRuleName(
        Guid sessionId,
        string purpose,
        string remoteAddresses,
        string remotePorts,
        FirewallProtocol? protocol = null,
        string? applicationPath = null)
    {
        if (string.Equals(purpose, "Mgmt", StringComparison.OrdinalIgnoreCase))
        {
            var cleanIp = remoteAddresses.Contains('/') ? remoteAddresses.Split('/')[0] : remoteAddresses;
            return $"SPEMCS-{sessionId:N}-Mgmt-{cleanIp}-{remotePorts}";
        }

        var protocolKey = protocol.HasValue ? protocol.Value.ToString() : "any";
        // Path casing is not significant on Windows; normalize so that two spellings of the same
        // executable cannot produce two differently-named rules for one logical rule.
        var appKey = string.IsNullOrWhiteSpace(applicationPath) ? "*" : applicationPath.ToUpperInvariant();

        var rawKey = $"{sessionId:N}-{purpose}-{remoteAddresses}-{remotePorts}-{protocolKey}-{appKey}";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawKey));
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
        // Normalize FIRST, then name from the normalized value, so the rule name is a function of
        // the properties actually written to Windows (not of the caller's spelling).
        var normalizedApplicationPath = string.IsNullOrWhiteSpace(applicationPath) ? null : applicationPath;
        var name = GenerateRuleName(sessionId, purpose, remoteAddresses, remotePorts, protocol, normalizedApplicationPath);
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
            ApplicationPath: normalizedApplicationPath,
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
