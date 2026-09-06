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

/// <summary>
/// The pre-exam firewall state SPEMCS captures so it can put the machine back exactly as it found it.
/// </summary>
/// <remarks>
/// <para>
/// SCOPE - WHAT THIS DELIBERATELY DOES NOT CAPTURE. Older documentation implied a broad "firewall
/// state" snapshot. It is not one, and it should not become one: a baseline must capture exactly the
/// state its owner MUTATES, because restoring anything else means overwriting configuration that
/// belongs to somebody else. The complete list of state SPEMCS writes is
/// <see cref="IFirewallAdapter.SetDefaultOutboundAction"/> on the targeted profiles, plus rules it
/// creates itself in the <see cref="FirewallRuleModel.SpemcsRuleGroup"/> group. That is all this
/// record needs to carry, and it carries it.
/// </para>
/// <para>
/// In particular INBOUND state is absent on purpose. SPEMCS never sets
/// <c>DefaultInboundAction</c> - <see cref="WindowsFirewallAdapter"/> exposes no way to - and every
/// rule it generates is <see cref="FirewallDirection.Outbound"/>; the only appearance of
/// <see cref="FirewallDirection.Inbound"/> in the whole agent is the enum member itself. Capturing
/// an inbound default would therefore add a value that rollback must either ignore (dead weight) or
/// write back (a change SPEMCS has no mandate to make, and one that could reopen or close inbound
/// paths an administrator set deliberately). <c>RollbackScopeTests</c> pins the absence of any
/// inbound mutation so this stays true rather than merely being true today.
/// </para>
/// <para>
/// <see cref="ActiveProfiles"/> is an OBSERVATION, not a restoration target. It records which
/// profiles Windows reported as current when the baseline was taken, for diagnostics and for the
/// loopback-coverage check in <c>NetworkEnforcer.LogAndVerifyRules</c>. Which profiles get restored
/// is decided by <see cref="EnforcementSession.TargetProfiles"/> / <see cref="JournalRecord.TargetProfiles"/>
/// instead, because the active set can change mid-exam - a laptop moving from a docked Domain
/// network to Public - and rollback must undo what SPEMCS actually wrote, not what happens to be
/// live at the moment it runs.
/// </para>
/// </remarks>
public sealed record FirewallProfileBaseline(
    FirewallAction DomainDefaultOutbound,
    FirewallAction PrivateDefaultOutbound,
    FirewallAction PublicDefaultOutbound,
    FirewallProfiles ActiveProfiles,
    DateTimeOffset CapturedUtc
)
{
    /// <summary>
    /// The captured default outbound action for a single profile, or <c>null</c> if
    /// <paramref name="profile"/> does not name exactly one profile.
    /// </summary>
    public FirewallAction? ActionFor(FirewallProfiles profile) => profile switch
    {
        FirewallProfiles.Domain => DomainDefaultOutbound,
        FirewallProfiles.Private => PrivateDefaultOutbound,
        FirewallProfiles.Public => PublicDefaultOutbound,
        _ => null
    };
}

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
    /// The literal prefix every SPEMCS-generated rule name begins with.
    /// </summary>
    public const string NamePrefix = "SPEMCS-";

    /// <summary>Length of a GUID formatted with "N" - 32 hex digits, no dashes.</summary>
    private const int SessionIdLength = 32;

    /// <summary>
    /// The name prefix that identifies rules owned by <paramref name="sessionId"/>.
    /// </summary>
    /// <remarks>
    /// This is the ownership boundary rollback uses. It must never be shortened to
    /// <see cref="NamePrefix"/>: a bare "SPEMCS-" match turns a single session's rollback into a
    /// product-wide firewall cleanup, deleting a concurrently-active session's allow rules and
    /// stranding that exam mid-flight.
    /// </remarks>
    public static string SessionNamePrefix(Guid sessionId) => $"{NamePrefix}{sessionId:N}-";

    /// <summary>
    /// Recovers the owning session from a SPEMCS rule name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used by orphan cleanup to attribute a rule found in the SPEMCS group to a session, so that
    /// cleanup can consult the journal about whether that session is still live instead of deleting
    /// every rule it can see. Attribution has to come from the name because
    /// <see cref="IFirewallAdapter.GetRulesByGroup"/> reads back from Windows, which stores no
    /// session field - <c>WindowsFirewallAdapter</c> fills <see cref="SessionId"/> with
    /// <see cref="Guid.Empty"/> on every discovered rule.
    /// </para>
    /// <para>
    /// Strict by design: the name must be exactly <c>SPEMCS-{32 hex}-{something}</c>. A name that
    /// almost matches is reported as unattributable rather than being coerced to some nearby GUID,
    /// because the caller's decision (delete / preserve) hinges on the answer.
    /// </para>
    /// </remarks>
    public static bool TryParseSessionId(string? ruleName, out Guid sessionId)
    {
        sessionId = Guid.Empty;
        if (string.IsNullOrWhiteSpace(ruleName)) return false;
        if (!ruleName.StartsWith(NamePrefix, StringComparison.OrdinalIgnoreCase)) return false;

        // Must be prefix + 32 hex digits + '-' + at least one more character, so a name that is
        // nothing but the prefix and a GUID (no purpose segment) is not treated as SPEMCS-generated.
        if (ruleName.Length < NamePrefix.Length + SessionIdLength + 2) return false;
        if (ruleName[NamePrefix.Length + SessionIdLength] != '-') return false;

        var candidate = ruleName.AsSpan(NamePrefix.Length, SessionIdLength);
        foreach (var c in candidate)
        {
            var isHex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!isHex) return false;
        }

        return Guid.TryParseExact(candidate, "N", out sessionId);
    }

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
            return $"{SessionNamePrefix(sessionId)}Mgmt-{cleanIp}-{remotePorts}";
        }

        var protocolKey = protocol.HasValue ? protocol.Value.ToString() : "any";
        // Path casing is not significant on Windows; normalize so that two spellings of the same
        // executable cannot produce two differently-named rules for one logical rule.
        var appKey = string.IsNullOrWhiteSpace(applicationPath) ? "*" : applicationPath.ToUpperInvariant();

        var rawKey = $"{sessionId:N}-{purpose}-{remoteAddresses}-{remotePorts}-{protocolKey}-{appKey}";
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawKey));
        var hexHash = Convert.ToHexString(hashBytes)[..8];
        return $"{SessionNamePrefix(sessionId)}{purpose}-{hexHash}";
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
            Name: $"{SessionNamePrefix(sessionId)}Loopback-IPv4",
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
            Name: $"{SessionNamePrefix(sessionId)}Loopback-IPv6",
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
