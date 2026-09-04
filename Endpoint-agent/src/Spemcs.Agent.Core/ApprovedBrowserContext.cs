using System;
using System.Collections.Generic;
using System.Threading;

namespace Spemcs.Agent.Core;

/// <summary>
/// Canonical mapping between <see cref="ApprovedBrowserFamily"/> and the identities that family
/// has on the wire (the signed <c>approved_browser</c> string) and on disk (process image names).
/// <para>
/// This exists as ONE table on purpose. The approved browser is load-bearing in three separate
/// subsystems - the firewall allow rules are scoped to its executable (requirements 4 and 5), the
/// process classifier grants it <see cref="Classification.Allowed"/>, and the network policy
/// evaluator suppresses its ordinary web traffic. If any two of those disagreed about what
/// "chrome" means, the disagreement would show up as either a silent allowlist widening or an exam
/// the candidate cannot sit. A single whitelist consulted by all three cannot drift.
/// </para>
/// </summary>
public static class ApprovedBrowserFamilies
{
    private static readonly HashSet<string> ChromeProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "chrome.exe"
    };

    private static readonly HashSet<string> EdgeProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "msedge", "msedge.exe"
    };

    private static readonly HashSet<string> AllSupportedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "chrome.exe", "msedge", "msedge.exe"
    };

    /// <summary>
    /// Process image names of every family SPEMCS is able to approve, regardless of which one a
    /// given exam actually approved. Used to answer "is this a browser we could have approved,
    /// but did not?" - which is a violation to report, not traffic to ignore.
    /// </summary>
    public static IReadOnlySet<string> SupportedProcessNames => AllSupportedProcessNames;

    /// <summary>
    /// Process image names belonging to <paramref name="family"/>, with and without the
    /// <c>.exe</c> suffix because different Windows APIs report each form.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown for a family that has no mapping. Deliberately fatal rather than returning an empty
    /// set: an empty set would silently mean "no browser is approved", which reads as a working
    /// lockdown right up until a candidate cannot open the exam.
    /// </exception>
    public static IReadOnlySet<string> ProcessNames(ApprovedBrowserFamily family) => family switch
    {
        ApprovedBrowserFamily.Chrome => ChromeProcessNames,
        ApprovedBrowserFamily.Edge => EdgeProcessNames,
        _ => throw new ArgumentOutOfRangeException(
            nameof(family), family, "No process-name mapping exists for this approved browser family.")
    };

    /// <summary>The value this family is written as inside a signed policy payload.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown for a family with no wire mapping.</exception>
    public static string ToWireValue(ApprovedBrowserFamily family) => family switch
    {
        ApprovedBrowserFamily.Chrome => "chrome",
        ApprovedBrowserFamily.Edge => "edge",
        _ => throw new ArgumentOutOfRangeException(
            nameof(family), family, "No wire mapping exists for this approved browser family.")
    };

    /// <summary>
    /// Maps a raw <c>approved_browser</c> string onto <see cref="ApprovedBrowserFamily"/>.
    /// <para>
    /// Written as an explicit whitelist rather than <c>Enum.TryParse</c> on purpose:
    /// <c>Enum.TryParse</c> also accepts numeric strings ("0", "1"), accepts any member added to
    /// the enum later without a corresponding resolver mapping, and is culture-sensitive in ways
    /// that are easy to get wrong. An explicit switch means a new browser family cannot become
    /// silently acceptable on the wire before someone has taught the executable resolver and the
    /// process classifier how to handle it.
    /// </para>
    /// <para>
    /// Notably rejects "firefox": it exists in the backend's historical exam enum, but the process
    /// classifier hard-denies firefox.exe, so it can never be a coherent exam browser.
    /// </para>
    /// </summary>
    /// <param name="value">Raw string from a signed payload or host configuration.</param>
    /// <param name="family">The mapped family; unspecified when this returns false.</param>
    /// <returns>False if the value is missing, malformed, or names an unsupported family.</returns>
    public static bool TryParse(string? value, out ApprovedBrowserFamily family)
    {
        family = default;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();

        if (string.Equals(trimmed, "chrome", StringComparison.OrdinalIgnoreCase))
        {
            family = ApprovedBrowserFamily.Chrome;
            return true;
        }

        if (string.Equals(trimmed, "edge", StringComparison.OrdinalIgnoreCase))
        {
            family = ApprovedBrowserFamily.Edge;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Reverse of <see cref="ProcessNames"/>: maps a process image name (with or without
    /// <c>.exe</c>) back to the family it belongs to.
    /// <para>
    /// Used to recover the approved family after a service restart. The signed policy is not part of
    /// the durable enforcement record, but the installed firewall rules are scoped to the browser's
    /// executable, so the image name of an already-installed rule is direct evidence of which family
    /// the running exam approved - no guessing, and no extra durable state to keep in sync.
    /// </para>
    /// </summary>
    /// <returns>False when the name belongs to no family SPEMCS can approve.</returns>
    public static bool TryResolveFromProcessName(string? processName, out ApprovedBrowserFamily family)
    {
        family = default;

        if (string.IsNullOrWhiteSpace(processName))
        {
            return false;
        }

        var name = processName.Trim();

        if (ChromeProcessNames.Contains(name))
        {
            family = ApprovedBrowserFamily.Chrome;
            return true;
        }

        if (EdgeProcessNames.Contains(name))
        {
            family = ApprovedBrowserFamily.Edge;
            return true;
        }

        return false;
    }
}

/// <summary>Where the currently effective approved-browser family came from.</summary>
public enum ApprovedBrowserSource
{
    /// <summary>
    /// Host configuration (service config.json / UI selection). Provisional: it is what
    /// pre-compliance has to work with before a signed policy has arrived, and it carries no
    /// cryptographic authority.
    /// </summary>
    HostRequested = 0,

    /// <summary>
    /// The <c>approved_browser</c> field of a validated, signature-verified policy. Authoritative:
    /// it is the same value the firewall allow rules are scoped to.
    /// </summary>
    SignedPolicy = 1
}

/// <summary>Immutable snapshot of the approved-browser decision at one instant.</summary>
public sealed record ApprovedBrowserSelection(
    ApprovedBrowserFamily Family,
    ApprovedBrowserSource Source,
    Guid? SessionId,
    string Reason);

/// <summary>
/// Shared, mutable-over-time answer to "which browser family is approved right now?".
/// <para>
/// Before this existed, the signed <c>approved_browser</c> reached only the firewall, while the
/// process classifier was constructed with a hardcoded Chrome default. For an Edge exam the two
/// subsystems then contradicted each other: msedge.exe got network access but was reported as an
/// unapproved browser, and chrome.exe was classified Allowed while having no route out. A single
/// shared context that the signed policy writes and the detection path reads removes that class of
/// bug entirely.
/// </para>
/// <para>
/// Implementations must be safe for concurrent use: the classifier reads this from the
/// <c>ProcessMonitor</c> reconciliation loop and from <c>PreComplianceEngine</c>, while the
/// enforcement state machine writes it from the activation path.
/// </para>
/// </summary>
public interface IApprovedBrowserContext
{
    /// <summary>Full provenance of the current decision, for logging and diagnostics.</summary>
    ApprovedBrowserSelection Current { get; }

    /// <summary>
    /// The family every consumer must treat as approved. Equals the signed family whenever a
    /// policy is bound, otherwise the provisional host-requested family.
    /// </summary>
    ApprovedBrowserFamily Effective { get; }

    /// <summary>The signed family, or null when no validated policy is currently bound.</summary>
    ApprovedBrowserFamily? SignedFamily { get; }

    /// <summary>True once a validated signed policy has bound the family for a session.</summary>
    bool IsPolicyBound { get; }

    /// <summary>
    /// Records the provisional host-configured family. Never overrides a bound signed policy.
    /// </summary>
    /// <returns>False if a signed policy is bound and therefore took precedence.</returns>
    bool SetHostRequested(ApprovedBrowserFamily family, string reason);

    /// <summary>
    /// Binds the family named by a validated, signature-verified policy to a session.
    /// </summary>
    /// <returns>
    /// False if a DIFFERENT session already has a policy bound - one exam must never be able to
    /// redefine another's approved browser.
    /// </returns>
    bool BindSignedPolicy(Guid sessionId, ApprovedBrowserFamily family, string reason);

    /// <summary>
    /// Releases the binding held by <paramref name="sessionId"/> on deactivation or rollback.
    /// Takes no reason string: nothing about a release is persisted, so the explanation belongs in
    /// the caller's log line rather than in dead state here.
    /// </summary>
    /// <returns>
    /// False when nothing was bound, or when the binding belongs to another session. A late
    /// deactivation of session A must not unbind session B.
    /// </returns>
    bool ReleaseSignedPolicy(Guid sessionId);
}

/// <summary>
/// Default <see cref="IApprovedBrowserContext"/>. Registered as a DI singleton so the enforcement
/// state machine, the process classifier, the network policy evaluator, and the exam pipeline all
/// observe the same decision.
/// </summary>
public sealed class ApprovedBrowserContext : IApprovedBrowserContext
{
    /// <summary>
    /// Whole state in one immutable record so a reader gets a self-consistent view from a single
    /// <see cref="Volatile.Read{T}(ref T)"/> - no lock, and no chance of pairing a stale signed
    /// family with a fresh session id.
    /// </summary>
    private sealed record State(
        ApprovedBrowserFamily HostRequested,
        string HostReason,
        ApprovedBrowserFamily? Signed,
        Guid? SignedSessionId,
        string? SignedReason);

    // Writes are rare (once per activation / deactivation) so they serialize on a plain lock;
    // reads happen per classified process and stay lock-free.
    private readonly object _writeGate = new();
    private State _state;

    /// <param name="hostRequested">
    /// Provisional family to use until a signed policy binds one. There is deliberately no default
    /// value: a silent Chrome default is the exact defect this type was introduced to remove, so
    /// every host must state its choice and can be audited on it.
    /// </param>
    /// <param name="reason">Free-text provenance for logs, e.g. "config.json approvedBrowser".</param>
    public ApprovedBrowserContext(ApprovedBrowserFamily hostRequested, string reason)
    {
        // Validate eagerly: an unmappable family here would otherwise surface much later as an
        // exception from deep inside the classifier's hot path.
        _ = ApprovedBrowserFamilies.ProcessNames(hostRequested);

        _state = new State(
            HostRequested: hostRequested,
            HostReason: string.IsNullOrWhiteSpace(reason) ? "unspecified host configuration" : reason,
            Signed: null,
            SignedSessionId: null,
            SignedReason: null);
    }

    /// <summary>
    /// A context pinned to one family, for hosts and tests that have no signed policy in play.
    /// The result is still bindable, so a test can exercise the signed-policy path afterwards.
    /// </summary>
    public static ApprovedBrowserContext ForFamily(ApprovedBrowserFamily family)
        => new(family, $"fixed selection ({ApprovedBrowserFamilies.ToWireValue(family)})");

    public ApprovedBrowserSelection Current
    {
        get
        {
            var s = Volatile.Read(ref _state);
            return s.Signed is ApprovedBrowserFamily signed
                ? new ApprovedBrowserSelection(
                    signed, ApprovedBrowserSource.SignedPolicy, s.SignedSessionId,
                    s.SignedReason ?? "signed policy")
                : new ApprovedBrowserSelection(
                    s.HostRequested, ApprovedBrowserSource.HostRequested, null, s.HostReason);
        }
    }

    public ApprovedBrowserFamily Effective
    {
        get
        {
            var s = Volatile.Read(ref _state);
            return s.Signed ?? s.HostRequested;
        }
    }

    public ApprovedBrowserFamily? SignedFamily => Volatile.Read(ref _state).Signed;

    public bool IsPolicyBound => Volatile.Read(ref _state).Signed is not null;

    public bool SetHostRequested(ApprovedBrowserFamily family, string reason)
    {
        _ = ApprovedBrowserFamilies.ProcessNames(family);

        lock (_writeGate)
        {
            var s = _state;

            // The signed value wins, always. Recording the host request underneath it is still
            // useful - it is what takes effect again after the session is released.
            var updated = s with
            {
                HostRequested = family,
                HostReason = string.IsNullOrWhiteSpace(reason) ? "unspecified host configuration" : reason
            };

            Volatile.Write(ref _state, updated);
            return s.Signed is null;
        }
    }

    public bool BindSignedPolicy(Guid sessionId, ApprovedBrowserFamily family, string reason)
    {
        _ = ApprovedBrowserFamilies.ProcessNames(family);

        lock (_writeGate)
        {
            var s = _state;

            if (s.SignedSessionId is Guid owner && owner != sessionId)
            {
                return false;
            }

            Volatile.Write(ref _state, s with
            {
                Signed = family,
                SignedSessionId = sessionId,
                SignedReason = string.IsNullOrWhiteSpace(reason) ? "validated signed policy" : reason
            });

            return true;
        }
    }

    public bool ReleaseSignedPolicy(Guid sessionId)
    {
        lock (_writeGate)
        {
            var s = _state;

            if (s.SignedSessionId is not Guid owner || owner != sessionId)
            {
                return false;
            }

            // Cleared completely rather than leaving a "released because X" breadcrumb behind:
            // residual signed state that nothing reads is exactly what makes a stale binding hard
            // to spot in a debugger. The release reason belongs in the caller's log line.
            Volatile.Write(ref _state, s with
            {
                Signed = null,
                SignedSessionId = null,
                SignedReason = null
            });

            return true;
        }
    }
}
