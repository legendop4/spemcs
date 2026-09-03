using System;
using System.Threading;
using System.Threading.Tasks;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Defines narrow, foundational network enforcement operations on the Windows endpoint.
/// Decoupled from WebSockets, exams, UI, and dynamic policy orchestration.
/// </summary>
public interface INetworkEnforcer
{
    /// <summary>Captures the current Windows Defender Firewall outbound baseline across relevant profiles.</summary>
    Task<FirewallProfileBaseline> CaptureBaselineAsync(CancellationToken cancellationToken = default);

    /// <summary>Applies an enforcement session: installs allow rules, switches default outbound action to block, and journals progress.</summary>
    Task<ApplyResult> ApplyEnforcementAsync(EnforcementSession session, CancellationToken cancellationToken = default);

    /// <summary>Removes SPEMCS-owned firewall rules for the given session.</summary>
    Task<RollbackResult> RemoveEnforcementAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>Restores the captured firewall profile baseline if SPEMCS still owns the outbound modification.</summary>
    Task<RollbackResult> RestoreBaselineAsync(Guid sessionId, CancellationToken cancellationToken = default);

    /// <summary>Inspects actual Windows Firewall and journal state to return current enforcement snapshot.</summary>
    Task<EnforcementStateSnapshot> GetCurrentStateAsync(CancellationToken cancellationToken = default);

    /// <summary>Reconciles journal state and Windows Firewall state on startup, cleaning orphan rules and restoring baselines if needed.</summary>
    Task<RecoveryResult> RecoverIncompleteSessionAsync(CancellationToken cancellationToken = default);
}
