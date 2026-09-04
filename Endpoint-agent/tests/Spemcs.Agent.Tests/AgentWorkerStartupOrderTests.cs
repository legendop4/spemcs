using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Service;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// P0-C: crash/restart recovery must finish before the agent will honour an exam command.
/// <para>
/// The invariant under test is an ordering one, and it was previously argued only by a comment in
/// <see cref="AgentWorker"/>: <c>RunStartupRecoveryAsync</c> is awaited before
/// <c>_ready.TrySetResult()</c>, and every IPC command path begins with
/// <c>await _ready.Task.WaitAsync(...)</c>. If that order is ever inverted - by moving the recovery
/// call, by setting the gate early, or by "optimising" the wait away - a START_EXAM arriving during
/// the recovery window would race the reconciliation pass over durable enforcement state, and could
/// activate a second lockdown on top of a half-applied one from a crashed run.
/// </para>
/// <para>
/// <b>Why every test here keeps recovery blocked forever.</b> The statement immediately after
/// <c>await RunStartupRecoveryAsync(...)</c> is
/// <c>BrowserPolicyEnforcer.DisableSecureDns(out _)</c>, which opens
/// <c>HKLM\SOFTWARE\Policies\Microsoft\Edge</c> and <c>...\Google\Chrome</c> for write. Letting
/// <c>ExecuteAsync</c> proceed past recovery inside a unit test would therefore mutate machine-wide
/// browser policy on whatever box runs <c>dotnet test</c> - silently succeeding if the test host
/// happens to be elevated. That is not acceptable, so the gate in these tests is never released and
/// there is deliberately no positive-path counterpart asserting "recovery completed, so START_EXAM
/// is accepted". Writing one requires extracting the Secure-DNS write behind an interface, which is
/// the DNS-hardening work item, not this one. Until then, the assertions below treat any appearance
/// of the Secure-DNS log line as a test failure rather than as an incidental detail.
/// </para>
/// </summary>
public sealed class AgentWorkerStartupOrderTests
{
    /// <summary>
    /// How long to watch a command that must not complete. Everything <c>ExecuteAsync</c> does
    /// before the recovery await is synchronous, and the tests only start watching after recovery
    /// has been observed to begin, so this window is guarding against a *late* completion rather
    /// than racing a startup sequence.
    /// </summary>
    private static readonly TimeSpan GateObservationWindow = TimeSpan.FromMilliseconds(250);

    /// <summary>Bound on how long a stop is allowed to take before the test gives up on a clean unwind.</summary>
    private static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(5);

    private const string RecoveryLogPrefix = "Running enforcement startup reconciliation";
    private const string SecureDnsLogPrefix = "Browser Secure DNS policy";
    private const string StartedLogPrefix = "SPEMCS agent started";

    // ── The ordering invariant ────────────────────────────────────────────────

    [Theory]
    [InlineData("START_EXAM")]
    [InlineData("STOP_EXAM")]
    public async Task An_exam_command_is_not_honoured_while_startup_recovery_is_still_running(string command)
    {
        var log = new RecordingLogger();
        var enforcement = new GatedEnforcementStateMachine();
        using var worker = CreateWorker(log, enforcement);

        await worker.StartAsync(CancellationToken.None);

        // Removes the race: from here on, ExecuteAsync is parked inside ReconcileStartupStateAsync.
        await enforcement.Entered.WaitAsync(ShutdownTimeout);

        using var caller = new CancellationTokenSource();
        var pending = command == "START_EXAM"
            ? worker.StartExamAsync(caller.Token)
            : worker.StopExamAsync(caller.Token);

        await Task.Delay(GateObservationWindow);

        Assert.False(pending.IsCompleted,
            $"{command} was answered while startup recovery was still in progress. The readiness gate " +
            "must stay closed until reconciliation of durable enforcement state has finished, or an " +
            "activation can race a half-applied lockdown left behind by a crashed run.");

        // Control for the assertion above: prove the command is genuinely parked on the readiness
        // gate's cancellable wait, not stuck somewhere that merely looks like it. Without this, a
        // command that could never complete for any reason would satisfy the test.
        await caller.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);

        AssertStartupNeverProceededPastRecovery(log);
        await QuietShutdownAsync(worker);
    }

    [Fact]
    public async Task Startup_recovery_is_attempted_once_and_before_any_other_startup_step()
    {
        var log = new RecordingLogger();
        var enforcement = new GatedEnforcementStateMachine();
        using var worker = CreateWorker(log, enforcement);

        await worker.StartAsync(CancellationToken.None);
        await enforcement.Entered.WaitAsync(ShutdownTimeout);
        await Task.Delay(GateObservationWindow);

        Assert.Equal(1, enforcement.ReconcileCalls);

        // Recovery is not merely *a* startup step, it is the first one. Anything logged ahead of it
        // would be a startup action that ran while durable enforcement state was still unreconciled,
        // so this deliberately pins position 0 rather than mere presence.
        Assert.NotEmpty(log.Lines);
        Assert.StartsWith(RecoveryLogPrefix, log.Lines[0], StringComparison.Ordinal);

        // The remaining startup steps - Secure-DNS policy, device registration, process monitor,
        // pipeline construction - all sit after the recovery await. None of their stubs may have
        // been touched, and the stubs throw if they are, so reaching them fails the test loudly.
        AssertStartupNeverProceededPastRecovery(log);
        await QuietShutdownAsync(worker);
    }

    [Fact]
    public async Task A_service_stop_during_recovery_unwinds_instead_of_falling_through_to_enforcement_setup()
    {
        var log = new RecordingLogger();
        var enforcement = new GatedEnforcementStateMachine();
        using var worker = CreateWorker(log, enforcement);

        await worker.StartAsync(CancellationToken.None);
        await enforcement.Entered.WaitAsync(ShutdownTimeout);

        // RunStartupRecoveryAsync swallows every exception except a cancellation raised by its own
        // stopping token, which it rethrows. That distinction is what makes this safe: a service
        // told to stop mid-recovery must abandon startup, not carry on into enforcement setup with
        // reconciliation unfinished.
        await QuietShutdownAsync(worker);

        AssertStartupNeverProceededPastRecovery(log);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static void AssertStartupNeverProceededPastRecovery(RecordingLogger log)
    {
        var secureDns = log.Lines
            .Where(line => line.StartsWith(SecureDnsLogPrefix, StringComparison.Ordinal))
            .ToArray();

        Assert.True(secureDns.Length == 0,
            "ExecuteAsync ran past startup recovery even though recovery never completed. The very " +
            "next statement writes machine-wide browser policy under HKLM\\SOFTWARE\\Policies, which " +
            "a test must never do. Fix the ordering, or move that write behind an injectable " +
            "abstraction before letting a test past this point. Lines seen: " +
            string.Join(" | ", secureDns));

        Assert.DoesNotContain(log.Lines, line => line.StartsWith(StartedLogPrefix, StringComparison.Ordinal));
    }

    private static AgentWorker CreateWorker(RecordingLogger log, GatedEnforcementStateMachine enforcement) =>
        new(log,
            new NullAgentStore(),
            new UnreachableUiGateway(),
            new UnreachableRegistrationService(),
            new UnreachableSessionService(),
            new UnreachableEventPublisher(),
            enforcement,
            new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "startup-order test"));

    private static async Task QuietShutdownAsync(AgentWorker worker)
    {
        using var timeout = new CancellationTokenSource(ShutdownTimeout);
        try
        {
            await worker.StopAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            // The gate is never released by design, so a stop is best-effort: the point of calling
            // it is to unwind ExecuteAsync, not to assert anything about shutdown latency.
        }
    }

    // ── Test doubles ─────────────────────────────────────────────────────────

    /// <summary>
    /// Blocks inside <see cref="ReconcileStartupStateAsync"/> until its stopping token fires, and
    /// refuses every other member: nothing else may be asked of enforcement before recovery ends.
    /// </summary>
    private sealed class GatedEnforcementStateMachine : IEnforcementStateMachine
    {
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<RecoveryResult> _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _reconcileCalls;

        /// <summary>Completes once <c>ExecuteAsync</c> has actually entered the recovery pass.</summary>
        public Task Entered => _entered.Task;

        public int ReconcileCalls => Volatile.Read(ref _reconcileCalls);

        // Read by the log line that precedes the recovery await, so this must answer rather than throw.
        public EnforcementState CurrentState => EnforcementState.Idle;

        public DurableEnforcementRecord? CurrentSession => null;

        public async Task<RecoveryResult> ReconcileStartupStateAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _reconcileCalls);
            _entered.TrySetResult();

            // Honours the token purely so a service stop can unwind ExecuteAsync. It is never
            // completed successfully - see the class remarks for why no test may let startup past
            // this point.
            return await _release.Task.WaitAsync(cancellationToken);
        }

        public Task<EnforcementActivationResult> ActivateAsync(Guid sessionId, SignedPolicyMessage signedMessage,
            Guid expectedExamId, FirewallProfiles targetProfiles = FirewallProfiles.All,
            DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default) =>
            throw Unreachable(nameof(ActivateAsync));

        public Task<EnforcementDeactivationResult> DeactivateAsync(Guid sessionId, string reason = "Exam stopped",
            CancellationToken cancellationToken = default) =>
            throw Unreachable(nameof(DeactivateAsync));

        public Task CheckExpiryAsync(DateTimeOffset? currentTimeUtc = null,
            CancellationToken cancellationToken = default) =>
            throw Unreachable(nameof(CheckExpiryAsync));

        public Task<PolicyUpdateResult> UpdatePolicyAsync(SignedPolicyMessage updateMessage,
            DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default) =>
            throw Unreachable(nameof(UpdatePolicyAsync));
    }

    private sealed class UnreachableUiGateway : IExamUiGateway
    {
        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) =>
            throw Unreachable(nameof(RequestRegistrationAsync));

        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) =>
            throw Unreachable(nameof(ShowPreComplianceLoadingAsync));

        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) =>
            throw Unreachable(nameof(UpdatePreComplianceResultAsync));

        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) =>
            throw Unreachable(nameof(RequestStudentVerificationAsync));

        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) =>
            throw Unreachable(nameof(NotifySessionStartedAsync));

        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) =>
            throw Unreachable(nameof(NotifySessionStoppedAsync));
    }

    private sealed class UnreachableRegistrationService : IRegistrationService
    {
        public Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress,
            CancellationToken cancellationToken = default) =>
            throw Unreachable(nameof(RegisterDeviceAsync));
    }

    private sealed class UnreachableSessionService : ISessionService
    {
        public Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser,
            CancellationToken cancellationToken = default) =>
            throw Unreachable(nameof(StartExamSessionAsync));

        public Task<bool> RegisterStudentAsync(string sessionId, string rollNumber,
            CancellationToken cancellationToken = default) =>
            throw Unreachable(nameof(RegisterStudentAsync));
    }

    private sealed class UnreachableEventPublisher : IEventPublisher
    {
        public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default) =>
            throw Unreachable(nameof(PublishEventAsync));
    }

    private static NotSupportedException Unreachable(string member) =>
        new($"{member} must not be reached while startup recovery is still running.");

    /// <summary>
    /// Captures formatted log lines. Ordering of startup steps is otherwise unobservable from
    /// outside <see cref="AgentWorker"/>, and the alternative - observing side effects - means
    /// touching the registry.
    /// </summary>
    private sealed class RecordingLogger : ILogger<AgentWorker>
    {
        private readonly List<string> _lines = [];

        public IReadOnlyList<string> Lines
        {
            get { lock (_lines) { return _lines.ToArray(); } }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);
            var line = formatter(state, exception);
            lock (_lines) { _lines.Add(line); }
        }
    }
}
