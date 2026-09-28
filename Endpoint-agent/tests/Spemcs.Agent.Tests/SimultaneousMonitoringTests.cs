using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Ipc;
using Spemcs.Agent.Service;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class SimultaneousMonitoringTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _dbPath;

    public SimultaneousMonitoringTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "spemcs-simul-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
        _dbPath = Path.Combine(_testDir, "agent.db");
        AgentWorker.DnsPolicyEnforcerForTesting = () => (true, "Mocked for unit testing (no registry mutation)");
    }

    public void Dispose()
    {
        AgentWorker.DnsPolicyEnforcerForTesting = null;
        SqliteConnection.ClearAllPools();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        try
        {
            if (Directory.Exists(_testDir))
                Directory.Delete(_testDir, true);
        }
        catch { }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Simultaneous startup: NetworkCollector, ProcessMonitor, EventUploader
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Simultaneous_Startup_BothMonitorsAndUploaderRunConcurrently()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-SIMUL-01", "192.168.1.100", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var log = new TestLogger<AgentWorker>();
        var enforcement = new StubEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var wsStatus = new MockWebSocketStatusProvider(true);

        using var worker = new AgentWorker(
            log,
            store,
            new MockUiGateway(),
            new MockRegistrationService(),
            new MockSessionService(),
            new MockEventPublisher(),
            enforcement,
            approvedBrowser,
            wsStatus);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        var bothRunning = await WaitForConditionAsync(
            () => worker.IsNetworkMonitoringRunning && worker.IsProcessMonitoringRunning && worker.IsEventUploaderRunning,
            TimeSpan.FromSeconds(3));

        Assert.True(bothRunning, "NetworkCollector, ProcessMonitor, and EventUploaderWorker must all run concurrently in the service.");
        Assert.NotNull(worker.NetworkCollector);
        Assert.NotNull(worker.ProcessMonitor);
        Assert.NotNull(worker.EventUploader);

        var diag = worker.GetDiagnosticStatus();
        Assert.True(diag.NetworkMonitoringRunning);
        Assert.True(diag.ProcessMonitoringRunning);
        Assert.True(diag.EventUploaderRunning);
        Assert.True(diag.WebSocketConnected);
        Assert.False(diag.EnforcementActive);
        Assert.Contains("NetworkMonitoring: RUNNING", diag.Summary);
        Assert.Contains("ProcessMonitoring: RUNNING", diag.Summary);
        Assert.Contains("EventUploader: RUNNING", diag.Summary);
        Assert.Contains("WebSocket: CONNECTED", diag.Summary);
        Assert.Contains("Enforcement: INACTIVE", diag.Summary);

        await worker.StopAsync(CancellationToken.None);
        Assert.False(worker.IsNetworkMonitoringRunning);
        Assert.False(worker.IsProcessMonitoringRunning);
        Assert.False(worker.IsEventUploaderRunning);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Controlled concurrent events: both types collected & uploaded
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ConcurrentEventCollection_BothProcessAndNetworkEventsProcessedAndUploaded()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-SIMUL-02", "192.168.1.101", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var publishedEvents = new ConcurrentBag<ViolationEvent>();
        var publisher = new RecordingPublisher(publishedEvents);

        var log = new TestLogger<AgentWorker>();
        var enforcement = new StubEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var wsStatus = new MockWebSocketStatusProvider(true);

        using var worker = new AgentWorker(
            log,
            store,
            new MockUiGateway(),
            new MockRegistrationService(),
            new MockSessionService(),
            publisher,
            enforcement,
            approvedBrowser,
            wsStatus);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        await WaitForConditionAsync(
            () => worker.IsNetworkMonitoringRunning && worker.IsProcessMonitoringRunning && worker.IsEventUploaderRunning,
            TimeSpan.FromSeconds(3));

        // Inject controlled process violation event
        var procEvent = new ViolationEvent(
            Guid.NewGuid(),
            "TEST-SIMUL-02",
            null,
            EventTypes.ApplicationOpened,
            1234,
            "notepad.exe",
            DateTimeOffset.UtcNow,
            @"C:\Windows\System32\notepad.exe",
            "Prohibited tool or service detected (notepad.exe)");
        store.Enqueue(procEvent);

        // Inject controlled network connection event
        var netEvent = new ViolationEvent(
            Guid.NewGuid(),
            "TEST-SIMUL-02",
            null,
            EventTypes.NetworkConnection,
            5678,
            "curl.exe",
            DateTimeOffset.UtcNow,
            @"C:\Windows\System32\curl.exe",
            "TCP 192.168.1.101:54321 -> 93.184.216.34:443 (Established)");
        store.Enqueue(netEvent);

        // Wait for EventUploader to claim and publish both events
        var eventsUploaded = await WaitForConditionAsync(
            () => publishedEvents.Any(e => e.EventType == EventTypes.ApplicationOpened) &&
                  publishedEvents.Any(e => e.EventType == EventTypes.NetworkConnection),
            TimeSpan.FromSeconds(4));

        Assert.True(eventsUploaded, "EventUploader must consume and publish both process and network events concurrently.");

        await worker.StopAsync(CancellationToken.None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Central policy activation & update preserves both monitors
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CentralPolicyActivation_And_Update_PreservesBothMonitorsConcurrently()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-SIMUL-03", "192.168.1.102", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var log = new TestLogger<AgentWorker>();
        var enforcement = new StubEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var wsStatus = new MockWebSocketStatusProvider(true);

        using var worker = new AgentWorker(
            log,
            store,
            new MockUiGateway(),
            new MockRegistrationService(),
            new MockSessionService(),
            new MockEventPublisher(),
            enforcement,
            approvedBrowser,
            wsStatus);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        await WaitForConditionAsync(
            () => worker.IsNetworkMonitoringRunning && worker.IsProcessMonitoringRunning,
            TimeSpan.FromSeconds(3));

        // Activate policy
        var actResult = await enforcement.ActivateAsync(
            Guid.NewGuid(),
            new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "fake-sig"),
            Guid.NewGuid(),
            FirewallProfiles.All);
        Assert.True(actResult.Success);

        // Assert both remain running after activation
        Assert.True(worker.IsNetworkMonitoringRunning, "NetworkCollector must remain running after policy activation.");
        Assert.True(worker.IsProcessMonitoringRunning, "ProcessMonitor must remain running after policy activation.");

        var diagActive = worker.GetDiagnosticStatus();
        Assert.True(diagActive.EnforcementActive);
        Assert.True(diagActive.NetworkMonitoringRunning);
        Assert.True(diagActive.ProcessMonitoringRunning);
        Assert.Contains("Enforcement: ACTIVE", diagActive.Summary);

        // Update policy
        var updResult = await enforcement.UpdatePolicyAsync(
            new SignedPolicyMessage("UPDATE_EXAM_POLICY", 1, "{}", "fake-sig-v2"));
        Assert.True(updResult.Success);

        // Assert both remain running after update
        Assert.True(worker.IsNetworkMonitoringRunning, "NetworkCollector must remain running after policy update.");
        Assert.True(worker.IsProcessMonitoringRunning, "ProcessMonitor must remain running after policy update.");

        // Deactivate policy
        var deactResult = await enforcement.DeactivateAsync(actResult.SessionId, "Test stop");
        Assert.True(deactResult.Success);

        // Assert both remain running after deactivation
        Assert.True(worker.IsNetworkMonitoringRunning, "NetworkCollector must remain running after policy deactivation.");
        Assert.True(worker.IsProcessMonitoringRunning, "ProcessMonitor must remain running after policy deactivation.");

        await worker.StopAsync(CancellationToken.None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Exam start and stop does NOT stop continuous ProcessMonitor
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ExamPipeline_ExamStartAndStop_DoesNotStopContinuousProcessMonitor()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-SIMUL-04", "192.168.1.103", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var log = new TestLogger<AgentWorker>();
        var enforcement = new StubEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var ui = new MockUiGateway();

        using var worker = new AgentWorker(
            log,
            store,
            ui,
            new MockRegistrationService(),
            new MockSessionService(),
            new MockEventPublisher(),
            enforcement,
            approvedBrowser);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        await WaitForConditionAsync(
            () => worker.IsNetworkMonitoringRunning && worker.IsProcessMonitoringRunning,
            TimeSpan.FromSeconds(3));

        // Start exam
        var started = await worker.StartExamAsync(CancellationToken.None);
        Assert.True(started);

        // Wait for pipeline to complete pre-compliance and verification
        await Task.Delay(500);

        Assert.True(worker.IsNetworkMonitoringRunning);
        Assert.True(worker.IsProcessMonitoringRunning);

        // Stop exam
        var stopped = await worker.StopExamAsync(CancellationToken.None);
        Assert.True(stopped);

        // Invariant: ProcessMonitor MUST NOT be stopped when exam stops
        Assert.True(worker.IsNetworkMonitoringRunning, "NetworkCollector must remain running after exam stop.");
        Assert.True(worker.IsProcessMonitoringRunning, "ProcessMonitor must remain running after exam stop (ownsMonitor: false).");

        await worker.StopAsync(CancellationToken.None);
        Assert.False(worker.IsNetworkMonitoringRunning);
        Assert.False(worker.IsProcessMonitoringRunning);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Error isolation: stopping one monitor leaves the other alive
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ErrorIsolation_ProcessMonitorStopped_LeavesNetworkCollectorAlive()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-SIMUL-05", "192.168.1.104", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var log = new TestLogger<AgentWorker>();
        var enforcement = new StubEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");

        using var worker = new AgentWorker(
            log,
            store,
            new MockUiGateway(),
            new MockRegistrationService(),
            new MockSessionService(),
            new MockEventPublisher(),
            enforcement,
            approvedBrowser);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        await WaitForConditionAsync(
            () => worker.IsNetworkMonitoringRunning && worker.IsProcessMonitoringRunning,
            TimeSpan.FromSeconds(3));

        // Simulate isolated stoppage of ProcessMonitor
        worker.ProcessMonitor?.Stop();
        Assert.False(worker.IsProcessMonitoringRunning);

        // Invariant: NetworkCollector remains alive
        Assert.True(worker.IsNetworkMonitoringRunning, "NetworkCollector must remain running even if ProcessMonitor stops.");

        // Restart ProcessMonitor on existing instance
        worker.ProcessMonitor?.Start();
        Assert.True(worker.IsProcessMonitoringRunning);
        Assert.True(worker.IsNetworkMonitoringRunning);

        await worker.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task ErrorIsolation_NetworkCollectorStopped_LeavesProcessMonitorAlive()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-SIMUL-06", "192.168.1.105", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var log = new TestLogger<AgentWorker>();
        var enforcement = new StubEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");

        using var worker = new AgentWorker(
            log,
            store,
            new MockUiGateway(),
            new MockRegistrationService(),
            new MockSessionService(),
            new MockEventPublisher(),
            enforcement,
            approvedBrowser);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        await WaitForConditionAsync(
            () => worker.IsNetworkMonitoringRunning && worker.IsProcessMonitoringRunning,
            TimeSpan.FromSeconds(3));

        // Simulate isolated stoppage of NetworkCollector
        worker.NetworkCollector?.Stop();
        Assert.False(worker.IsNetworkMonitoringRunning);

        // Invariant: ProcessMonitor remains alive
        Assert.True(worker.IsProcessMonitoringRunning, "ProcessMonitor must remain running even if NetworkCollector stops.");

        // Restart NetworkCollector on existing instance
        worker.NetworkCollector?.Start();
        Assert.True(worker.IsNetworkMonitoringRunning);
        Assert.True(worker.IsProcessMonitoringRunning);

        await worker.StopAsync(CancellationToken.None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. Diagnostic status query matches actual service state
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DiagnosticStatus_ReflectsAccurateState_WithAndWithoutWebSocket()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-SIMUL-07", "192.168.1.106", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var log = new TestLogger<AgentWorker>();
        var enforcement = new StubEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var wsStatus = new MockWebSocketStatusProvider(true);

        using var worker = new AgentWorker(
            log,
            store,
            new MockUiGateway(),
            new MockRegistrationService(),
            new MockSessionService(),
            new MockEventPublisher(),
            enforcement,
            approvedBrowser,
            wsStatus);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StartAsync(cts.Token);

        await WaitForConditionAsync(
            () => worker.IsNetworkMonitoringRunning && worker.IsProcessMonitoringRunning,
            TimeSpan.FromSeconds(3));

        var diag1 = worker.GetDiagnosticStatus();
        Assert.True(diag1.NetworkMonitoringRunning);
        Assert.True(diag1.ProcessMonitoringRunning);
        Assert.True(diag1.EventUploaderRunning);
        Assert.True(diag1.WebSocketConnected);
        Assert.Contains("WebSocket: CONNECTED", diag1.Summary);

        // Toggle WebSocket disconnect
        wsStatus.IsConnected = false;
        var diag2 = worker.GetDiagnosticStatus();
        Assert.False(diag2.WebSocketConnected);
        Assert.Contains("WebSocket: DISCONNECTED", diag2.Summary);

        await worker.StopAsync(CancellationToken.None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper types & methods
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<bool> WaitForConditionAsync(Func<bool> condition, TimeSpan timeout)
    {
        var start = DateTimeOffset.UtcNow;
        while (DateTimeOffset.UtcNow - start < timeout)
        {
            if (condition()) return true;
            await Task.Delay(50);
        }
        return condition();
    }

    private sealed class MockWebSocketStatusProvider : IWebSocketStatusProvider
    {
        public bool IsConnected { get; set; }
        public MockWebSocketStatusProvider(bool isConnected = false) => IsConnected = isConnected;
    }

    private sealed class RecordingPublisher : IEventPublisher
    {
        private readonly ConcurrentBag<ViolationEvent> _events;
        public RecordingPublisher(ConcurrentBag<ViolationEvent> events) => _events = events;

        public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
        {
            _events.Add(violation);
            return Task.CompletedTask;
        }
    }

    private sealed class MockUiGateway : IExamUiGateway
    {
        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) =>
            Task.FromResult<DeviceRegistration?>(new DeviceRegistration(Guid.NewGuid(), "TEST-WORKSTATION", ipAddress, DateTimeOffset.UtcNow));

        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) => Task.FromResult<string?>("ROLL-12345");
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class MockRegistrationService : IRegistrationService
    {
        public Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress, CancellationToken cancellationToken = default) =>
            Task.FromResult(new DeviceRegistration(Guid.NewGuid(), deviceName, ipAddress, DateTimeOffset.UtcNow));
    }

    private sealed class MockSessionService : ISessionService
    {
        public Task<bool> RegisterStudentAsync(string sessionId, string rollNumber, CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser, CancellationToken cancellationToken = default) => Task.FromResult(true);
    }

    private sealed class MockEventPublisher : IEventPublisher
    {
        public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class StubEnforcementStateMachine : IEnforcementStateMachine
    {
        public EnforcementState CurrentState { get; private set; } = EnforcementState.Idle;
        public DurableEnforcementRecord? CurrentSession { get; private set; }

        public Task<RecoveryResult> ReconcileStartupStateAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new RecoveryResult(false, true, null, 0, false, false, "Startup reconciliation clean"));
        }

        public Task<EnforcementActivationResult> ActivateAsync(
            Guid sessionId,
            SignedPolicyMessage signedMessage,
            Guid expectedExamId,
            FirewallProfiles targetProfiles = FirewallProfiles.All,
            DateTimeOffset? currentTimeUtc = null,
            CancellationToken cancellationToken = default)
        {
            CurrentState = EnforcementState.Active;
            CurrentSession = new DurableEnforcementRecord(
                SessionId: sessionId,
                ExamId: expectedExamId,
                PolicyId: Guid.NewGuid(),
                PolicyVersion: 1,
                State: EnforcementState.Active,
                ActivationUtc: DateTimeOffset.UtcNow,
                ExpiresAtUtc: DateTimeOffset.UtcNow.AddHours(2),
                LastTransitionUtc: DateTimeOffset.UtcNow);

            return Task.FromResult(new EnforcementActivationResult(true, sessionId, EnforcementState.Active));
        }

        public Task<PolicyUpdateResult> UpdatePolicyAsync(SignedPolicyMessage updateMessage, DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new PolicyUpdateResult(true, CurrentSession?.SessionId ?? Guid.NewGuid(), 1, 2, null));
        }

        public Task<EnforcementDeactivationResult> DeactivateAsync(Guid sessionId, string reason = "Exam stopped", CancellationToken cancellationToken = default)
        {
            CurrentState = EnforcementState.Idle;
            CurrentSession = null;
            return Task.FromResult(new EnforcementDeactivationResult(true, sessionId, EnforcementState.Idle, true, false));
        }

        public Task CheckExpiryAsync(DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class TestLogger<T> : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
    }
}
