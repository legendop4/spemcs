using System;
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
using Spemcs.Agent.Service;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class ProcessMonitorLifecycleTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _dbPath;

    public ProcessMonitorLifecycleTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "spemcs-pm-tests-" + Guid.NewGuid().ToString("N"));
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
    // 1. ProcessMonitor starts when AgentState is Idle
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ProcessMonitor_Starts_When_AgentState_Is_Idle()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-WORKSTATION", "192.168.1.100", DateTimeOffset.UtcNow));
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

        // Wait up to 3 seconds for ExecuteAsync to initialize and start the monitor
        var started = await WaitForConditionAsync(() => worker.IsProcessMonitoringRunning, TimeSpan.FromSeconds(3));

        Assert.True(started, "ProcessMonitor should have started unconditionally even when AgentState is Idle.");
        Assert.NotNull(worker.ProcessMonitor);
        Assert.True(worker.ProcessMonitor.IsRunning);

        await worker.StopAsync(CancellationToken.None);
        Assert.False(worker.IsProcessMonitoringRunning);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. ProcessMonitor remains running after central WebSocket policy activation
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ProcessMonitor_Remains_Running_After_Central_WebSocket_Policy_Activation()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-PC2556", "192.168.1.59", DateTimeOffset.UtcNow));
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

        var started = await WaitForConditionAsync(() => worker.IsProcessMonitoringRunning, TimeSpan.FromSeconds(3));
        Assert.True(started, "ProcessMonitor should be running before policy activation.");

        // Simulate CentralWebSocketWorker receiving SIGNED_NETWORK_POLICY and calling ActivateAsync
        var examId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var policyJson = $"{{\"exam_id\":\"{examId}\",\"policy_id\":\"{Guid.NewGuid()}\",\"version\":1,\"approved_browser\":\"chrome\"}}";
        var signedMessage = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, policyJson, "mock_signature");

        var activationResult = await enforcement.ActivateAsync(sessionId, signedMessage, examId);
        Assert.True(activationResult.Success);
        Assert.Equal(EnforcementState.Active, enforcement.CurrentState);

        // Verify ProcessMonitor remains running post-activation
        Assert.NotNull(worker.ProcessMonitor);
        Assert.True(worker.ProcessMonitor.IsRunning, "ProcessMonitor must remain running after central policy activation.");
        Assert.True(worker.IsProcessMonitoringRunning);

        await worker.StopAsync(CancellationToken.None);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. ProcessMonitor stops cleanly during service shutdown
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ProcessMonitor_Stops_Cleanly_During_Service_Shutdown()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "TEST-SHUTDOWN", "192.168.1.10", DateTimeOffset.UtcNow));

        var enforcement = new StubEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");

        using var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            new MockUiGateway(),
            new MockRegistrationService(),
            new MockSessionService(),
            new MockEventPublisher(),
            enforcement,
            approvedBrowser);

        await worker.StartAsync(CancellationToken.None);
        var started = await WaitForConditionAsync(() => worker.IsProcessMonitoringRunning, TimeSpan.FromSeconds(3));
        Assert.True(started);

        var monitor = worker.ProcessMonitor;
        Assert.NotNull(monitor);
        Assert.True(monitor.IsRunning);

        // Perform clean shutdown
        await worker.StopAsync(CancellationToken.None);

        Assert.False(worker.IsProcessMonitoringRunning);
        Assert.False(monitor.IsRunning, "ProcessMonitor should be stopped after AgentWorker.StopAsync.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Controlled process lifecycle produces local process events
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Controlled_Process_Lifecycle_Produces_Local_Process_Events_Without_Student_Session()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "LAB-PC2556", "192.168.1.59", DateTimeOffset.UtcNow));
        // Under central policy, there is no active student session initially (Session is null)
        store.SaveState(AgentState.Idle, null);

        var processes = new List<ProcessInfo>();
        var source = new ControlledProcessSource(processes);
        var classifier = new ControlledClassifier();
        var eventsPublished = new List<ViolationEvent>();
        var publisher = new RecordedEventPublisher(eventsPublished);

        var monitor = new ProcessMonitor(
            source,
            classifier,
            store,
            store.LoadSnapshot,
            publisher,
            NullLogger.Instance);

        monitor.Start();
        Assert.True(monitor.IsRunning);

        // 1. Initially no suspicious processes
        var count = monitor.Reconcile();
        Assert.Equal(0, count);
        Assert.Empty(store.GetEvents());

        // 2. Launch an unauthorized process (e.g. notepad.exe / pid 4040)
        var suspiciousProc = new ProcessInfo(4040, "notepad.exe", @"C:\Windows\System32\notepad.exe", null, true);
        processes.Add(suspiciousProc);

        count = monitor.Reconcile();
        Assert.Equal(1, count);

        // Verify APPLICATION_OPENED event enqueued in store
        var queuedEvents = store.GetEvents();
        Assert.Single(queuedEvents);
        var openEvent = queuedEvents[0];
        Assert.Equal(EventTypes.ApplicationOpened, openEvent.EventType);
        Assert.Equal("notepad.exe", openEvent.ProcessName);
        Assert.Equal(4040, openEvent.ProcessId);
        Assert.Equal("LAB-PC2556", openEvent.DeviceName);
        Assert.Null(openEvent.StudentRollNumber); // Tolerates null session
        Assert.Equal(EventDeliveryStatus.Pending, openEvent.DeliveryStatus);

        // 3. Process exits
        processes.Clear();
        monitor.Reconcile();

        // Verify APPLICATION_CLOSED event enqueued in store
        queuedEvents = store.GetEvents();
        Assert.Equal(2, queuedEvents.Count);
        var closeEvent = queuedEvents.First(e => e.EventType == EventTypes.ApplicationClosed);
        Assert.Equal("notepad.exe", closeEvent.ProcessName);
        Assert.Equal(4040, closeEvent.ProcessId);
        Assert.Null(closeEvent.StudentRollNumber);

        monitor.Stop();
        Assert.False(monitor.IsRunning);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. EventUploaderWorker consumes and uploads the resulting event
    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task EventUploaderWorker_Consumes_And_Uploads_Process_Violations_With_Null_Student_Session()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "PC2556", "192.168.1.59", DateTimeOffset.UtcNow));

        var publishedEvents = new List<ViolationEvent>();
        var publisher = new RecordedEventPublisher(publishedEvents);

        // Enqueue an APPLICATION_OPENED violation with null roll number
        var violation = new ViolationEvent(
            Guid.NewGuid(),
            "PC2556",
            null, // Central policy before candidate login has null roll number
            EventTypes.ApplicationOpened,
            7788,
            "cheatengine.exe",
            DateTimeOffset.UtcNow,
            @"C:\Tools\cheatengine.exe",
            "Prohibited application running");

        store.Enqueue(violation);

        var pendingBefore = store.GetEvents(EventDeliveryStatus.Pending);
        Assert.Single(pendingBefore);

        var uploader = new EventUploaderWorker(store, publisher, NullLogger.Instance, TimeSpan.FromMilliseconds(50));

        // Process single batch synchronously
        var processed = await uploader.ProcessBatchAsync(CancellationToken.None);
        Assert.Equal(1, processed);

        // Verify publisher received event
        Assert.Single(publishedEvents);
        Assert.Equal(violation.EventId, publishedEvents[0].EventId);
        Assert.Equal("cheatengine.exe", publishedEvents[0].ProcessName);
        Assert.Null(publishedEvents[0].StudentRollNumber);

        // Verify store marks status as Uploaded
        var uploadedEvents = store.GetEvents(EventDeliveryStatus.Uploaded);
        Assert.Single(uploadedEvents);
        Assert.Equal(violation.EventId, uploadedEvents[0].EventId);

        var pendingAfter = store.GetEvents(EventDeliveryStatus.Pending);
        Assert.Empty(pendingAfter);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test Doubles & Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static async Task<bool> WaitForConditionAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return true;
            await Task.Delay(50);
        }
        return condition();
    }

    private sealed class ControlledProcessSource(List<ProcessInfo> processes) : IProcessSource
    {
        public IReadOnlyList<ProcessInfo> GetProcesses() => processes.ToArray();
        public ProcessInfo? FindById(int id) => processes.FirstOrDefault(p => p.ProcessId == id);
    }

    private sealed class ControlledClassifier : IProcessClassifier
    {
        public ClassificationResult Classify(ProcessInfo process)
        {
            if (process.Name.Contains("notepad", StringComparison.OrdinalIgnoreCase) ||
                process.Name.Contains("cheatengine", StringComparison.OrdinalIgnoreCase))
            {
                return new ClassificationResult(Classification.Suspicious, "unapproved-app", "Unapproved App", null, null, "Suspicious process");
            }
            return new ClassificationResult(Classification.Allowed, "allowed-app", "Allowed", null, null, null);
        }
    }

    private sealed class RecordedEventPublisher(List<ViolationEvent> destination) : IEventPublisher
    {
        public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
        {
            lock (destination) { destination.Add(violation); }
            return Task.CompletedTask;
        }
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

        public Task<EnforcementDeactivationResult> DeactivateAsync(Guid sessionId, string reason = "Exam stopped", CancellationToken cancellationToken = default)
        {
            CurrentState = EnforcementState.Idle;
            CurrentSession = null;
            return Task.FromResult(new EnforcementDeactivationResult(true, sessionId, EnforcementState.Idle, true, false));
        }

        public Task CheckExpiryAsync(DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<PolicyUpdateResult> UpdatePolicyAsync(SignedPolicyMessage updateMessage, DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new PolicyUpdateResult(true, Guid.NewGuid(), 1, 2, null));
        }
    }

    private sealed class MockUiGateway : IExamUiGateway
    {
        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) => Task.FromResult<DeviceRegistration?>(null);
        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) => Task.FromResult<string?>("ROLL-101");
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class MockRegistrationService : IRegistrationService
    {
        public Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new DeviceRegistration(Guid.NewGuid(), deviceName, ipAddress, DateTimeOffset.UtcNow));
        }
    }

    private sealed class MockSessionService : ISessionService
    {
        public Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser, CancellationToken cancellationToken = default) => Task.FromResult(true);
        public Task<bool> RegisterStudentAsync(string sessionId, string rollNumber, CancellationToken cancellationToken = default) => Task.FromResult(true);
    }

    private sealed class MockEventPublisher : IEventPublisher
    {
        public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class TestLogger<T> : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
    }
}
