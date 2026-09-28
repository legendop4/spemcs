using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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

public sealed class ProcessLoggingAndRollNumberFlowTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _dbPath;

    public ProcessLoggingAndRollNumberFlowTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "spemcs-roll-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
        _dbPath = Path.Combine(_testDir, "agent.db");
        AgentWorker.DnsPolicyEnforcerForTesting = () => (true, "Mocked for testing");
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

    [Fact]
    public async Task ProcessMonitor_RunningBeforeRollNumber_GeneratesPreSessionEvent_WithoutRollNumber()
    {
        // A. ProcessMonitor is already running BEFORE roll number entry.
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "PC-2556", "192.168.11.59", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var uploaderPublisher = new RecordingPublisher();
        var processSource = new ControlledProcessSource();
        var classifier = new ControlledClassifier();

        var stateMachine = new AgentStateMachine(store);
        // Null publisher on monitor so it only enqueues to store, testing EventUploaderWorker uploading from store
        var monitor = new ProcessMonitor(processSource, classifier, store, stateMachine.Snapshot);
        var uploader = new EventUploaderWorker(store, uploaderPublisher);

        monitor.Start();
        uploader.Start();

        Assert.True(monitor.IsRunning, "ProcessMonitor must be running continuously before roll number entry.");
        Assert.True(uploader.IsRunning, "EventUploader must be running.");

        // Add suspicious process before roll number is set
        processSource.AddProcess(101, "unauthorized_tool.exe", @"C:\Tools\unauthorized_tool.exe");
        classifier.MarkSuspicious("unauthorized_tool.exe", "Remote access detected");

        int detected = monitor.Reconcile();
        Assert.Equal(1, detected);

        // Allow background uploader loop to process the queue
        for (int i = 0; i < 20 && uploaderPublisher.PublishedEvents.Count == 0; i++)
        {
            await Task.Delay(50);
        }

        var preSessionEvent = Assert.Single(uploaderPublisher.PublishedEvents);
        Assert.Equal("APPLICATION_OPENED", preSessionEvent.EventType);
        Assert.Equal("unauthorized_tool.exe", preSessionEvent.ProcessName);
        Assert.Null(preSessionEvent.StudentRollNumber); // Intentionally null before roll number verification

        monitor.Stop();
        uploader.Stop();
    }

    [Fact]
    public async Task RollNumberEntry_BindsStudentSession_AndProcessEventsAreAttributed()
    {
        // 1. Service starts with continuous monitor
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "PC-2556", "192.168.11.59", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var uploaderPublisher = new RecordingPublisher();
        var processSource = new ControlledProcessSource();
        var classifier = new ControlledClassifier();

        var stateMachine = new AgentStateMachine(store);
        var monitor = new ProcessMonitor(processSource, classifier, store, stateMachine.Snapshot);
        var uploader = new EventUploaderWorker(store, uploaderPublisher);

        monitor.Start();
        uploader.Start();

        // 2. Student enters roll number in UI
        const string expectedRollNumber = "2301921540174";
        var sessionId = Guid.NewGuid().ToString("N");
        var activeSession = new AgentSession(sessionId, expectedRollNumber, DateTimeOffset.UtcNow);
        store.SaveState(AgentState.Monitoring, activeSession);

        // Verify state machine snapshot immediately sees the student roll number
        var currentSnapshot = stateMachine.Snapshot();
        Assert.Equal(AgentState.Monitoring, currentSnapshot.State);
        Assert.Equal(expectedRollNumber, currentSnapshot.Session?.StudentRollNumber);

        // 3. Launch a harmless / controlled test process
        processSource.AddProcess(202, "calc.exe", @"C:\Windows\System32\calc.exe");
        classifier.MarkSuspicious("calc.exe", "Calculator is prohibited during exam");

        int detected = monitor.Reconcile();
        Assert.Equal(1, detected);

        // Allow background uploader to pick up event
        for (int i = 0; i < 20 && uploaderPublisher.PublishedEvents.Count == 0; i++)
        {
            await Task.Delay(50);
        }

        var openEvent = Assert.Single(uploaderPublisher.PublishedEvents);
        Assert.Equal("APPLICATION_OPENED", openEvent.EventType);
        Assert.Equal("calc.exe", openEvent.ProcessName);
        Assert.Equal(202, openEvent.ProcessId);
        // CRITICAL INVARIANT: Student Roll Number is correctly attributed!
        Assert.Equal(expectedRollNumber, openEvent.StudentRollNumber);

        // 5. Close process
        processSource.RemoveProcess(202);
        monitor.Reconcile();

        for (int i = 0; i < 20 && uploaderPublisher.PublishedEvents.Count < 2; i++)
        {
            await Task.Delay(50);
        }

        Assert.Equal(2, uploaderPublisher.PublishedEvents.Count);
        var closeEvent = uploaderPublisher.PublishedEvents[1];
        Assert.Equal("APPLICATION_CLOSED", closeEvent.EventType);
        Assert.Equal("calc.exe", closeEvent.ProcessName);
        Assert.Equal(expectedRollNumber, closeEvent.StudentRollNumber);

        monitor.Stop();
        uploader.Stop();
    }

    [Fact]
    public async Task ExamLifecycle_StartAndStop_DoesNotTerminateContinuousProcessMonitor()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "PC-2556", "192.168.11.59", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var publisher = new RecordingPublisher();
        var processSource = new ControlledProcessSource();
        var classifier = new ControlledClassifier();

        var stateMachine = new AgentStateMachine(store);
        var monitor = new ProcessMonitor(processSource, classifier, store, stateMachine.Snapshot, publisher);
        var uploader = new EventUploaderWorker(store, publisher);
        var networkCollector = new NetworkCollector(store, snapshotProvider: stateMachine.Snapshot);

        monitor.Start();
        uploader.Start();
        networkCollector.Start();

        var compliance = new PreComplianceEngine(processSource, classifier);
        var uiGateway = new StubUiGateway("2301921540174");
        var sessionService = new StubSessionService();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");

        // ExamPipeline created with ownsMonitor: false (Service model)
        var pipeline = new ExamPipeline(
            stateMachine,
            compliance,
            monitor,
            uiGateway,
            approvedBrowser,
            store,
            sessionService,
            ownsMonitor: false);

        // Start exam
        bool started = await pipeline.StartAsync(CancellationToken.None);
        Assert.True(started);
        Assert.True(monitor.IsRunning, "ProcessMonitor must remain RUNNING during exam.");
        Assert.True(networkCollector.IsRunning, "NetworkCollector must remain RUNNING during exam.");

        // Stop exam
        bool stopped = await pipeline.StopAsync(CancellationToken.None);
        Assert.True(stopped);
        Assert.True(monitor.IsRunning, "ProcessMonitor must remain RUNNING after exam stop.");
        Assert.True(networkCollector.IsRunning, "NetworkCollector must remain RUNNING after exam stop.");

        monitor.Stop();
        uploader.Stop();
        networkCollector.Stop();
    }

    [Fact]
    public void Architecture_UI_DoesNotContainProcessMonitor_OrCompetingWebSocket()
    {
        // Verify via reflection that MainWindow has NO ProcessMonitor field
        var uiAssembly = typeof(Spemcs.Agent.UI.MainWindow).Assembly;
        var mainWindowType = uiAssembly.GetType("Spemcs.Agent.UI.MainWindow");
        Assert.NotNull(mainWindowType);

        var fields = mainWindowType.GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
        var monitorField = fields.FirstOrDefault(f => f.FieldType.Name.Contains("ProcessMonitor"));
        Assert.Null(monitorField);

        // Verify MainWindow does not have ConnectCentralWebSocketAsync method
        var methods = mainWindowType.GetMethods(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
        var wsMethod = methods.FirstOrDefault(m => m.Name.Contains("ConnectCentralWebSocket"));
        Assert.Null(wsMethod);
    }

    [Fact]
    public void NoDuplicateProcessEvents_SingleAuthoritativeMonitor()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "PC-2556", "192.168.11.59", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Monitoring, new AgentSession("test-sess", "2301921540174", DateTimeOffset.UtcNow));

        var publisher = new RecordingPublisher();
        var processSource = new ControlledProcessSource();
        var classifier = new ControlledClassifier();

        var stateMachine = new AgentStateMachine(store);
        var monitor = new ProcessMonitor(processSource, classifier, store, stateMachine.Snapshot, publisher);

        monitor.Start();

        processSource.AddProcess(303, "test_app.exe", @"C:\test_app.exe");
        classifier.MarkSuspicious("test_app.exe", "Violation");

        // First reconcile detects it
        int count1 = monitor.Reconcile();
        Assert.Equal(1, count1);

        // Second reconcile with same process does NOT generate duplicate event
        int count2 = monitor.Reconcile();
        Assert.Equal(0, count2);

        var events = store.GetPendingEvents();
        Assert.Single(events);
        Assert.Equal("2301921540174", events[0].StudentRollNumber);

        monitor.Stop();
    }

    // ── Supporting test doubles ──────────────────────────────────────────────

    private sealed class RecordingPublisher : IEventPublisher
    {
        public List<ViolationEvent> PublishedEvents { get; } = new();

        public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
        {
            PublishedEvents.Add(violation);
            return Task.CompletedTask;
        }
    }

    private sealed class ControlledProcessSource : IProcessSource
    {
        private readonly Dictionary<int, ProcessInfo> _processes = new();

        public void AddProcess(int pid, string name, string path) =>
            _processes[pid] = new ProcessInfo(pid, name, path, null, true);

        public void RemoveProcess(int pid) =>
            _processes.Remove(pid);

        public IReadOnlyList<ProcessInfo> GetProcesses() =>
            _processes.Values.ToList();
    }

    private sealed class ControlledClassifier : IProcessClassifier
    {
        private readonly Dictionary<string, (bool Suspicious, string Reason)> _rules = new(StringComparer.OrdinalIgnoreCase);

        public void MarkSuspicious(string name, string reason) =>
            _rules[name] = (true, reason);

        public ClassificationResult Classify(ProcessInfo process)
        {
            if (_rules.TryGetValue(process.Name, out var rule) && rule.Suspicious)
            {
                return new ClassificationResult(Classification.Suspicious, "Rule", "Category", "Publisher", "Hash", rule.Reason);
            }
            return new ClassificationResult(Classification.Allowed, "Rule", "Category", "Publisher", "Hash");
        }
    }

    private sealed class StubUiGateway : IExamUiGateway
    {
        private readonly string _rollNumber;
        public StubUiGateway(string rollNumber) => _rollNumber = rollNumber;

        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) =>
            Task.FromResult<DeviceRegistration?>(new DeviceRegistration(Guid.NewGuid(), "PC-2556", ipAddress, DateTimeOffset.UtcNow));

        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(_rollNumber);
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubSessionService : ISessionService
    {
        public Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);

        public Task<bool> RegisterStudentAsync(string sessionId, string rollNumber, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }
}
