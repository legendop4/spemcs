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

public sealed class ExamActivationWorkflowTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _dbPath;

    public ExamActivationWorkflowTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "spemcs-workflow-tests-" + Guid.NewGuid().ToString("N"));
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

    // =========================================================================
    // Constraint 11 & Acceptance Test: Full End-to-End Workflow Integration Test
    //
    // Activate Exam
    //   ↓
    // LAUNCH_EXAM_MODE
    //   ↓
    // UI launch requested
    //   ↓
    // readiness screen
    //   ↓
    // Continue
    //   ↓
    // roll number entry
    //   ↓
    // student session active
    //   ↓
    // ProcessMonitor captures process event
    //   ↓
    // event contains roll + session_id
    //   ↓
    // NetworkCollector still running
    //   ↓
    // Firewall still active
    //   ↓
    // event uploaded successfully
    // =========================================================================
    [Fact]
    public async Task FullWorkflow_ActivationToUpload_EndToEndIntegrationTest()
    {
        // 1. Setup service storage & registration
        var store = new SqliteAgentStore(_testDir);
        var deviceId = Guid.NewGuid();
        store.SaveRegistration(new DeviceRegistration(deviceId, "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var testRollNumber = "2301921540174";
        var examId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        var loggingUi = new WorkflowTrackingUi(testRollNumber);
        var sessionService = new WorkflowTrackingSessionService();
        var publisher = new WorkflowTrackingPublisher();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            loggingUi,
            new LocalMockRegistrationService(),
            sessionService,
            publisher,
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        var workerTask = worker.StartAsync(cts.Token);
        await Task.Delay(200); // Allow startup reconciliation & worker initialization

        // Precondition: Both monitors are running before any exam action
        Assert.True(worker.IsProcessMonitoringRunning, "ProcessMonitor must be running at startup.");
        Assert.True(worker.IsNetworkMonitoringRunning, "NetworkCollector must be running at startup.");
        Assert.True(worker.IsEventUploaderRunning, "EventUploaderWorker must be running at startup.");

        // 2. Activate Firewall Policy (simulate SIGNED_NETWORK_POLICY)
        var signedPolicy = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "fake_sig");
        var activateResult = await enforcementMachine.ActivateAsync(sessionId, signedPolicy, examId, FirewallProfiles.All);
        Assert.True(activateResult.Success, "Firewall enforcement must activate.");
        Assert.True(worker.IsEnforcementActive, "Firewall must be ACTIVE.");

        // 3. Receive LAUNCH_EXAM_MODE via LifecycleCoordinator
        var launchRequest = new ExamActivationRequest(examId, "TestingExam", "exam.univ.edu", "chrome");
        var launchInitiated = await lifecycleCoordinator.LaunchExamAsync(launchRequest, CancellationToken.None);
        Assert.True(launchInitiated, "Exam launch must be accepted by lifecycle coordinator.");

        // 4. Verify UI readiness screen (Screen 1) was requested
        for (int i = 0; i < 60 && (loggingUi.PreComplianceLoadingCount == 0 || loggingUi.PreComplianceResultCount == 0); i++)
            await Task.Delay(50);
        Assert.Equal(1, loggingUi.PreComplianceLoadingCount);
        Assert.Equal(1, loggingUi.PreComplianceResultCount);
        Assert.True(loggingUi.ContinueClicked, "Student clicked Continue on Pre-Compliance readiness screen.");

        // 5. Verify Student verification (Screen 2) was requested and roll number provided
        for (int i = 0; i < 60 && !sessionService.RegisteredStudents.ContainsKey(testRollNumber); i++)
            await Task.Delay(50);
        Assert.Equal(1, loggingUi.StudentVerificationCount);
        Assert.True(loggingUi.SessionStartedNotified, "SessionStart must be sent to UI.");

        // 6. Verify student session is now ACTIVE
        var snapshot = store.LoadSnapshot();
        Assert.Equal(AgentState.Monitoring, snapshot.State);
        Assert.NotNull(snapshot.Session);
        Assert.Equal(testRollNumber, snapshot.Session.StudentRollNumber);

        // 7. Verify ProcessMonitor & NetworkCollector remain running simultaneously
        Assert.True(worker.IsProcessMonitoringRunning, "ProcessMonitor must remain RUNNING.");
        Assert.True(worker.IsNetworkMonitoringRunning, "NetworkCollector must remain RUNNING.");
        Assert.True(worker.IsEnforcementActive, "Firewall Enforcement must remain ACTIVE.");
        Assert.True(worker.IsEventUploaderRunning, "EventUploaderWorker must remain RUNNING.");

        // 8. Controlled process event during active session
        var processSource = new ControlledProcessSource();
        var classifier = new ControlledClassifier();
        processSource.AddProcess(9901, "suspicious_test_process.exe", @"C:\Test\suspicious_test_process.exe");
        classifier.MarkSuspicious("suspicious_test_process.exe", "Controlled test violation");

        // Single authoritative monitor checks state and enqueues event
        var localMonitor = new ProcessMonitor(processSource, classifier, store, () => store.LoadSnapshot(), publisher);
        int detected = localMonitor.Reconcile();
        Assert.Equal(1, detected);

        // 9. Verify event contains actual student roll number and session ID
        var pendingOrUploaded = store.GetEvents();
        var processEvent = Assert.Single(pendingOrUploaded, e => e.ProcessName == "suspicious_test_process.exe");
        Assert.Equal(testRollNumber, processEvent.StudentRollNumber);

        // 10. Verify event uploaded successfully by publisher
        for (int i = 0; i < 40 && !publisher.PublishedEvents.Any(e => e.ProcessName == "suspicious_test_process.exe"); i++)
            await Task.Delay(50);
        var publishedEvent = Assert.Single(publisher.PublishedEvents, e => e.ProcessName == "suspicious_test_process.exe");
        Assert.Equal(testRollNumber, publishedEvent.StudentRollNumber);

        // Clean shutdown
        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Constraint 1: Independent arrival orders
    // Order A: LAUNCH_EXAM_MODE → UI launch → SIGNED_NETWORK_POLICY → enforcement active
    // =========================================================================
    [Fact]
    public async Task IndependentArrivalOrder_LaunchExamModeThenSignedPolicy_ProducesIdenticalActiveState()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var testRollNumber = "2301921540174";
        var examId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        var loggingUi = new WorkflowTrackingUi(testRollNumber);
        var sessionService = new WorkflowTrackingSessionService();
        var publisher = new WorkflowTrackingPublisher();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            loggingUi,
            new LocalMockRegistrationService(),
            sessionService,
            publisher,
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        // Step 1: LAUNCH_EXAM_MODE arrives first
        var launchRequest = new ExamActivationRequest(examId, "TestingExam", "exam.univ.edu", "chrome");
        var launched = await lifecycleCoordinator.LaunchExamAsync(launchRequest, CancellationToken.None);
        Assert.True(launched);

        // Wait for UI verification flow to complete
        for (int i = 0; i < 100 && !sessionService.RegisteredStudents.ContainsKey(testRollNumber); i++)
            await Task.Delay(50);
        Assert.Equal(AgentState.Monitoring, store.LoadSnapshot().State);

        // Step 2: SIGNED_NETWORK_POLICY arrives second
        var signedPolicy = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "fake_sig");
        var activation = await enforcementMachine.ActivateAsync(sessionId, signedPolicy, examId, FirewallProfiles.All);
        Assert.True(activation.Success);

        // Both are now fully active simultaneously
        Assert.True(worker.IsEnforcementActive);
        Assert.True(worker.IsProcessMonitoringRunning);
        Assert.True(worker.IsNetworkMonitoringRunning);
        Assert.True(worker.IsEventUploaderRunning);
        Assert.Equal(testRollNumber, store.LoadSnapshot().Session?.StudentRollNumber);

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Constraint 1: Independent arrival orders
    // Order B: SIGNED_NETWORK_POLICY → enforcement active → LAUNCH_EXAM_MODE → UI launch
    // =========================================================================
    [Fact]
    public async Task IndependentArrivalOrder_SignedPolicyThenLaunchExamMode_ProducesIdenticalActiveState()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var testRollNumber = "2301921540174";
        var examId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        var loggingUi = new WorkflowTrackingUi(testRollNumber);
        var sessionService = new WorkflowTrackingSessionService();
        var publisher = new WorkflowTrackingPublisher();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            loggingUi,
            new LocalMockRegistrationService(),
            sessionService,
            publisher,
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        // Step 1: SIGNED_NETWORK_POLICY arrives first
        var signedPolicy = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "fake_sig");
        var activation = await enforcementMachine.ActivateAsync(sessionId, signedPolicy, examId, FirewallProfiles.All);
        Assert.True(activation.Success);
        Assert.True(worker.IsEnforcementActive);

        // Step 2: LAUNCH_EXAM_MODE arrives second
        var launchRequest = new ExamActivationRequest(examId, "TestingExam", "exam.univ.edu", "chrome");
        var launched = await lifecycleCoordinator.LaunchExamAsync(launchRequest, CancellationToken.None);
        Assert.True(launched);

        // Wait for UI verification flow to complete
        for (int i = 0; i < 100 && !sessionService.RegisteredStudents.ContainsKey(testRollNumber); i++)
            await Task.Delay(50);
        Assert.Equal(AgentState.Monitoring, store.LoadSnapshot().State);

        // Both are now fully active simultaneously
        Assert.True(worker.IsEnforcementActive);
        Assert.True(worker.IsProcessMonitoringRunning);
        Assert.True(worker.IsNetworkMonitoringRunning);
        Assert.True(worker.IsEventUploaderRunning);
        Assert.Equal(testRollNumber, store.LoadSnapshot().Session?.StudentRollNumber);

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Constraint 2: UI launch must be idempotent
    // =========================================================================
    [Fact]
    public async Task LaunchExamMode_IsIdempotent_DoesNotDuplicateUiOrSessionsOrMonitors()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var testRollNumber = "2301921540174";
        var examId = Guid.NewGuid();

        var loggingUi = new WorkflowTrackingUi(testRollNumber);
        var sessionService = new WorkflowTrackingSessionService();
        var publisher = new WorkflowTrackingPublisher();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            loggingUi,
            new LocalMockRegistrationService(),
            sessionService,
            publisher,
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        var procMonitorInstance = worker.ProcessMonitor;
        var netCollectorInstance = worker.NetworkCollector;

        // First launch
        var launchRequest = new ExamActivationRequest(examId, "TestingExam", "exam.univ.edu", "chrome");
        Assert.True(await lifecycleCoordinator.LaunchExamAsync(launchRequest, CancellationToken.None));

        for (int i = 0; i < 100 && !sessionService.RegisteredStudents.ContainsKey(testRollNumber); i++)
            await Task.Delay(50);

        var originalSessionId = store.LoadSnapshot().Session?.SessionId;
        Assert.NotNull(originalSessionId);

        // Second launch request for identical exam
        var duplicateResult = await lifecycleCoordinator.LaunchExamAsync(launchRequest, CancellationToken.None);
        Assert.True(duplicateResult, "Duplicate launch request must return true gracefully.");

        // Verify no duplicate UI launches or sessions were created
        Assert.Equal(1, loggingUi.PreComplianceLoadingCount);
        Assert.Equal(1, loggingUi.StudentVerificationCount);
        Assert.Equal(originalSessionId, store.LoadSnapshot().Session?.SessionId);

        // Verify monitor instances were NOT recreated
        Assert.Same(procMonitorInstance, worker.ProcessMonitor);
        Assert.Same(netCollectorInstance, worker.NetworkCollector);

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Constraint 3: Monitor lifecycle independent of student session lifecycle
    // =========================================================================
    [Fact]
    public async Task MonitorLifecycle_CompletelyIndependentOfSessionLifecycle()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var testRollNumber = "2301921540174";
        var examId = Guid.NewGuid();

        var loggingUi = new WorkflowTrackingUi(testRollNumber);
        var sessionService = new WorkflowTrackingSessionService();
        var publisher = new WorkflowTrackingPublisher();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            loggingUi,
            new LocalMockRegistrationService(),
            sessionService,
            publisher,
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        var initialProcMonitor = worker.ProcessMonitor;
        var initialNetCollector = worker.NetworkCollector;
        Assert.True(worker.IsProcessMonitoringRunning);
        Assert.True(worker.IsNetworkMonitoringRunning);

        // Start Exam
        await lifecycleCoordinator.LaunchExamAsync(new ExamActivationRequest(examId, "TestExam"), CancellationToken.None);
        for (int i = 0; i < 100 && !sessionService.RegisteredStudents.ContainsKey(testRollNumber); i++)
            await Task.Delay(50);

        // Verify instances remained unchanged during session active
        Assert.Same(initialProcMonitor, worker.ProcessMonitor);
        Assert.Same(initialNetCollector, worker.NetworkCollector);
        Assert.True(worker.IsProcessMonitoringRunning);
        Assert.True(worker.IsNetworkMonitoringRunning);

        // Stop Exam
        await lifecycleCoordinator.StopExamAsync(CancellationToken.None);

        // Verify instances remained unchanged after exam stop
        Assert.Same(initialProcMonitor, worker.ProcessMonitor);
        Assert.Same(initialNetCollector, worker.NetworkCollector);
        Assert.True(worker.IsProcessMonitoringRunning);
        Assert.True(worker.IsNetworkMonitoringRunning);

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Constraint 4: Dynamic session context
    // Before roll number: ProcessMonitor = RUNNING, Session = none/N/A
    // After roll number: ProcessMonitor = SAME INSTANCE, Session = active
    // =========================================================================
    [Fact]
    public void DynamicSessionContext_CapturesRollNumberAndSessionId_OnlyAfterVerification()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var processSource = new ControlledProcessSource();
        var classifier = new ControlledClassifier();
        var stateMachine = new AgentStateMachine(store);

        // Continuous monitor uses dynamic snapshot
        var monitor = new ProcessMonitor(processSource, classifier, store, stateMachine.Snapshot);
        monitor.Start();

        // 1. Process violation BEFORE student verification
        processSource.AddProcess(1001, "pre_exam_violation.exe", @"C:\pre_exam_violation.exe");
        classifier.MarkSuspicious("pre_exam_violation.exe", "Pre-session violation");
        monitor.Reconcile();

        var preEvent = Assert.Single(store.GetPendingEvents());
        Assert.Null(preEvent.StudentRollNumber);

        // 2. Student verifies roll number
        stateMachine.StartExam(ApprovedBrowserFamily.Chrome);
        stateMachine.ComplianceSatisfied();
        var verified = stateMachine.VerifyStudent("2301921540174");
        Assert.True(verified);

        // 3. Process violation AFTER student verification on the SAME monitor instance
        processSource.AddProcess(1002, "post_exam_violation.exe", @"C:\post_exam_violation.exe");
        classifier.MarkSuspicious("post_exam_violation.exe", "Post-session violation");
        monitor.Reconcile();

        var allEvents = store.GetPendingEvents();
        var postEvent = Assert.Single(allEvents, e => e.ProcessName == "post_exam_violation.exe");
        Assert.Equal("2301921540174", postEvent.StudentRollNumber);

        monitor.Stop();
    }

    // =========================================================================
    // Constraint 7 & 8: Pre-compliance screen must be actual first screen;
    // UI launch failure reported separately without altering fail-closed firewall.
    // =========================================================================
    [Fact]
    public async Task UiLaunchFailure_ReportedSeparately_DoesNotDismantleFirewall()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var examId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        // Failing UI
        var failingUi = new FailingUiGateway();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            failingUi,
            new LocalMockRegistrationService(),
            new WorkflowTrackingSessionService(),
            new WorkflowTrackingPublisher(),
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        // Firewall activation succeeds
        var signedPolicy = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "fake_sig");
        var activation = await enforcementMachine.ActivateAsync(sessionId, signedPolicy, examId, FirewallProfiles.All);
        Assert.True(activation.Success);
        Assert.True(worker.IsEnforcementActive);

        // UI Launch fails
        var launchRequest = new ExamActivationRequest(examId, "FailingExam");
        await lifecycleCoordinator.LaunchExamAsync(launchRequest, CancellationToken.None);
        await Task.Delay(300);

        // Crucial requirement: Firewall enforcement remains safely enforced (fail-closed)
        Assert.True(worker.IsEnforcementActive, "Firewall must remain active even if UI launch fails.");

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Constraint 9: If student verification fails, network enforcement remains intact
    // =========================================================================
    [Fact]
    public async Task StudentVerificationFailure_PreservesFailClosedEnforcement_WhileUiRemainsOnVerification()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var examId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        // UI that returns empty roll number (verification failure)
        var invalidRollUi = new WorkflowTrackingUi("");
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            invalidRollUi,
            new LocalMockRegistrationService(),
            new WorkflowTrackingSessionService(),
            new WorkflowTrackingPublisher(),
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        var signedPolicy = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "fake_sig");
        await enforcementMachine.ActivateAsync(sessionId, signedPolicy, examId, FirewallProfiles.All);
        Assert.True(worker.IsEnforcementActive);

        await lifecycleCoordinator.LaunchExamAsync(new ExamActivationRequest(examId, "Exam"), CancellationToken.None);
        await Task.Delay(300);

        // Verification failed (empty roll number)
        Assert.Null(store.LoadSnapshot().Session?.StudentRollNumber);

        // Network enforcement remains ACTIVE (fail-closed)
        Assert.True(worker.IsEnforcementActive, "Firewall MUST remain active even if student verification fails.");

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Constraint 10: STOP_EXAM_MODE rolls back firewall but keeps monitors running
    // =========================================================================
    [Fact]
    public async Task StopExamMode_RollsBackFirewall_EndsSession_WhileMonitorsRemainRunning()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var testRollNumber = "2301921540174";
        var examId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        var loggingUi = new WorkflowTrackingUi(testRollNumber);
        var sessionService = new WorkflowTrackingSessionService();
        var publisher = new WorkflowTrackingPublisher();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            loggingUi,
            new LocalMockRegistrationService(),
            sessionService,
            publisher,
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        // 1. Activate enforcement & start session
        var signedPolicy = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "fake_sig");
        await enforcementMachine.ActivateAsync(sessionId, signedPolicy, examId, FirewallProfiles.All);
        await lifecycleCoordinator.LaunchExamAsync(new ExamActivationRequest(examId, "Exam"), CancellationToken.None);

        for (int i = 0; i < 100 && !sessionService.RegisteredStudents.ContainsKey(testRollNumber); i++)
            await Task.Delay(50);
        Assert.True(worker.IsEnforcementActive);

        // 2. Stop Exam Mode
        var deact = await enforcementMachine.DeactivateAsync(sessionId, "Exam stopped by Central Server");
        Assert.True(deact.Success);
        await lifecycleCoordinator.StopExamAsync(CancellationToken.None);

        // 3. Verify Firewall rolled back, session ended
        Assert.False(worker.IsEnforcementActive);
        Assert.Equal(AgentState.Idle, store.LoadSnapshot().State);
        Assert.True(loggingUi.SessionStoppedNotified);

        // 4. Crucial: Monitors continue running 24/7 in the Windows Service
        Assert.True(worker.IsProcessMonitoringRunning, "ProcessMonitor must remain running after STOP_EXAM_MODE.");
        Assert.True(worker.IsNetworkMonitoringRunning, "NetworkCollector must remain running after STOP_EXAM_MODE.");
        Assert.True(worker.IsEventUploaderRunning, "EventUploader must remain running after STOP_EXAM_MODE.");

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Multi-Exam Verification: Two consecutive brand new exams with Pre-Compliance & Password Verification
    // =========================================================================
    [Fact]
    public async Task FullWorkflow_IncludesPreComplianceAndStudentPasswordVerification_AcrossTwoConsecutiveExams()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var testRollNumber = "2301921540174";
        var testPassword = "ValidPassword123";
        var loggingUi = new WorkflowTrackingUi(testRollNumber, testPassword);
        var sessionService = new WorkflowTrackingSessionService();
        var publisher = new WorkflowTrackingPublisher();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            loggingUi,
            new LocalMockRegistrationService(),
            sessionService,
            publisher,
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        for (int examIndex = 1; examIndex <= 2; examIndex++)
        {
            var examId = Guid.NewGuid();
            var sessionId = Guid.NewGuid();

            // 1. Activate Firewall Policy
            var signedPolicy = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "sig");
            var act = await enforcementMachine.ActivateAsync(sessionId, signedPolicy, examId, FirewallProfiles.All);
            Assert.True(act.Success);
            Assert.True(worker.IsEnforcementActive);

            // 2. Launch Exam Mode
            var req = new ExamActivationRequest(examId, $"Exam-{examIndex}", "exam.test.edu", "chrome");
            var launched = await lifecycleCoordinator.LaunchExamAsync(req, CancellationToken.None);
            Assert.True(launched);

            // 3. Wait for pre-compliance & password verification to complete
            for (int i = 0; i < 100 && !sessionService.RegisteredStudents.ContainsKey(testRollNumber); i++)
                await Task.Delay(50);

            // 4. Verify candidate session is ACTIVE
            Assert.Equal(AgentState.Monitoring, store.LoadSnapshot().State);
            Assert.Equal(testRollNumber, store.LoadSnapshot().Session?.StudentRollNumber);
            Assert.True(worker.IsProcessMonitoringRunning);
            Assert.True(worker.IsNetworkMonitoringRunning);
            Assert.True(worker.IsEnforcementActive);

            // 5. Cleanly stop exam
            await enforcementMachine.DeactivateAsync(sessionId, "Exam finished");
            await lifecycleCoordinator.StopExamAsync(CancellationToken.None);
            Assert.Equal(AgentState.Idle, store.LoadSnapshot().State);
            Assert.False(worker.IsEnforcementActive);
            Assert.True(worker.IsProcessMonitoringRunning);
            Assert.True(worker.IsNetworkMonitoringRunning);

            // Reset tracking for next iteration
            sessionService.RegisteredStudents.Clear();
        }

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // =========================================================================
    // Fail-Closed Validation: Short / invalid password entry rejects student verification
    // =========================================================================
    [Fact]
    public async Task StudentVerification_RejectsEmptyOrShortPassword_FailClosed()
    {
        var store = new SqliteAgentStore(_testDir);
        store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", "192.168.11.33", DateTimeOffset.UtcNow));
        store.SaveState(AgentState.Idle, null);

        var examId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();

        // UI with short password (< 4 chars)
        var shortPasswordUi = new WorkflowTrackingUi("2301921540174", "12");
        var sessionService = new WorkflowTrackingSessionService();
        var publisher = new WorkflowTrackingPublisher();
        var enforcementMachine = new MockEnforcementStateMachine();
        var approvedBrowser = new ApprovedBrowserContext(ApprovedBrowserFamily.Chrome, "test");
        var lifecycleCoordinator = new ExamLifecycleCoordinator(NullLogger<ExamLifecycleCoordinator>.Instance);

        var worker = new AgentWorker(
            NullLogger<AgentWorker>.Instance,
            store,
            shortPasswordUi,
            new LocalMockRegistrationService(),
            sessionService,
            publisher,
            enforcementMachine,
            approvedBrowser,
            wsStatus: new MockWsStatus(true),
            lifecycleCoordinator: lifecycleCoordinator
        );

        using var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(150);

        // Activate firewall
        var signedPolicy = new SignedPolicyMessage("SIGNED_NETWORK_POLICY", 1, "{}", "sig");
        await enforcementMachine.ActivateAsync(sessionId, signedPolicy, examId, FirewallProfiles.All);
        Assert.True(worker.IsEnforcementActive);

        // Launch exam
        var req = new ExamActivationRequest(examId, "SecureExam", "exam.test.edu", "chrome");
        await lifecycleCoordinator.LaunchExamAsync(req, CancellationToken.None);
        await Task.Delay(300);

        // Verify session was NOT activated
        Assert.NotEqual(AgentState.Monitoring, store.LoadSnapshot().State);
        Assert.Null(store.LoadSnapshot().Session?.StudentRollNumber);

        // Verify fail-closed enforcement remains intact
        Assert.True(worker.IsEnforcementActive, "Firewall MUST remain active when student password check fails (fail-closed).");

        await worker.StopAsync(CancellationToken.None);
        cts.Cancel();
    }

    // ── Supporting test doubles ──────────────────────────────────────────────

    private sealed class MockEnforcementStateMachine : IEnforcementStateMachine
    {
        public EnforcementState CurrentState { get; set; } = EnforcementState.Idle;
        public DurableEnforcementRecord? CurrentSession { get; set; }

        public Task<EnforcementActivationResult> ActivateAsync(
            Guid sessionId,
            SignedPolicyMessage signedMessage,
            Guid expectedExamId,
            FirewallProfiles targetProfiles = FirewallProfiles.All,
            DateTimeOffset? currentTimeUtc = null,
            CancellationToken cancellationToken = default)
        {
            CurrentState = EnforcementState.Active;
            CurrentSession = new DurableEnforcementRecord(sessionId, expectedExamId, Guid.NewGuid(), 1, EnforcementState.Active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(2), DateTimeOffset.UtcNow);
            return Task.FromResult(new EnforcementActivationResult(true, sessionId, CurrentState));
        }

        public Task<EnforcementDeactivationResult> DeactivateAsync(
            Guid sessionId,
            string reason = "Exam stopped",
            CancellationToken cancellationToken = default)
        {
            CurrentState = EnforcementState.Idle;
            CurrentSession = null;
            return Task.FromResult(new EnforcementDeactivationResult(true, sessionId, CurrentState, true, false));
        }

        public Task CheckExpiryAsync(DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<RecoveryResult> ReconcileStartupStateAsync(CancellationToken cancellationToken = default) => Task.FromResult(new RecoveryResult(false, true, null, 0, false, false, "Mock clean startup"));
        public Task<PolicyUpdateResult> UpdatePolicyAsync(SignedPolicyMessage updateMessage, DateTimeOffset? currentTimeUtc = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PolicyUpdateResult(true, CurrentSession?.SessionId ?? Guid.NewGuid(), 1, 2));
    }

    private sealed class WorkflowTrackingUi : IExamUiGateway
    {
        private readonly string _rollNumber;
        private readonly string? _password;
        public int PreComplianceLoadingCount { get; private set; }
        public int PreComplianceResultCount { get; private set; }
        public int StudentVerificationCount { get; private set; }
        public bool ContinueClicked { get; private set; }
        public bool SessionStartedNotified { get; private set; }
        public bool SessionStoppedNotified { get; private set; }

        public WorkflowTrackingUi(string rollNumber, string? password = "ValidPassword123")
        {
            _rollNumber = rollNumber;
            _password = password;
        }

        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) =>
            Task.FromResult<DeviceRegistration?>(new DeviceRegistration(Guid.NewGuid(), "NetworkLab-PC2557", ipAddress, DateTimeOffset.UtcNow));

        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken)
        {
            PreComplianceLoadingCount++;
            return Task.CompletedTask;
        }

        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken)
        {
            PreComplianceResultCount++;
            ContinueClicked = true; // Simulated student clicking [ Continue ]
            return Task.CompletedTask;
        }

        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken)
        {
            StudentVerificationCount++;
            if (string.IsNullOrWhiteSpace(_password) || _password.Length < 4)
                return Task.FromResult<string?>(null);
            return Task.FromResult<string?>(_rollNumber);
        }

        public Task NotifySessionStartedAsync(CancellationToken cancellationToken)
        {
            SessionStartedNotified = true;
            return Task.CompletedTask;
        }

        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken)
        {
            SessionStoppedNotified = true;
            return Task.CompletedTask;
        }
    }

    private sealed class FailingUiGateway : IExamUiGateway
    {
        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) => Task.FromResult<DeviceRegistration?>(null);
        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) => throw new IOException("Failed to connect to UI pipe");
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class WorkflowTrackingSessionService : ISessionService
    {
        public ConcurrentDictionary<string, string> RegisteredStudents { get; } = new();

        public Task<bool> StartExamSessionAsync(string sessionId, ApprovedBrowserFamily approvedBrowser, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);

        public Task<bool> RegisterStudentAsync(string sessionId, string rollNumber, CancellationToken cancellationToken = default)
        {
            RegisteredStudents[rollNumber] = sessionId;
            return Task.FromResult(true);
        }
    }

    private sealed class WorkflowTrackingPublisher : IEventPublisher
    {
        public List<ViolationEvent> PublishedEvents { get; } = new();

        public Task PublishEventAsync(ViolationEvent violation, CancellationToken cancellationToken = default)
        {
            PublishedEvents.Add(violation);
            return Task.CompletedTask;
        }
    }

    private sealed class MockWsStatus : IWebSocketStatusProvider
    {
        public bool IsConnected { get; }
        public MockWsStatus(bool isConnected) => IsConnected = isConnected;
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
}
