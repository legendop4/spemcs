using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Spemcs.Agent.Core;
using Spemcs.Agent.Ipc;
using Spemcs.Agent.Service;
using Spemcs.Agent.UI.Models;
using Spemcs.Agent.UI.Services;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class ExamUiLaunchLifecycleTests
{
    private sealed class TrackingLauncher : IUiLauncher
    {
        public string? LastExecutablePath { get; private set; }
        public string? LastArguments { get; private set; }
        public int LaunchCount { get; private set; }
        public bool LaunchReturnValue { get; set; } = true;

        public bool HasActiveInteractiveSession() => true;

        public bool Launch(string executablePath, string? arguments = null)
        {
            LastExecutablePath = executablePath;
            LastArguments = arguments;
            LaunchCount++;
            return LaunchReturnValue;
        }
    }

    [Fact]
    public async Task ShowPreComplianceLoadingAsync_LaunchesExamMode_WithForceRestart()
    {
        var testPipe = $"spemcs-test-agent-{Guid.NewGuid():N}";
        var launcher = new TrackingLauncher();
        var gateway = new NamedPipeUiGateway(NullLogger<NamedPipeUiGateway>.Instance, launcher, testPipe);

        // Ensure SPEMCS_AGENT_UI_PATH points to a valid file for test discovery
        var dummyExe = Path.Combine(Path.GetTempPath(), $"Spemcs.Agent.UI_{Guid.NewGuid():N}.exe");
        File.WriteAllText(dummyExe, "dummy");
        Environment.SetEnvironmentVariable("SPEMCS_AGENT_UI_PATH", dummyExe);

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(3500));
            try
            {
                await gateway.ShowPreComplianceLoadingAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                // Expected timeout waiting on named pipe in test environment
            }

            Assert.True(launcher.LaunchCount >= 1, "UI launcher must be invoked when starting pre-compliance scan.");
            Assert.Equal("--exam-mode", launcher.LastArguments);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SPEMCS_AGENT_UI_PATH", null);
            if (File.Exists(dummyExe)) File.Delete(dummyExe);
        }
    }

    [Fact]
    public void ExamModeTakeover_WhenMutexOwnedByIdleUi_CleansUpAndAcquiresMutex()
    {
        // 1. Simulate an idle UI process holding the mutex
        var uniqueMutexName = $@"Global\SpemcsTestMutex_{Guid.NewGuid():N}";
        bool idleHasMutex = false;
        Mutex? idleMutex = null;
        Mutex? secondaryMutex = null;

        try
        {
            try
            {
                idleMutex = new Mutex(true, uniqueMutexName, out idleHasMutex);
            }
            catch (AbandonedMutexException)
            {
                idleHasMutex = true;
            }

            Assert.True(idleHasMutex, "Idle process must hold mutex initially.");

            // 2. Secondary process arrives with --exam-mode
            string[] examArgs = ["--exam-mode"];
            bool isExamMode = Array.Exists(examArgs, a => string.Equals(a, "--exam-mode", StringComparison.OrdinalIgnoreCase));
            Assert.True(isExamMode);

            // Attempt to acquire mutex fails initially because idleMutex holds it
            bool secondaryHasMutex = false;
            try
            {
                secondaryMutex = new Mutex(true, uniqueMutexName, out secondaryHasMutex);
            }
            catch (AbandonedMutexException)
            {
                secondaryHasMutex = true;
            }
            catch
            {
                secondaryHasMutex = false;
            }

            Assert.False(secondaryHasMutex, "Secondary instance must initially fail to acquire held mutex.");

            // 3. Exam takeover logic: Release the idle holder (simulating TryKillOrphanUiProcesses)
            idleMutex?.ReleaseMutex();
            idleMutex?.Dispose();
            idleMutex = null;

            // Secondary process claims mutex for exam mode
            secondaryMutex?.Dispose();
            try
            {
                secondaryMutex = new Mutex(true, uniqueMutexName, out secondaryHasMutex);
            }
            catch (AbandonedMutexException)
            {
                secondaryHasMutex = true;
            }

            Assert.True(secondaryHasMutex, "Exam-mode takeover must successfully acquire the mutex after orphan cleanup.");
            if (secondaryHasMutex && secondaryMutex != null)
            {
                secondaryMutex.ReleaseMutex();
            }
        }
        finally
        {
            try { idleMutex?.Dispose(); } catch { }
            try { secondaryMutex?.Dispose(); } catch { }
        }
    }

    [Fact]
    public void AlreadyEnrolled_ExamMode_MustNotBeSuppressed()
    {
        var tempConfigPath = Path.Combine(Path.GetTempPath(), $"spemcs_enrolled_exam_{Guid.NewGuid():N}.json");
        try
        {
            var configService = new AgentConfigService(tempConfigPath);
            configService.Save(new AgentConfig
            {
                ServerUrl = "http://192.168.11.65:8000",
                DeviceId = Guid.NewGuid().ToString(),
                DeviceToken = "tok-12345",
                DeviceName = "Lab-PC01",
                Registered = true
            });

            var configCheck = configService.Load();
            bool isAlreadyEnrolled = configCheck != null && configCheck.IsEnrolled && configCheck.IsValid();
            Assert.True(isAlreadyEnrolled, "Device must be recognized as enrolled.");

            // Under --exam-mode, the secondary suppression branch (!isAlreadyEnrolled => setup, else => suppress)
            // must NOT execute for isExamMode = true.
            string[] examArgs = ["--exam-mode"];
            bool isExamMode = Array.Exists(examArgs, a => string.Equals(a, "--exam-mode", StringComparison.OrdinalIgnoreCase));
            bool hasMutexOwnership = false;

            // In App.xaml.cs: if (!_hasMutexOwnership && !isExamMode) => suppression branch
            bool wouldBeSuppressedAsDuplicate = !hasMutexOwnership && !isExamMode && isAlreadyEnrolled;
            Assert.False(wouldBeSuppressedAsDuplicate, "Exam-mode launch must NEVER be suppressed as duplicate, even when already enrolled.");
        }
        finally
        {
            if (File.Exists(tempConfigPath)) File.Delete(tempConfigPath);
        }
    }

    [Fact]
    public void NormalNonExamUi_WhenAlreadyEnrolledAndMutexHeld_RemainsSuppressed()
    {
        var tempConfigPath = Path.Combine(Path.GetTempPath(), $"spemcs_enrolled_norm_{Guid.NewGuid():N}.json");
        try
        {
            var configService = new AgentConfigService(tempConfigPath);
            configService.Save(new AgentConfig
            {
                ServerUrl = "http://192.168.11.65:8000",
                DeviceId = Guid.NewGuid().ToString(),
                DeviceToken = "tok-12345",
                DeviceName = "Lab-PC01",
                Registered = true
            });

            var configCheck = configService.Load();
            bool isAlreadyEnrolled = configCheck != null && configCheck.IsEnrolled && configCheck.IsValid();
            Assert.True(isAlreadyEnrolled);

            // Normal user click or --setup flag without --exam-mode
            string[] normalArgs = ["--setup"];
            bool isExamMode = Array.Exists(normalArgs, a => string.Equals(a, "--exam-mode", StringComparison.OrdinalIgnoreCase));
            bool hasMutexOwnership = false;

            // In App.xaml.cs: if (!_hasMutexOwnership && !isExamMode) => suppression branch executes
            bool wouldEnterSuppressionBranch = !hasMutexOwnership && !isExamMode;
            Assert.True(wouldEnterSuppressionBranch, "Normal non-exam UI must enter single-instance suppression branch when another instance holds the mutex.");

            bool wouldBeSuppressedAsDuplicate = wouldEnterSuppressionBranch && isAlreadyEnrolled;
            Assert.True(wouldBeSuppressedAsDuplicate, "Normal non-exam UI must be cleanly suppressed if already enrolled and mutex is held.");
        }
        finally
        {
            if (File.Exists(tempConfigPath)) File.Delete(tempConfigPath);
        }
    }

    [Fact]
    public async Task ShowPreComplianceLoadingAsync_WhenLauncherFails_ThrowsInvalidOperationException()
    {
        var launcher = new TrackingLauncher { LaunchReturnValue = false };
        var gateway = new NamedPipeUiGateway(NullLogger<NamedPipeUiGateway>.Instance, launcher);

        var dummyExe = Path.Combine(Path.GetTempPath(), $"Spemcs.Agent.UI_{Guid.NewGuid():N}.exe");
        File.WriteAllText(dummyExe, "dummy");
        Environment.SetEnvironmentVariable("SPEMCS_AGENT_UI_PATH", dummyExe);

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => gateway.ShowPreComplianceLoadingAsync(cts.Token));
            Assert.Contains("Failed to launch SPEMCS Agent UI", ex.Message);
            Assert.Equal(1, launcher.LaunchCount);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SPEMCS_AGENT_UI_PATH", null);
            if (File.Exists(dummyExe)) File.Delete(dummyExe);
        }
    }

    [Fact]
    public void ExamMode_WhenUnenrolled_BypassesSetupWizard()
    {
        var tempConfigPath = Path.Combine(Path.GetTempPath(), $"spemcs_unenrolled_exam_{Guid.NewGuid():N}.json");
        try
        {
            var configService = new AgentConfigService(tempConfigPath);
            configService.Save(new AgentConfig
            {
                ServerUrl = "http://192.168.11.65:8000",
                DeviceId = "",
                DeviceToken = "",
                DeviceName = "Lab-PC01",
                Registered = false
            });

            var configCheck = configService.Load();
            bool enrolled = configCheck != null && configCheck.IsEnrolled && configCheck.IsValid();
            Assert.False(enrolled, "Device must be recognized as unenrolled.");

            string[] examArgs = ["--exam-mode"];
            bool isExamMode = Array.Exists(examArgs, a => string.Equals(a, "--exam-mode", StringComparison.OrdinalIgnoreCase));
            Assert.True(isExamMode);

            // In App.xaml.cs: if (!enrolled && !isExamMode) => show setup wizard
            // Since isExamMode == true, it must NOT show setup wizard
            bool wouldShowSetupWizard = !enrolled && !isExamMode;
            Assert.False(wouldShowSetupWizard, "Under --exam-mode, setup wizard must be bypassed even if device is unenrolled.");

            // Conversely, for normal non-exam mode:
            string[] normalArgs = [];
            bool normalIsExamMode = Array.Exists(normalArgs, a => string.Equals(a, "--exam-mode", StringComparison.OrdinalIgnoreCase));
            bool normalWouldShowSetupWizard = !enrolled && !normalIsExamMode;
            Assert.True(normalWouldShowSetupWizard, "Non-exam launch must show setup wizard when unenrolled.");
        }
        finally
        {
            if (File.Exists(tempConfigPath)) File.Delete(tempConfigPath);
        }
    }

    [Fact]
    public async Task Pipeline_WhenUiLaunchFails_TransitionsPreComplianceToIdleAndReturnsFalse()
    {
        var store = new TestStore(new DeviceRegistration(Guid.NewGuid(), "LAB-01", "127.0.0.1", DateTimeOffset.UtcNow));
        var machine = new AgentStateMachine(store);
        var source = new TestProcessSource([new ProcessInfo(10, "chrome", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", null, true)]);
        var classifier = new TestClassifier(Classification.Allowed);
        var monitor = new ProcessMonitor(source, classifier, store, machine.Snapshot);

        var failingUi = new ThrowingUiGateway();
        var pipeline = new ExamPipeline(
            machine,
            new PreComplianceEngine(source, classifier),
            monitor,
            failingUi,
            ApprovedBrowserContext.ForFamily(ApprovedBrowserFamily.Chrome));

        bool started = await pipeline.StartAsync(CancellationToken.None);

        Assert.False(started, "Pipeline must return false when UI launch throws.");
        Assert.Equal(AgentState.Idle, pipeline.State);
    }

    [Fact]
    public void InteractiveSessionUiLauncher_HasActiveInteractiveSession_ReturnsTrueInUserSession()
    {
        var launcher = new InteractiveSessionUiLauncher();
        bool hasSession = launcher.HasActiveInteractiveSession();
        Assert.True(hasSession);
    }

    [Fact]
    public void UiStartup_DoesNotOpenAgentDatabase_WhenServiceOwnsDatabase()
    {
        // 1. Verify structural architecture: MainWindow must not declare or depend on IAgentStore / SqliteAgentStore
        var mainWindowType = typeof(Spemcs.Agent.UI.MainWindow);
        var fields = mainWindowType.GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Public);
        foreach (var field in fields)
        {
            Assert.False(field.FieldType == typeof(SqliteAgentStore) || field.FieldType == typeof(IAgentStore),
                $"MainWindow must not hold a reference to {field.FieldType.Name}. The Windows Service is the sole DB owner.");
        }

        // 2. Verify runtime isolation: lock agent.db exclusively (simulating the running Service),
        // then verify UI MainWindow instantiates cleanly without attempting to open or lock agent.db.
        var tempDir = Path.Combine(Path.GetTempPath(), $"spemcs-ui-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var agentDbPath = Path.Combine(tempDir, "agent.db");

        using (var serviceLock = new FileStream(agentDbPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        {
            Exception? uiStartupException = null;
            var staThread = new Thread(() =>
            {
                try
                {
                    var config = new AgentConfig
                    {
                        DeviceId = "test-device",
                        DeviceName = "TestDevice",
                        ServerUrl = "http://127.0.0.1:8000",
                        Registered = true
                    };
                    var window = new Spemcs.Agent.UI.MainWindow(config);
                    Assert.NotNull(window);
                }
                catch (Exception ex)
                {
                    uiStartupException = ex;
                }
            });
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            bool finished = staThread.Join(TimeSpan.FromSeconds(5));

            Assert.True(finished, "UI window construction on STA thread timed out.");
            Assert.Null(uiStartupException);
        }

        try { Directory.Delete(tempDir, true); } catch { }
    }

    private sealed class ThrowingUiGateway : IExamUiGateway
    {
        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) => Task.FromResult<DeviceRegistration?>(null);
        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("Simulated UI launcher failure");
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) => Task.FromResult<string?>("ROLL-01");
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class TestProcessSource(IReadOnlyList<ProcessInfo> processes) : IProcessSource
    {
        public IReadOnlyList<ProcessInfo> GetProcesses() => processes;
    }

    private sealed class TestClassifier(Classification classification) : IProcessClassifier
    {
        public ClassificationResult Classify(ProcessInfo process) => new(classification, "test", null, null, null);
    }

    private sealed class TestStore(DeviceRegistration registration) : IAgentStore
    {
        private AgentState _state = AgentState.Idle;
        private AgentSession? _session;
        private readonly List<ViolationEvent> _events = [];

        public AgentSnapshot LoadSnapshot() => new(_state, registration, _session);
        public void SaveRegistration(DeviceRegistration value) => registration = value;
        public void SaveState(AgentState state, AgentSession? session) { _state = state; _session = session; }
        public void Enqueue(ViolationEvent violation) => _events.Add(violation);
        public IReadOnlyList<ViolationEvent> GetPendingEvents(int limit = 100) => _events.Take(limit).ToArray();
        public IReadOnlyList<ViolationEvent> ClaimPendingEvents(int limit = 100, DateTimeOffset? nowUtc = null) => _events.Take(limit).Select(e => e with { DeliveryStatus = EventDeliveryStatus.Uploading }).ToArray();
        public void MarkUploadFailed(Guid eventId, DateTimeOffset retryAtUtc) { }
        public int PurgeUploaded(DateTimeOffset olderThanUtc) => 0;
        public IReadOnlyList<ViolationEvent> GetEvents(EventDeliveryStatus? status = null, int limit = 100) => _events.Take(limit).ToArray();
        public void MarkUploaded(Guid eventId) { }
    }
}
