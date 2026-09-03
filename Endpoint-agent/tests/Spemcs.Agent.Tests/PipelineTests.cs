using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class PipelineTests
{
    [Fact]
    public async Task Pipeline_drives_compliance_verification_and_monitoring()
    {
        var store = new MemoryStore(new DeviceRegistration(Guid.NewGuid(), "LAB-01", "127.0.0.1", DateTimeOffset.UtcNow));
        var machine = new AgentStateMachine(store);
        var source = new FakeProcessSource([new ProcessInfo(10, "chrome", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", null, true)]);
        var classifier = new FakeClassifier(Classification.Allowed);
        var monitor = new ProcessMonitor(source, classifier, store, machine.Snapshot);
        var ui = new FakeUi();
        var pipeline = new ExamPipeline(machine, new PreComplianceEngine(source, classifier), monitor, ui);

        Assert.True(await pipeline.StartAsync(CancellationToken.None));
        Assert.Equal(AgentState.Monitoring, pipeline.State);
        Assert.Equal("ROLL-42", store.LoadSnapshot().Session?.StudentRollNumber);
        Assert.Equal(1, ui.StudentCalls);
        Assert.True(await pipeline.StopAsync(CancellationToken.None));
        Assert.Equal(AgentState.Idle, pipeline.State);
    }

    private sealed class FakeUi : IExamUiGateway
    {
        public int LoadingCalls;
        public int StudentCalls;

        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) => Task.FromResult<DeviceRegistration?>(null);
        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) { LoadingCalls++; return Task.CompletedTask; }
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) { StudentCalls++; return Task.FromResult<string?>("ROLL-42"); }
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FakeProcessSource(IReadOnlyList<ProcessInfo> processes) : IProcessSource
    {
        public IReadOnlyList<ProcessInfo> GetProcesses() => processes;
    }

    private sealed class FakeClassifier(Classification classification) : IProcessClassifier
    {
        public ClassificationResult Classify(ProcessInfo process) => new(classification, "test", null, null, null);
    }

    private sealed class MemoryStore(DeviceRegistration registration) : IAgentStore
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
