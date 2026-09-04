using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class PreComplianceChoiceTests
{
    [Fact]
    public async Task Warning_only_precompliance_warns_and_continues_without_terminating()
    {
        var store = new ChoiceStore();
        var machine = new AgentStateMachine(store);
        var ui = new ChoiceUi();
        var source = new StaticSource([new ProcessInfo(9, "notepad", "C:\\Users\\student\\notepad.exe", null, true)]);
        var pipeline = new ExamPipeline(
            machine,
            new PreComplianceEngine(source, new DenyClassifier()),
            new ProcessMonitor(source, new DenyClassifier(), store, machine.Snapshot),
            ui,
            ApprovedBrowserContext.ForFamily(ApprovedBrowserFamily.Chrome));

        Assert.True(await pipeline.StartAsync(CancellationToken.None));
        Assert.Equal(AgentState.Monitoring, pipeline.State);
        Assert.Equal(1, ui.UpdateCalls);
    }

    private sealed class ChoiceUi : IExamUiGateway
    {
        public int UpdateCalls;

        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken) => Task.FromResult<DeviceRegistration?>(null);
        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) { UpdateCalls++; return Task.CompletedTask; }
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) => Task.FromResult<string?>("R-1");
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class ChoiceStore : IAgentStore
    {
        private AgentState _state = AgentState.Idle;
        private AgentSession? _session;

        public AgentSnapshot LoadSnapshot() => new(_state, new DeviceRegistration(Guid.NewGuid(), "LAB", "127.0.0.1", DateTimeOffset.UtcNow), _session);
        public void SaveRegistration(DeviceRegistration registration) { }
        public void SaveState(AgentState state, AgentSession? session) { _state = state; _session = session; }
        public void Enqueue(ViolationEvent violation) { }
        public IReadOnlyList<ViolationEvent> GetPendingEvents(int limit = 100) => [];
        public IReadOnlyList<ViolationEvent> ClaimPendingEvents(int limit = 100, DateTimeOffset? nowUtc = null) => [];
        public void MarkUploadFailed(Guid eventId, DateTimeOffset retryAtUtc) { }
        public int PurgeUploaded(DateTimeOffset olderThanUtc) => 0;
        public IReadOnlyList<ViolationEvent> GetEvents(EventDeliveryStatus? status = null, int limit = 100) => [];
        public void MarkUploaded(Guid eventId) { }
    }

    private sealed class StaticSource(IReadOnlyList<ProcessInfo> processes) : IProcessSource
    {
        public IReadOnlyList<ProcessInfo> GetProcesses() => processes;
    }

    private sealed class DenyClassifier : IProcessClassifier
    {
        public ClassificationResult Classify(ProcessInfo process) => new(Classification.Suspicious, "test", null, null, "Suspicious process");
    }
}
