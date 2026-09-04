using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class AgentStateMachineTests
{
    [Fact]
    public void Full_cycle_persists_each_transition()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            store.SaveRegistration(new DeviceRegistration(Guid.NewGuid(), "LAB-01", "10.0.0.1", DateTimeOffset.UtcNow));
            var machine = new AgentStateMachine(store);

            // Edge, not Chrome: a Chrome-shaped test would still pass if the family argument were
            // ignored, which is exactly the defect the parameter was introduced to close.
            Assert.True(machine.StartExam(ApprovedBrowserFamily.Edge));
            Assert.Equal(AgentState.PreCompliance, machine.State);
            Assert.Equal(ApprovedBrowserFamily.Edge, machine.Session?.ApprovedBrowser);

            Assert.True(machine.ComplianceSatisfied());
            Assert.Equal(AgentState.StudentVerification, machine.State);

            Assert.True(machine.VerifyStudent("R-100"));
            Assert.Equal(AgentState.Monitoring, machine.State);

            var resumed = new AgentStateMachine(new SqliteAgentStore(root));
            Assert.Equal(AgentState.Monitoring, resumed.State);
            Assert.Equal("R-100", resumed.Session?.StudentRollNumber);
            // The family must survive the snapshot round-trip; a restart that silently reverted to
            // Chrome would put the classifier at odds with the installed firewall rules.
            Assert.Equal(ApprovedBrowserFamily.Edge, resumed.Session?.ApprovedBrowser);

            Assert.True(resumed.StopExam());
            Assert.Equal(AgentState.Idle, resumed.State);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Start_is_rejected_without_registration()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var machine = new AgentStateMachine(new SqliteAgentStore(root));
            Assert.False(machine.StartExam(ApprovedBrowserFamily.Chrome));
            Assert.Equal(AgentState.Idle, machine.State);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Invalid_transitions_are_rejected_and_logged()
    {
        var store = new RegistrationMemoryStore();
        var transitions = new List<StateTransition>();
        var machine = new AgentStateMachine(store, transitions.Add);

        Assert.False(machine.ComplianceSatisfied());
        Assert.False(machine.VerifyStudent("R-1"));
        Assert.False(machine.StopExam());

        Assert.Equal(3, transitions.Count);
        Assert.All(transitions, item => Assert.Equal(item.From, item.To));
        Assert.Contains(transitions, item => item.Event == "COMPLIANCE_SATISFIED");
    }

    private sealed class RegistrationMemoryStore : IAgentStore
    {
        public AgentSnapshot LoadSnapshot() => new(AgentState.Idle, new DeviceRegistration(Guid.NewGuid(), "TEST", "127.0.0.1", DateTimeOffset.UtcNow), null);
        public void SaveRegistration(DeviceRegistration registration) { }
        public void SaveState(AgentState state, AgentSession? session) { }
        public void Enqueue(ViolationEvent violation) { }
        public IReadOnlyList<ViolationEvent> GetPendingEvents(int limit = 100) => [];
        public IReadOnlyList<ViolationEvent> ClaimPendingEvents(int limit = 100, DateTimeOffset? nowUtc = null) => [];
        public void MarkUploadFailed(Guid eventId, DateTimeOffset retryAtUtc) { }
        public int PurgeUploaded(DateTimeOffset olderThanUtc) => 0;
        public IReadOnlyList<ViolationEvent> GetEvents(EventDeliveryStatus? status = null, int limit = 100) => [];
        public void MarkUploaded(Guid eventId) { }
    }
}
