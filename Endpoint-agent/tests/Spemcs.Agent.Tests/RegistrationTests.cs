using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class RegistrationTests
{
    [Fact]
    public async Task Fresh_store_registers_once_and_restart_does_not_prompt_again()
    {
        var store = new RegistrationMemoryStore();
        var ui = new RegistrationUi();
        var coordinator = new RegistrationCoordinator(store, ui);

        Assert.True(await coordinator.EnsureRegisteredAsync("10.0.0.5", CancellationToken.None));
        Assert.Equal(1, ui.Calls);
        Assert.Equal("LAB-05", store.LoadSnapshot().Registration?.DeviceName);

        Assert.True(await new RegistrationCoordinator(store, ui).EnsureRegisteredAsync("10.0.0.6", CancellationToken.None));
        Assert.Equal(1, ui.Calls);
        Assert.Equal("10.0.0.5", store.LoadSnapshot().Registration?.IpAddress);
    }

    private sealed class RegistrationUi : IExamUiGateway
    {
        public int Calls;
        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<DeviceRegistration?>(new DeviceRegistration(Guid.NewGuid(), "LAB-05", ipAddress, DateTimeOffset.UtcNow));
        }

        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class RegistrationMemoryStore : IAgentStore
    {
        private DeviceRegistration? _registration;
        public AgentSnapshot LoadSnapshot() => new(AgentState.Idle, _registration, null);
        public void SaveRegistration(DeviceRegistration registration) => _registration = registration;
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
