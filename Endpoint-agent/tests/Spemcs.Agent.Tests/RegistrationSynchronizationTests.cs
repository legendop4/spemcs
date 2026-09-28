using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Spemcs.Agent.Core;
using Spemcs.Agent.Service;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class RegistrationSynchronizationTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _configPath;

    public RegistrationSynchronizationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "spemcs_reg_sync_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _configPath = Path.Combine(_tempDir, "config.json");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, true);
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Test 1: Fresh enrolled endpoint + empty agent.db -> startup -> registration
    // synchronization -> agent.db contains valid DeviceRegistration.
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Test1_FreshEnrolledEndpoint_EmptyDb_SynchronizesRegistrationToStore()
    {
        var expectedId = Guid.NewGuid();
        var configObj = new
        {
            registered = true,
            deviceName = "PC04",
            deviceId = expectedId.ToString(),
            deviceToken = "test-jwt-token-pc04",
            serverUrl = "http://10.0.0.1:8000"
        };
        await File.WriteAllTextAsync(_configPath, JsonSerializer.Serialize(configObj));

        var store = new InMemoryTestAgentStore();
        var credentials = new DeviceCredentialStore(null, null);
        var synchronizer = new RegistrationSynchronizer(
            NullLogger<RegistrationSynchronizer>.Instance,
            store,
            credentials,
            regService: null,
            configPath: _configPath);

        // Act
        var result = await synchronizer.SyncRegistrationAsync("startup");

        // Assert
        Assert.True(result);
        var snapshot = store.LoadSnapshot();
        Assert.NotNull(snapshot.Registration);
        Assert.Equal(expectedId, snapshot.Registration!.DeviceId);
        Assert.Equal("PC04", snapshot.Registration.DeviceName);
        Assert.Equal("test-jwt-token-pc04", credentials.DeviceToken);
    }

    // -------------------------------------------------------------------------
    // Test 2: Existing valid registration -> startup -> idempotent (no corruption)
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Test2_ExistingValidRegistration_Startup_IsIdempotentAndPreservesRegistration()
    {
        var expectedId = Guid.NewGuid();
        var configObj = new
        {
            registered = true,
            deviceName = "PC03",
            deviceId = expectedId.ToString(),
            deviceToken = "test-jwt-token-pc03"
        };
        await File.WriteAllTextAsync(_configPath, JsonSerializer.Serialize(configObj));

        var store = new InMemoryTestAgentStore();
        var existingReg = new DeviceRegistration(expectedId, "PC03", "192.168.1.100", DateTimeOffset.UtcNow.AddDays(-1));
        store.SaveRegistration(existingReg);

        var synchronizer = new RegistrationSynchronizer(
            NullLogger<RegistrationSynchronizer>.Instance,
            store,
            configPath: _configPath);

        // Act
        var result = await synchronizer.SyncRegistrationAsync("startup");

        // Assert
        Assert.True(result);
        var snapshot = store.LoadSnapshot();
        Assert.NotNull(snapshot.Registration);
        Assert.Equal(expectedId, snapshot.Registration!.DeviceId);
        Assert.Equal("PC03", snapshot.Registration.DeviceName);
    }

    // -------------------------------------------------------------------------
    // Test 3: Missing device_id -> MUST NOT synthesize identity -> fails closed
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Test3_MissingDeviceId_MustNotSynthesizeIdentity_FailsClosed()
    {
        // Fresh unenrolled template config without deviceId or deviceToken
        var configObj = new
        {
            registered = false,
            deviceName = "PC08",
            serverUrl = "http://10.0.0.1:8000"
        };
        await File.WriteAllTextAsync(_configPath, JsonSerializer.Serialize(configObj));

        var store = new InMemoryTestAgentStore();
        var synchronizer = new RegistrationSynchronizer(
            NullLogger<RegistrationSynchronizer>.Instance,
            store,
            configPath: _configPath);

        // Act
        var result = await synchronizer.SyncRegistrationAsync("startup", allowBackendQuery: false);

        // Assert
        Assert.False(result);
        var snapshot = store.LoadSnapshot();
        // MUST NOT synthesize identity using MachineName or random GUID
        Assert.Null(snapshot.Registration);
    }

    // -------------------------------------------------------------------------
    // Test 4: Valid registration in agent.db -> StartExam() -> succeeds
    // -------------------------------------------------------------------------
    [Fact]
    public void Test4_ValidRegistration_StartExam_Succeeds()
    {
        var store = new InMemoryTestAgentStore();
        var reg = new DeviceRegistration(Guid.NewGuid(), "PC03", "10.0.0.3", DateTimeOffset.UtcNow);
        store.SaveRegistration(reg);

        var machine = new AgentStateMachine(store);
        // Act
        var started = machine.StartExam(ApprovedBrowserFamily.Chrome);

        // Assert
        Assert.True(started);
        Assert.Equal(AgentState.PreCompliance, machine.State);
    }

    // -------------------------------------------------------------------------
    // Test 5: Empty registration in agent.db -> StartExam() -> remains rejected
    // -------------------------------------------------------------------------
    [Fact]
    public void Test5_EmptyRegistration_StartExam_RemainsRejected()
    {
        var store = new InMemoryTestAgentStore(); // Registration is null
        var machine = new AgentStateMachine(store);
        // Act
        var started = machine.StartExam(ApprovedBrowserFamily.Chrome);

        // Assert: fails closed, never begins precompliance or UI launch without registration
        Assert.False(started);
        Assert.Equal(AgentState.Idle, machine.State);
    }

    // -------------------------------------------------------------------------
    // Test 6: Enrollment followed immediately by exam activation ->
    // registration persistence completes before exam activation -> UI launch proceeds
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Test6_EnrollmentFollowedByExamActivation_PersistsBeforeStartExam()
    {
        var backendDeviceId = Guid.NewGuid();
        var configObj = new
        {
            registered = true,
            deviceName = "PC05",
            enrollmentKey = "secret-key",
            serverUrl = "http://10.0.0.1:8000"
            // Note: deviceId is missing from config initially
        };
        await File.WriteAllTextAsync(_configPath, JsonSerializer.Serialize(configObj));

        var store = new InMemoryTestAgentStore();
        var mockBackend = new MockRegistrationService(new DeviceRegistration(backendDeviceId, "PC05", "10.0.0.5", DateTimeOffset.UtcNow));

        var synchronizer = new RegistrationSynchronizer(
            NullLogger<RegistrationSynchronizer>.Instance,
            store,
            regService: mockBackend,
            configPath: _configPath);

        // Simulate pre-exam activation sync gate
        var syncSuccess = await synchronizer.EnsureAuthoritativeRegistrationAsync("pre_exam_activation", TimeSpan.FromSeconds(3));
        Assert.True(syncSuccess);

        // Assert that agent.db store has received registration
        var snapshot = store.LoadSnapshot();
        Assert.NotNull(snapshot.Registration);
        Assert.Equal(backendDeviceId, snapshot.Registration!.DeviceId);

        // Now exam pipeline runs machine.StartExam()
        var machine = new AgentStateMachine(store);
        var examStarted = machine.StartExam(ApprovedBrowserFamily.Chrome);

        // Assert exam activation succeeds and UI pre-compliance can proceed
        Assert.True(examStarted);
        Assert.Equal(AgentState.PreCompliance, machine.State);

        // Also verify authoritative deviceId was persisted to config.json
        var updatedConfigText = await File.ReadAllTextAsync(_configPath);
        using var doc = JsonDocument.Parse(updatedConfigText);
        Assert.True(doc.RootElement.TryGetProperty("deviceId", out var diProp));
        Assert.Equal(backendDeviceId.ToString(), diProp.GetString());
    }

    // -------------------------------------------------------------------------
    // Test Doubles
    // -------------------------------------------------------------------------
    private sealed class InMemoryTestAgentStore : IAgentStore
    {
        private DeviceRegistration? _reg;
        private AgentState _state = AgentState.Idle;
        private AgentSession? _session;

        public AgentSnapshot LoadSnapshot() => new(_state, _reg, _session);
        public void SaveRegistration(DeviceRegistration registration) => _reg = registration;
        public void SaveState(AgentState state, AgentSession? session)
        {
            _state = state;
            _session = session;
        }
        public void Enqueue(ViolationEvent violation) { }
        public IReadOnlyList<ViolationEvent> GetPendingEvents(int limit = 100) => [];
        public IReadOnlyList<ViolationEvent> ClaimPendingEvents(int limit = 100, DateTimeOffset? nowUtc = null) => [];
        public void MarkUploadFailed(Guid eventId, DateTimeOffset retryAtUtc) { }
        public int PurgeUploaded(DateTimeOffset olderThanUtc) => 0;
        public IReadOnlyList<ViolationEvent> GetEvents(EventDeliveryStatus? status = null, int limit = 100) => [];
        public void MarkUploaded(Guid eventId) { }
    }

    private sealed class MockRegistrationService : IRegistrationService
    {
        private readonly DeviceRegistration _response;
        public MockRegistrationService(DeviceRegistration response) => _response = response;

        public Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_response);
        }
    }
}
