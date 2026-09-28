using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Service;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class CentralWebSocketEnrollmentTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _configPath;

    public CentralWebSocketEnrollmentTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "spemcs_ws_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
        _configPath = Path.Combine(_testDir, "config.json");
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testDir))
            {
                Directory.Delete(_testDir, true);
            }
        }
        catch { }
    }

    [Fact]
    public void TryLoadValidConfig_WhenFileMissing_ReturnsNull()
    {
        var identity = CentralWebSocketWorker.TryLoadValidConfig(_configPath, NullLogger.Instance);
        Assert.Null(identity);
    }

    [Fact]
    public void TryLoadValidConfig_WhenUnenrolledOrRegisteredFalse_ReturnsNull()
    {
        var json = JsonSerializer.Serialize(new
        {
            serverUrl = "http://localhost:8000",
            registered = false
        });
        File.WriteAllText(_configPath, json);

        var identity = CentralWebSocketWorker.TryLoadValidConfig(_configPath, NullLogger.Instance);
        Assert.Null(identity);
    }

    [Fact]
    public void TryLoadValidConfig_WhenMissingRequiredFields_ReturnsNull()
    {
        // Missing deviceToken and deviceName
        var json = JsonSerializer.Serialize(new
        {
            serverUrl = "http://localhost:8000",
            hardwareUuid = "hw-1234",
            registered = true
        });
        File.WriteAllText(_configPath, json);

        var identity = CentralWebSocketWorker.TryLoadValidConfig(_configPath, NullLogger.Instance);
        Assert.Null(identity);
    }

    [Fact]
    public void TryLoadValidConfig_WhenEnrolledAndValid_ReturnsEnrolledIdentity()
    {
        var json = JsonSerializer.Serialize(new
        {
            serverUrl = "http://192.168.11.100:8000",
            hardwareUuid = "b8637cb2-pc2557",
            deviceName = "NetworkLab-PC2557",
            deviceToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid-token",
            registered = true
        });
        File.WriteAllText(_configPath, json);

        var identity = CentralWebSocketWorker.TryLoadValidConfig(_configPath, NullLogger.Instance);
        Assert.NotNull(identity);
        Assert.Equal("http://192.168.11.100:8000", identity.ServerUrl);
        Assert.Equal("b8637cb2-pc2557", identity.HardwareUuid);
        Assert.Equal("NetworkLab-PC2557", identity.DeviceName);
        Assert.Equal("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid-token", identity.DeviceToken);
    }

    [Fact]
    public void HandleConfigChanged_ReplacesIdentityAtomically()
    {
        var credStore = new DeviceCredentialStore("bootstrap-key");
        var keyStore = new TrustedKeyStore();
        var keySync = new StubKeyringSyncService();
        var enforcement = new StubEnforcementStateMachine();
        var firewall = new MockFirewallAdapter();
        var regService = new LocalMockRegistrationService();
        var configResolver = ServiceConfigResolver.Resolve(null, null, "http://localhost:8000");

        using var worker = new CentralWebSocketWorker(
            NullLogger<CentralWebSocketWorker>.Instance,
            credStore,
            keySync,
            keyStore,
            enforcement,
            firewall,
            regService,
            configResolver,
            customConfigPath: _configPath);

        // Initially un-enrolled
        Assert.Null(worker.CurrentHardwareUuid);
        Assert.Null(worker.CurrentDeviceName);
        Assert.False(worker.IsConnected);

        // Setup Wizard completes enrollment and writes config.json
        var enrolledJson = JsonSerializer.Serialize(new
        {
            serverUrl = "http://192.168.11.100:8000",
            hardwareUuid = "b8637cb2-pc2557",
            deviceName = "NetworkLab-PC2557",
            deviceToken = "valid-token-pc2557",
            registered = true
        });
        File.WriteAllText(_configPath, enrolledJson);

        // Trigger config change
        worker.HandleConfigChanged();

        // Verifications:
        Assert.Equal("b8637cb2-pc2557", worker.CurrentHardwareUuid);
        Assert.Equal("NetworkLab-PC2557", worker.CurrentDeviceName);
        Assert.Equal("valid-token-pc2557", credStore.DeviceToken);
    }

    [Fact]
    public void CentralWebSocketWorker_HandleConfigChanged_SynchronizesAgentStore()
    {
        var credStore = new DeviceCredentialStore("bootstrap-key");
        var keyStore = new TrustedKeyStore();
        var keySync = new StubKeyringSyncService();
        var enforcement = new StubEnforcementStateMachine();
        var firewall = new MockFirewallAdapter();
        var regService = new LocalMockRegistrationService();
        var configResolver = ServiceConfigResolver.Resolve(null, null, "http://127.0.0.1:8000");
        var agentStore = new NullAgentStore();

        using var worker = new CentralWebSocketWorker(
            NullLogger<CentralWebSocketWorker>.Instance,
            credStore,
            keySync,
            keyStore,
            enforcement,
            firewall,
            regService,
            configResolver,
            customConfigPath: _configPath,
            agentStore: agentStore);

        // Initially store has no registration
        Assert.Null(agentStore.LoadSnapshot().Registration);

        // Enroll device
        var enrolledJson = JsonSerializer.Serialize(new
        {
            serverUrl = "http://192.168.11.65:8000",
            deviceId = Guid.NewGuid().ToString(),
            hardwareUuid = "hw-2557",
            deviceName = "NetworkLab-PC2557",
            deviceToken = "token-2557",
            registered = true
        });
        File.WriteAllText(_configPath, enrolledJson);

        worker.HandleConfigChanged();

        var snapshot = agentStore.LoadSnapshot();
        Assert.NotNull(snapshot.Registration);
        Assert.Equal("NetworkLab-PC2557", snapshot.Registration.DeviceName);
    }

    [Fact]
    public async Task FileSystemWatcher_RapidConfigWrites_AreDebouncedAndLoaded()
    {
        var credStore = new DeviceCredentialStore("bootstrap-key");
        var keyStore = new TrustedKeyStore();
        var keySync = new StubKeyringSyncService();
        var enforcement = new StubEnforcementStateMachine();
        var firewall = new MockFirewallAdapter();
        var regService = new LocalMockRegistrationService();
        var configResolver = ServiceConfigResolver.Resolve(null, null, "http://localhost:8000");

        using var worker = new CentralWebSocketWorker(
            NullLogger<CentralWebSocketWorker>.Instance,
            credStore,
            keySync,
            keyStore,
            enforcement,
            firewall,
            regService,
            configResolver,
            customConfigPath: _configPath);

        // Simulate rapid Setup Wizard writes (temp file write, rename, overwrite)
        for (int i = 0; i < 5; i++)
        {
            var partial = JsonSerializer.Serialize(new
            {
                serverUrl = "http://192.168.11.100:8000",
                hardwareUuid = "b8637cb2-pc2557",
                deviceName = $"NetworkLab-PC2557-step{i}",
                deviceToken = $"token-step{i}",
                registered = true
            });
            File.WriteAllText(_configPath, partial);
            await Task.Delay(30);
        }

        // Final authoritative write
        var finalJson = JsonSerializer.Serialize(new
        {
            serverUrl = "http://192.168.11.100:8000",
            hardwareUuid = "b8637cb2-pc2557",
            deviceName = "NetworkLab-PC2557",
            deviceToken = "final-valid-token-2557",
            registered = true
        });
        File.WriteAllText(_configPath, finalJson);

        // Wait for debounce timer (300ms) to fire and settle
        for (int retry = 0; retry < 30 && worker.CurrentHardwareUuid == null; retry++)
        {
            await Task.Delay(100);
        }

        Assert.Equal("b8637cb2-pc2557", worker.CurrentHardwareUuid);
        Assert.Equal("NetworkLab-PC2557", worker.CurrentDeviceName);
        Assert.Equal("final-valid-token-2557", credStore.DeviceToken);
    }

    private sealed class StubKeyringSyncService : IKeyringSyncService
    {
        public bool HasKeys => true;
        public Task<bool> EnsureKeyStoreInitializedAsync(CancellationToken ct = default) => Task.FromResult(true);
        public Task<bool> EnsureKeyStoreInitializedAsync(string? serverUrl, CancellationToken ct = default) => Task.FromResult(true);
        public Task<bool> ForceRefreshAsync(CancellationToken ct = default) => Task.FromResult(true);
        public Task<bool> ForceRefreshAsync(string? serverUrl, CancellationToken ct = default) => Task.FromResult(true);
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
}
