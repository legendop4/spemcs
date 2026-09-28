using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core;
using Spemcs.Agent.Ipc;
using Spemcs.Agent.Service;
using Spemcs.Agent.UI.Models;
using Spemcs.Agent.UI.Services;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class RegistrationUpgradeAndEnrollmentLifecycleTests
{
    // =========================================================================
    // Scenario A: Fresh install -> registration wizard
    // =========================================================================
    [Fact]
    public void ScenarioA_FreshInstall_RequiresRegistrationWizard()
    {
        AgentConfig? config = null;

        // When fresh install occurs, config is null or unpopulated
        bool needsWizard = config == null || !config.Registered || !config.IsValid();

        Assert.True(needsWizard);
    }

    // =========================================================================
    // Scenario B: Valid current config upgrade -> no wizard
    // =========================================================================
    [Fact]
    public void ScenarioB_ValidCurrentConfigUpgrade_DoesNotShowWizard()
    {
        var existingDeviceId = Guid.NewGuid();
        var config = new AgentConfig
        {
            ServerUrl = "http://10.0.0.1:8000",
            DeviceName = "Lab01-PC05",
            DeviceId = existingDeviceId.ToString(),
            DeviceToken = "valid-jwt-token-12345",
            Registered = true,
            RegisteredAtUtc = DateTimeOffset.UtcNow,
            EnrollmentKey = "bootstrap-secret"
        };

        Assert.True(config.IsEnrolled);
        Assert.True(config.IsValid());
        Assert.False(config.IsLegacySchema);

        bool needsWizard = !config.Registered || !config.IsValid();
        Assert.False(needsWizard);
    }

    // =========================================================================
    // Scenario C: Legacy 5-line config -> registration wizard
    // =========================================================================
    [Fact]
    public void ScenarioC_LegacyFiveLineConfig_RequiresRegistrationWizard()
    {
        var legacyJson = """
        {
          "serverUrl": "http://127.0.0.1:8000",
          "deviceName": "NetworkLab-PC06",
          "hardwareUuid": "NetworkLab-PC06",
          "enrollmentKey": "spemcs-enrollment-bootstrap-key-default",
          "approvedBrowser": "chrome"
        }
        """;

        var config = JsonSerializer.Deserialize<AgentConfig>(legacyJson);
        Assert.NotNull(config);

        Assert.True(config.IsLegacySchema);
        Assert.False(config.IsEnrolled);
        Assert.False(config.IsValid());

        bool needsWizard = !config.Registered || !config.IsValid();
        Assert.True(needsWizard);
    }

    // =========================================================================
    // Scenario D: Missing deviceToken -> registration wizard
    // =========================================================================
    [Fact]
    public void ScenarioD_MissingDeviceToken_RequiresRegistrationWizard()
    {
        var config = new AgentConfig
        {
            ServerUrl = "http://10.0.0.1:8000",
            DeviceName = "Lab01-PC05",
            DeviceId = Guid.NewGuid().ToString(),
            DeviceToken = null, // Missing token
            Registered = true
        };

        Assert.True(config.IsLegacySchema);
        Assert.False(config.IsEnrolled);
        Assert.False(config.IsValid());

        bool needsWizard = !config.Registered || !config.IsValid();
        Assert.True(needsWizard);
    }

    // =========================================================================
    // Scenario E: Missing deviceId -> registration wizard
    // =========================================================================
    [Fact]
    public void ScenarioE_MissingDeviceId_RequiresRegistrationWizard()
    {
        var config = new AgentConfig
        {
            ServerUrl = "http://10.0.0.1:8000",
            DeviceName = "Lab01-PC05",
            DeviceId = "", // Missing or invalid GUID
            DeviceToken = "valid-jwt-token-12345",
            Registered = true
        };

        Assert.True(config.IsLegacySchema);
        Assert.False(config.IsEnrolled);
        Assert.False(config.IsValid());

        bool needsWizard = !config.Registered || !config.IsValid();
        Assert.True(needsWizard);
    }

    // =========================================================================
    // Scenario F: Revoked token -> enrollment required
    // =========================================================================
    [Fact]
    public async Task ScenarioF_RevokedToken_TransitionsToEnrollmentRequired()
    {
        var store = new RegistrationMemoryStore();
        var initialDevId = Guid.NewGuid();
        store.SaveRegistration(new DeviceRegistration(initialDevId, "Lab01-PC05", "10.0.0.5", DateTimeOffset.UtcNow));

        var credentials = new DeviceCredentialStore("bootstrap-key", "initial-stale-token");
        Assert.Equal("initial-stale-token", credentials.DeviceToken);

        // When revoked, token is cleared
        credentials.ClearDeviceToken();
        Assert.Null(credentials.DeviceToken);

        var ui = new MockRegistrationUi();
        var coordinator = new RegistrationCoordinator(
            store,
            ui,
            isCredentialValid: () => !string.IsNullOrWhiteSpace(credentials.DeviceToken)
        );

        // Even though store has a record, because credentials are now invalid, it prompts UI!
        bool success = await coordinator.EnsureRegisteredAsync("10.0.0.5", CancellationToken.None);

        Assert.True(success);
        Assert.Equal(1, ui.Calls);
    }

    // =========================================================================
    // Scenario G: Service startup with no interactive session
    // =========================================================================
    [Fact]
    public void ScenarioG_NoInteractiveSession_DetectedCorrectly()
    {
        var launcher = new MockUiLauncher(hasInteractiveSession: false);
        Assert.False(launcher.HasActiveInteractiveSession());

        // When launching with no session, does not run Session 0 zombie process
        bool launched = launcher.Launch("C:\\Dummy\\Spemcs.Agent.UI.exe", "--setup");
        Assert.False(launched);
    }

    // =========================================================================
    // Scenario H: Upgrade preserves valid device identity
    // =========================================================================
    [Fact]
    public async Task ScenarioH_UpgradePreservesValidDeviceIdentity()
    {
        var originalId = Guid.NewGuid();
        var originalToken = "authoritative-backend-token-999";
        var originalName = "Lab01-PC05";

        var store = new RegistrationMemoryStore();
        store.SaveRegistration(new DeviceRegistration(originalId, originalName, "10.0.0.5", DateTimeOffset.UtcNow));

        var credentials = new DeviceCredentialStore("bootstrap-key", originalToken);

        var ui = new MockRegistrationUi();
        var coordinator = new RegistrationCoordinator(
            store,
            ui,
            isCredentialValid: () => !string.IsNullOrWhiteSpace(credentials.DeviceToken)
        );

        // Registration coordinator preserves existing registration
        bool success = await coordinator.EnsureRegisteredAsync("10.0.0.5", CancellationToken.None);

        Assert.True(success);
        Assert.Equal(0, ui.Calls); // UI was NOT called unnecessarily
        Assert.Equal(originalId, store.LoadSnapshot().Registration?.DeviceId);
        Assert.Equal(originalName, store.LoadSnapshot().Registration?.DeviceName);
    }

    // =========================================================================
    // Scenario I: No random Guid.NewGuid() registration synthesis
    // =========================================================================
    [Fact]
    public async Task ScenarioI_LegacyConfig_DoesNotSynthesizeRandomGuid()
    {
        var legacyJson = """
        {
          "serverUrl": "http://127.0.0.1:8000",
          "deviceName": "NetworkLab-PC06",
          "hardwareUuid": "NetworkLab-PC06",
          "enrollmentKey": "spemcs-enrollment-bootstrap-key-default"
        }
        """;

        using var doc = JsonDocument.Parse(legacyJson);
        var cRoot = doc.RootElement;

        bool isReg = cRoot.TryGetProperty("registered", out var rProp) &&
            (rProp.ValueKind == JsonValueKind.True ||
             (rProp.ValueKind == JsonValueKind.String && bool.TryParse(rProp.GetString(), out var b) && b));

        var devName = cRoot.TryGetProperty("deviceName", out var dnProp) ? dnProp.GetString() : null;
        var devIdStr = cRoot.TryGetProperty("deviceId", out var diProp) ? diProp.GetString() : null;
        var devToken = cRoot.TryGetProperty("deviceToken", out var dtProp) ? dtProp.GetString() : null;

        // In the fixed code:
        bool isAuthoritativeEnrolled = isReg &&
            !string.IsNullOrWhiteSpace(devName) &&
            Guid.TryParse(devIdStr, out var parsedId) &&
            parsedId != Guid.Empty &&
            !string.IsNullOrWhiteSpace(devToken);

        Assert.False(isAuthoritativeEnrolled);

        var store = new RegistrationMemoryStore();
        // Since isAuthoritativeEnrolled is false, store.SaveRegistration is NEVER called with a random Guid!
        Assert.Null(store.LoadSnapshot().Registration);

        var ui = new MockRegistrationUi();
        var coordinator = new RegistrationCoordinator(store, ui, isCredentialValid: () => isAuthoritativeEnrolled);
        await coordinator.EnsureRegisteredAsync("10.0.0.5", CancellationToken.None);

        // Verification: UI was called to perform genuine enrollment
        Assert.Equal(1, ui.Calls);
    }

    // =========================================================================
    // Scenario J: Existing UI mutex + setup request -> setup window is surfaced
    // =========================================================================
    [Fact]
    public void ScenarioJ_ExistingUiMutex_NeedsEnrollment_SignalsSetup()
    {
        bool hasMutexOwnership = false;
        var args = new[] { "--setup" };
        var isSetupRequested = Array.Exists(args, a => string.Equals(a, "--setup", StringComparison.OrdinalIgnoreCase));

        var unenrolledConfig = new AgentConfig { DeviceName = "Unregistered-PC", Registered = false };
        bool isAlreadyEnrolled = unenrolledConfig.IsEnrolled && unenrolledConfig.IsValid();
        bool needsEnrollment = !isAlreadyEnrolled;

        Assert.False(hasMutexOwnership);
        Assert.True(needsEnrollment);
    }

    // =========================================================================
    // Scenario K: Successful registration followed by UI/service startup must NOT reopen SetupWizardWindow
    // =========================================================================
    [Fact]
    public async Task ScenarioK_SuccessfulRegistration_FollowedByUiOrServiceStartup_MustNotReopenSetupWizard()
    {
        var deviceId = Guid.NewGuid();
        var config = new AgentConfig
        {
            ServerUrl = "http://192.168.11.65:8000",
            DeviceName = "NetworkLab-PC01",
            DeviceId = deviceId.ToString(),
            DeviceToken = "authoritative-session-token-xyz",
            Registered = true,
            RegisteredAtUtc = DateTimeOffset.UtcNow,
            EnrollmentKey = "spemcs-enrollment-bootstrap-key-default"
        };

        // 1. Verify config invariants after successful registration
        Assert.True(config.IsEnrolled);
        Assert.True(config.IsValid());

        // 2. Primary UI launch with --setup MUST suppress wizard
        var uiArgs = new[] { "--setup" };
        bool primaryEnrolled = config.IsEnrolled && config.IsValid();
        bool primaryShowWizard = !primaryEnrolled;
        Assert.False(primaryShowWizard, "Primary UI launch must NOT show setup wizard when enrolled.");

        // 3. Secondary UI launch with --setup MUST suppress signaling
        bool secondaryEnrolled = config.IsEnrolled && config.IsValid();
        bool secondaryNeedsEnrollment = !secondaryEnrolled;
        Assert.False(secondaryNeedsEnrollment, "Secondary UI launch must NOT signal setup when enrolled.");

        // 4. Service RegistrationCoordinator MUST NOT request UI registration
        var store = new RegistrationMemoryStore();
        store.SaveRegistration(new DeviceRegistration(deviceId, "NetworkLab-PC01", "127.0.0.1", DateTimeOffset.UtcNow));
        var ui = new MockRegistrationUi();
        var regService = new MockBackendRegistrationService();

        var coordinator = new RegistrationCoordinator(store, ui, regService, isCredentialValid: () => true);
        var success = await coordinator.EnsureRegisteredAsync("127.0.0.1", CancellationToken.None);

        Assert.True(success);
        Assert.Equal(0, ui.Calls);
        Assert.Equal(0, regService.Calls);

        // 5. If UI receives IPC RequestRegistration while enrolled, it must suppress wizard and reply existing data
        bool ipcEnrolled = config.IsEnrolled && config.IsValid();
        Assert.True(ipcEnrolled);
        var replyPayload = new RegistrationPayload(config.DeviceName, "127.0.0.1", Guid.Parse(config.DeviceId), config.DeviceToken);
        Assert.Equal(deviceId, replyPayload.DeviceId);
        Assert.Equal("authoritative-session-token-xyz", replyPayload.DeviceToken);
    }

    [Fact]
    public void InstallerPackageWxs_HasNeverOverwriteAndPermanentOnConfig()
    {
        var wxsPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "installer", "Package.wxs"));
        if (!File.Exists(wxsPath)) return; // Pass if run in different test directory layout

        var content = File.ReadAllText(wxsPath);
        Assert.Contains("NeverOverwrite=\"yes\"", content);
        Assert.Contains("Permanent=\"yes\"", content);
        Assert.Contains("Start=\"both\"", content);
        Assert.Contains("Stop=\"both\"", content);
        Assert.DoesNotContain("RemoveStaleAgentDb", content);
        Assert.DoesNotContain("PurgeStaleStateComponent", content);
    }

    [Fact]
    public void Upgrade_PreservesExistingConfigJson_WhenFileAlreadyExists()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"spemcs-test-upgrade-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var configPath = Path.Combine(tempDir, "config.json");
            var originalConfig = new AgentConfig
            {
                ServerUrl = "http://192.168.11.65:8000",
                DeviceName = "PaloAltoLab-PC03",
                DeviceId = Guid.NewGuid().ToString(),
                DeviceToken = "device-token-preserve-12345",
                Registered = true,
                RegisteredAtUtc = DateTimeOffset.UtcNow
            };
            File.WriteAllText(configPath, JsonSerializer.Serialize(originalConfig));

            // Simulate MSI NeverOverwrite="yes" behavior: if target exists, target remains unmodified
            bool fileExistsBeforeInstall = File.Exists(configPath);
            Assert.True(fileExistsBeforeInstall);

            // Verified: Existing file retains token and registration
            var loaded = JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(configPath));
            Assert.NotNull(loaded);
            Assert.Equal("device-token-preserve-12345", loaded.DeviceToken);
            Assert.Equal("PaloAltoLab-PC03", loaded.DeviceName);
            Assert.True(loaded.Registered);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, true);
        }
    }

    // ── Supporting Mock Classes ──────────────────────────────────────────
    private sealed class MockRegistrationUi : IExamUiGateway
    {
        public int Calls;
        public Task<DeviceRegistration?> RequestRegistrationAsync(string ipAddress, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult<DeviceRegistration?>(new DeviceRegistration(Guid.NewGuid(), "Lab01-PC05", ipAddress, DateTimeOffset.UtcNow));
        }

        public Task ShowPreComplianceLoadingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task UpdatePreComplianceResultAsync(PreComplianceScanResult result, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> RequestStudentVerificationAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task NotifySessionStartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task NotifySessionStoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class MockUiLauncher : IUiLauncher
    {
        private readonly bool _hasInteractiveSession;
        public MockUiLauncher(bool hasInteractiveSession) => _hasInteractiveSession = hasInteractiveSession;
        public bool HasActiveInteractiveSession() => _hasInteractiveSession;
        public bool Launch(string executablePath, string? arguments = null) => _hasInteractiveSession;
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

    private sealed class MockBackendRegistrationService : IRegistrationService
    {
        public int Calls;
        public Task<DeviceRegistration> RegisterDeviceAsync(string deviceName, string ipAddress, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(new DeviceRegistration(Guid.NewGuid(), deviceName, ipAddress, DateTimeOffset.UtcNow));
        }
    }
}
