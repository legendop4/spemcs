using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.UI.Models;
using Spemcs.Agent.UI.Services;
using Spemcs.Agent.UI.ViewModels;
using Xunit;

namespace Spemcs.Agent.Tests;

public class ConfigAndSetupWizardTests
{
    [Fact]
    public void AgentConfigService_SavesAndLoads_Configuration()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"spemcs_test_config_{Guid.NewGuid():N}.json");
        try
        {
            var service = new AgentConfigService(tempFile);
            Assert.False(service.Exists());
            Assert.Null(service.Load());

            var config = new AgentConfig
            {
                ServerUrl = "http://192.168.1.100:8000",
                DeviceId = Guid.NewGuid().ToString(),
                DeviceName = "Lab101-PC01",
                HardwareUuid = "HW-UUID-TEST-01",
                LabId = Guid.NewGuid().ToString(),
                LabCode = "LAB101",
                LabName = "Lab 101",
                BuildingName = "Main Block",
                PcNumber = "01",
                Registered = true,
                RegisteredAtUtc = DateTimeOffset.UtcNow
            };

            service.Save(config);

            Assert.True(service.Exists());
            var loaded = service.Load();
            Assert.NotNull(loaded);
            Assert.Equal("http://192.168.1.100:8000", loaded.ServerUrl);
            Assert.Equal("Lab101-PC01", loaded.DeviceName);
            Assert.Equal("01", loaded.PcNumber);
            Assert.True(loaded.Registered);
            Assert.True(loaded.IsValid());
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public void AgentConfigService_HandlesCorruptedJson_Gracefully()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"spemcs_corrupt_{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(tempFile, "{ this is not valid JSON !!!");
            var service = new AgentConfigService(tempFile);

            var loaded = service.Load();
            Assert.Null(loaded);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task SetupWizardViewModel_Calculates_WorkstationIdentifier()
    {
        var mockApi = new MockCentralApiClient();
        var tempFile = Path.Combine(Path.GetTempPath(), $"spemcs_vm_{Guid.NewGuid():N}.json");
        var configService = new AgentConfigService(tempFile);
        var startupService = new MockStartupService();

        try
        {
            var vm = new SetupWizardViewModel(mockApi, configService, startupService, StubKey);
            await vm.InitializeAsync();

            Assert.NotEmpty(vm.Labs);
            vm.SelectedLab = vm.Labs[0]; // "Lab 101"
            vm.PcNumber = "05";

            Assert.Equal("Lab101-PC05", vm.WorkstationIdentifier);
            Assert.True(vm.CanRegister());

            vm.PcNumber = "PC-12";
            Assert.Equal("Lab101-PC-12", vm.WorkstationIdentifier);

            await vm.RegisterAsync();

            Assert.True(configService.Exists());
            var saved = configService.Load();
            Assert.NotNull(saved);
            Assert.Equal("Lab101-PC-12", saved.DeviceName);
            Assert.True(saved.Registered);
            Assert.True(startupService.Configured);

            // The device token is what every later agent call authenticates with, so a saved
            // configuration without one is a registration that did not register. Asserted here
            // because this test's own mock used to return no token at all, which made the
            // assertions above pass against exactly that broken state.
            Assert.False(string.IsNullOrWhiteSpace(saved.DeviceToken));
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    /// <summary>
    /// A stand-in for a configured enrolment key. Any non-blank value does; the wizard's own check is
    /// only "is one configured", and the value's correctness is the backend's to judge.
    /// </summary>
    private static string? StubKey() => "test-enrollment-key";

    private class MockCentralApiClient : ICentralApiClient
    {
        /// <summary>The enrolment key the last <c>RegisterDeviceAsync</c> call carried.</summary>
        public string? LastEnrollmentKey { get; private set; }

        /// <summary>When false, registration answers with no device token.</summary>
        public bool IssueDeviceToken { get; init; } = true;

        public Task<bool> CheckHealthAsync(string serverUrl, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);

        public Task<List<LabDto>> FetchLabsAsync(string serverUrl, CancellationToken cancellationToken = default)
        {
            var list = new List<LabDto>
            {
                new() { LabId = Guid.NewGuid(), LabName = "Lab 101", BuildingId = "Main Block", Capacity = 40 },
                new() { LabId = Guid.NewGuid(), LabName = "Computer Center A", BuildingId = "IT Tower", Capacity = 60 }
            };
            return Task.FromResult(list);
        }

        public Task<DeviceRegistrationResponse> RegisterDeviceAsync(string serverUrl, DeviceRegistrationRequest request, CancellationToken cancellationToken = default)
        {
            LastEnrollmentKey = request.EnrollmentKey;

            return Task.FromResult(new DeviceRegistrationResponse
            {
                DeviceId = Guid.NewGuid().ToString(),
                DeviceName = request.DeviceName,
                HardwareUuid = request.HardwareUuid,
                BuildingName = "Main Block",
                LabName = "Lab 101",
                PcNumber = request.PcNumber,
                IpAddress = request.IpAddress,
                Registered = true,
                // A real backend answers with the token it just issued. The earlier version of this
                // mock left it null, so the test asserted a successful registration against a
                // response that could not authenticate anything.
                DeviceToken = IssueDeviceToken ? $"stub-device-token-{Guid.NewGuid():N}" : null,
            });
        }
    }

    // ── The registration guard: a saved config must be able to authenticate ───────

    [Fact]
    public async Task SetupWizard_DoesNotSaveRegistration_WhenNoDeviceTokenIsIssued()
    {
        // A configuration saved with Registered=true and no token produces an agent that starts,
        // connects, monitors, and has every finding refused with 401 - which reads on the dashboard
        // as "nothing happened" rather than "nothing was delivered".
        var mockApi = new MockCentralApiClient { IssueDeviceToken = false };
        var tempFile = Path.Combine(Path.GetTempPath(), $"spemcs_vm_notoken_{Guid.NewGuid():N}.json");
        var configService = new AgentConfigService(tempFile);
        var startupService = new MockStartupService();

        try
        {
            var vm = new SetupWizardViewModel(mockApi, configService, startupService, StubKey);
            await vm.InitializeAsync();
            vm.SelectedLab = vm.Labs[0];
            vm.PcNumber = "07";

            await vm.RegisterAsync();

            Assert.False(configService.Exists());
            Assert.False(startupService.Configured);
            Assert.True(vm.IsError);
            Assert.Contains("device token", vm.StatusMessage, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task SetupWizard_RefusesToRegister_WhenNoEnrollmentKeyIsConfigured()
    {
        // Refused locally rather than sent as null, so the operator is pointed at this workstation's
        // configuration instead of at a 401 that reads as the server rejecting them.
        var mockApi = new MockCentralApiClient();
        var tempFile = Path.Combine(Path.GetTempPath(), $"spemcs_vm_nokey_{Guid.NewGuid():N}.json");
        var configService = new AgentConfigService(tempFile);
        var startupService = new MockStartupService();

        try
        {
            var vm = new SetupWizardViewModel(mockApi, configService, startupService, () => null);
            await vm.InitializeAsync();
            vm.SelectedLab = vm.Labs[0];
            vm.PcNumber = "08";

            await vm.RegisterAsync();

            Assert.Null(mockApi.LastEnrollmentKey);
            Assert.False(configService.Exists());
            Assert.True(vm.IsError);
            Assert.Contains(EnrollmentKeyProvider.EnvironmentVariableName, vm.StatusMessage, StringComparison.Ordinal);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task SetupWizard_SendsTheResolvedEnrollmentKey_WithRegistration()
    {
        var mockApi = new MockCentralApiClient();
        var tempFile = Path.Combine(Path.GetTempPath(), $"spemcs_vm_key_{Guid.NewGuid():N}.json");
        var configService = new AgentConfigService(tempFile);

        try
        {
            var vm = new SetupWizardViewModel(mockApi, configService, new MockStartupService(), StubKey);
            await vm.InitializeAsync();
            vm.SelectedLab = vm.Labs[0];
            vm.PcNumber = "09";

            await vm.RegisterAsync();

            Assert.Equal(StubKey(), mockApi.LastEnrollmentKey);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task SetupWizard_PersistsTheDeviceToken_SoARestartNeedNotReEnroll()
    {
        // The credential has to survive process exit or every restart re-enrols, and a workstation
        // that re-enrols on every boot needs the bootstrap key permanently present on disk.
        var mockApi = new MockCentralApiClient();
        var tempFile = Path.Combine(Path.GetTempPath(), $"spemcs_vm_persist_{Guid.NewGuid():N}.json");

        try
        {
            var vm = new SetupWizardViewModel(
                mockApi, new AgentConfigService(tempFile), new MockStartupService(), StubKey);
            await vm.InitializeAsync();
            vm.SelectedLab = vm.Labs[0];
            vm.PcNumber = "10";
            await vm.RegisterAsync();

            // A second service instance over the same path stands in for the next process.
            var reloaded = new AgentConfigService(tempFile).Load();
            Assert.NotNull(reloaded);
            Assert.False(string.IsNullOrWhiteSpace(reloaded.DeviceToken));
            Assert.True(reloaded.Registered);
            Assert.True(reloaded.IsValid());
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task SetupWizard_StatusMessages_NeverContainTheEnrollmentKey()
    {
        // The wizard's status line is user-visible and is screenshotted by operators reporting
        // problems. It names the config property and the environment variable; it must never name
        // the value either holds.
        const string Secret = "an-unmistakable-enrollment-secret";
        var messages = new List<string>();

        var tempFile = Path.Combine(Path.GetTempPath(), $"spemcs_vm_leak_{Guid.NewGuid():N}.json");
        try
        {
            var vm = new SetupWizardViewModel(
                new MockCentralApiClient(), new AgentConfigService(tempFile),
                new MockStartupService(), () => Secret);
            vm.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(vm.StatusMessage)) messages.Add(vm.StatusMessage);
            };

            await vm.InitializeAsync();
            vm.SelectedLab = vm.Labs[0];
            vm.PcNumber = "11";
            await vm.RegisterAsync();

            Assert.NotEmpty(messages);
            Assert.DoesNotContain(messages, m => m.Contains(Secret, StringComparison.Ordinal));
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    private class MockStartupService : IStartupService
    {
        public bool Configured { get; private set; }

        public bool ConfigureStartup(string? exePath = null)
        {
            Configured = true;
            return true;
        }

        public bool RemoveStartup()
        {
            Configured = false;
            return true;
        }

        public bool IsConfigured() => Configured;
    }
}
