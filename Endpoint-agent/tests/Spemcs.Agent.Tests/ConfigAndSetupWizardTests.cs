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
            var vm = new SetupWizardViewModel(mockApi, configService, startupService);
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
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    private class MockCentralApiClient : ICentralApiClient
    {
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
            return Task.FromResult(new DeviceRegistrationResponse
            {
                DeviceId = Guid.NewGuid().ToString(),
                DeviceName = request.DeviceName,
                HardwareUuid = request.HardwareUuid,
                BuildingName = "Main Block",
                LabName = "Lab 101",
                PcNumber = request.PcNumber,
                IpAddress = request.IpAddress,
                Registered = true
            });
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
