using System;
using System.Text.Json.Serialization;

namespace Spemcs.Agent.UI.Models;

public class AgentConfig
{
    [JsonPropertyName("serverUrl")]
    public string ServerUrl { get; set; } = "http://127.0.0.1:8001";

    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; set; }

    [JsonPropertyName("deviceName")]
    public string DeviceName { get; set; } = "lab1";

    [JsonPropertyName("hardwareUuid")]
    public string? HardwareUuid { get; set; }

    [JsonPropertyName("deviceToken")]
    public string? DeviceToken { get; set; }

    [JsonPropertyName("labId")]
    public string? LabId { get; set; }

    [JsonPropertyName("labCode")]
    public string? LabCode { get; set; }

    [JsonPropertyName("labName")]
    public string? LabName { get; set; }

    [JsonPropertyName("buildingName")]
    public string? BuildingName { get; set; }

    [JsonPropertyName("pcNumber")]
    public string? PcNumber { get; set; }

    [JsonPropertyName("registered")]
    public bool Registered { get; set; }

    [JsonPropertyName("registeredAtUtc")]
    public DateTimeOffset? RegisteredAtUtc { get; set; }

    public bool IsValid()
    {
        return !string.IsNullOrWhiteSpace(ServerUrl) &&
               !string.IsNullOrWhiteSpace(DeviceName) &&
               Registered;
    }
}
