using System;
using System.Text.Json.Serialization;

namespace Spemcs.Agent.UI.Models;

public class LabDto
{
    [JsonPropertyName("lab_id")]
    public Guid LabId { get; set; }

    [JsonPropertyName("lab_name")]
    public string LabName { get; set; } = string.Empty;

    [JsonPropertyName("building_id")]
    public string BuildingId { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("capacity")]
    public int Capacity { get; set; }

    [JsonPropertyName("spemcs_enabled")]
    public bool SpemcsEnabled { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "active";

    [JsonIgnore]
    public string DisplayText => $"{LabName} ({BuildingId})";

    public override string ToString() => DisplayText;
}

public class DeviceRegistrationRequest
{
    [JsonPropertyName("deviceName")]
    public string DeviceName { get; set; } = string.Empty;

    [JsonPropertyName("ipAddress")]
    public string IpAddress { get; set; } = "127.0.0.1";

    [JsonPropertyName("hardwareUuid")]
    public string? HardwareUuid { get; set; }

    [JsonPropertyName("labId")]
    public string? LabId { get; set; }

    [JsonPropertyName("pcNumber")]
    public string? PcNumber { get; set; }

    [JsonPropertyName("hostname")]
    public string? Hostname { get; set; }

    [JsonPropertyName("enrollmentKey")]
    public string? EnrollmentKey { get; set; } = "spemcs-enrollment-bootstrap-key-default";
}

public class DeviceRegistrationResponse
{
    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; set; }

    [JsonPropertyName("deviceName")]
    public string DeviceName { get; set; } = string.Empty;

    [JsonPropertyName("hardwareUuid")]
    public string? HardwareUuid { get; set; }

    [JsonPropertyName("deviceToken")]
    public string? DeviceToken { get; set; }

    [JsonPropertyName("buildingName")]
    public string? BuildingName { get; set; }

    [JsonPropertyName("labName")]
    public string? LabName { get; set; }

    [JsonPropertyName("pcNumber")]
    public string? PcNumber { get; set; }

    [JsonPropertyName("ipAddress")]
    public string? IpAddress { get; set; }

    [JsonPropertyName("registeredAtUtc")]
    public string? RegisteredAtUtc { get; set; }

    [JsonPropertyName("registered")]
    public bool Registered { get; set; } = true;
}
