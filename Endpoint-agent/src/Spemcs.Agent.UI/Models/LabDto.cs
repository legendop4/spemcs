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

    /// <summary>
    /// Bootstrap enrolment key authorising this registration.
    /// </summary>
    /// <remarks>
    /// This property previously defaulted to the literal string
    /// <c>"spemcs-enrollment-bootstrap-key-default"</c>, which is the backend's committed
    /// development placeholder. The consequence was not that enrolment was convenient: it was that
    /// the shared secret guarding device enrolment was published in the agent binary installed on
    /// every examination workstation AND in the backend source, so it protected nothing, and any
    /// deployment that changed the backend's key would have been broken by this default anyway.
    /// It is now supplied by the caller from configuration - see
    /// <c>EnrollmentKeyProvider.Resolve</c> - and a null value means unconfigured, which the
    /// backend answers with a 401 naming the problem.
    /// </remarks>
    [JsonPropertyName("enrollmentKey")]
    public string? EnrollmentKey { get; set; }
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
