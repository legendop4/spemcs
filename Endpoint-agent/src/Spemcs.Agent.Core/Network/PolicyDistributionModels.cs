using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Outer wire message received over WebSocket transport for network policy distribution.
/// </summary>
public sealed record SignedPolicyMessage(
    [property: JsonPropertyName("message_type")] string MessageType,
    [property: JsonPropertyName("protocol_version")] int ProtocolVersion,
    [property: JsonPropertyName("raw_policy_json")] string RawPolicyJson,
    [property: JsonPropertyName("signature_base64")] string SignatureBase64
);

public enum PolicyAcceptanceStatus
{
    Accepted,
    InvalidMessage,
    MissingFields,
    UnknownKey,
    RejectedKeyRevoked,
    InvalidSignature,
    UnsupportedSchema,
    NotYetValid,
    Expired,
    InvalidValidityWindow,
    VersionReplay,
    ExamMismatch,
    ManagementUnreachable,
    PolicyInvalid
}

public sealed record PolicyValidationResult(
    PolicyAcceptanceStatus Status,
    string? Details = null,
    ValidatedPolicy? ValidatedPolicy = null
);

public sealed record PolicyDestination(
    string Name,
    IReadOnlyList<string> Domains,
    IReadOnlyList<string> IpRanges,
    IReadOnlyList<int> TcpPorts,
    IReadOnlyList<int> UdpPorts
);

public sealed record ManagementDestination(
    IReadOnlyList<string> IpAddresses,
    int Port,
    string? ExpectedHostname = null,
    bool UseTls = true
);

public sealed record ValidatedPolicy(
    string SchemaVersion,
    string KeyId,
    Guid ExamId,
    Guid PolicyId,
    int Version,
    Guid? VendorProfileId,
    IReadOnlyList<PolicyDestination> AllowedDestinations,
    ManagementDestination ManagementServer,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt,
    string RawPolicyJson,
    string SignatureBase64
);
