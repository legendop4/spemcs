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
    PolicyInvalid,

    /// <summary>
    /// The signed policy named an approved browser this agent cannot map to a browser family
    /// (see <see cref="BrowserExecutableResolver"/>). Distinct from PolicyInvalid so operators
    /// can tell a configuration mismatch apart from a malformed envelope.
    /// </summary>
    UnsupportedApprovedBrowser
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

/// <summary>
/// A signed policy that has passed every envelope invariant (signature, schema, exam binding,
/// monotonic version, validity window).
/// </summary>
/// <param name="ApprovedBrowser">
/// The approved examination browser family, taken from the SIGNED policy payload.
/// Requirements 4 and 5: every vendor/exam destination allow rule is scoped to this browser's
/// executable, so this value must never come from unsigned local input.
/// </param>
public sealed record ValidatedPolicy(
    string SchemaVersion,
    string KeyId,
    Guid ExamId,
    Guid PolicyId,
    int Version,
    Guid? VendorProfileId,
    ApprovedBrowserFamily ApprovedBrowser,
    IReadOnlyList<PolicyDestination> AllowedDestinations,
    ManagementDestination ManagementServer,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt,
    string RawPolicyJson,
    string SignatureBase64
);
