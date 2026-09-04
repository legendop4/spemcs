using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Verifies and validates incoming signed network policies received over WebSocket.
/// Establishes cryptographic authenticity, monotonic version protection, exam binding,
/// and pre-enforcement management connectivity without touching firewall rules.
/// </summary>
public interface IPolicyReceiver
{
    Task<PolicyValidationResult> ProcessPolicyMessageAsync(
        SignedPolicyMessage message,
        Guid expectedExamId,
        DateTimeOffset? currentTimeUtc = null,
        bool commitVersion = true,
        CancellationToken cancellationToken = default);
}

public sealed class PolicyReceiver : IPolicyReceiver
{
    private static readonly HashSet<string> AllowedTopLevelFields = new(StringComparer.Ordinal)
    {
        "schema_version",
        "key_id",
        "exam_id",
        "policy_id",
        "version",
        "vendor_profile_id",
        "allowed_destinations",
        "management_server",
        "not_before",
        "expires_at"
    };

    private readonly ITrustedKeyStore _keyStore;
    private readonly IRollbackJournal _journal;
    private readonly IManagementConnectivityVerifier _connectivity;
    private readonly ILogger<PolicyReceiver> _logger;

    public PolicyReceiver(
        ITrustedKeyStore keyStore,
        IRollbackJournal journal,
        IManagementConnectivityVerifier connectivity,
        ILogger<PolicyReceiver>? logger = null)
    {
        _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _connectivity = connectivity ?? throw new ArgumentNullException(nameof(connectivity));
        _logger = logger ?? NullLogger<PolicyReceiver>.Instance;
    }

    public async Task<PolicyValidationResult> ProcessPolicyMessageAsync(
        SignedPolicyMessage message,
        Guid expectedExamId,
        DateTimeOffset? currentTimeUtc = null,
        bool commitVersion = true,
        CancellationToken cancellationToken = default)
    {
        // ---------------------------------------------------------------------
        // 1. Outer Message Structure Validation
        // ---------------------------------------------------------------------
        if (message is null)
        {
            return new PolicyValidationResult(PolicyAcceptanceStatus.InvalidMessage, "Message is null");
        }

        if (!string.Equals(message.MessageType, "SIGNED_NETWORK_POLICY", StringComparison.Ordinal) &&
            !string.Equals(message.MessageType, "UPDATE_EXAM_POLICY", StringComparison.Ordinal))
        {
            return new PolicyValidationResult(PolicyAcceptanceStatus.InvalidMessage, $"Unsupported message_type: '{message.MessageType}'");
        }

        if (message.ProtocolVersion != 1)
        {
            return new PolicyValidationResult(PolicyAcceptanceStatus.UnsupportedSchema, $"Unsupported protocol_version: {message.ProtocolVersion}");
        }

        if (string.IsNullOrWhiteSpace(message.RawPolicyJson))
        {
            return new PolicyValidationResult(PolicyAcceptanceStatus.MissingFields, "raw_policy_json is missing or empty");
        }

        if (string.IsNullOrWhiteSpace(message.SignatureBase64))
        {
            return new PolicyValidationResult(PolicyAcceptanceStatus.MissingFields, "signature_base64 is missing or empty");
        }

        // ---------------------------------------------------------------------
        // 2. Parse Raw Canonical JSON Document & Strict Top-Level Schema (Option A)
        // ---------------------------------------------------------------------
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(message.RawPolicyJson);
        }
        catch (Exception ex)
        {
            return new PolicyValidationResult(PolicyAcceptanceStatus.InvalidMessage, $"Failed to parse raw_policy_json as JSON: {ex.Message}");
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.InvalidMessage, "raw_policy_json must be a JSON object");
            }

            // Strict schema validation: reject unknown top-level fields
            foreach (var prop in root.EnumerateObject())
            {
                if (!AllowedTopLevelFields.Contains(prop.Name))
                {
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid, $"Unexpected top-level property '{prop.Name}' in policy schema");
                }
            }

            // Check presence of mandatory fields
            foreach (var requiredField in AllowedTopLevelFields)
            {
                if (!root.TryGetProperty(requiredField, out _))
                {
                    return new PolicyValidationResult(PolicyAcceptanceStatus.MissingFields, $"Missing mandatory field '{requiredField}'");
                }
            }

            // -----------------------------------------------------------------
            // 3. Schema Version & Key ID Resolution
            // -----------------------------------------------------------------
            var schemaVersion = root.GetProperty("schema_version").GetString();
            if (schemaVersion != "1.0")
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.UnsupportedSchema, $"Unsupported schema_version: '{schemaVersion}'");
            }

            var keyId = root.GetProperty("key_id").GetString();
            if (string.IsNullOrWhiteSpace(keyId))
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.MissingFields, "key_id is empty");
            }

            if (_keyStore.IsRevoked(keyId))
            {
                _logger.LogWarning("Policy rejected: key_id '{KeyId}' has been revoked", keyId);
                return new PolicyValidationResult(PolicyAcceptanceStatus.RejectedKeyRevoked, $"Signing key '{keyId}' has been revoked.");
            }

            var trustedRsa = _keyStore.GetPublicKey(keyId);
            if (trustedRsa is null)
            {
                _logger.LogWarning("Policy rejected: unknown or untrusted key_id '{KeyId}'", keyId);
                return new PolicyValidationResult(PolicyAcceptanceStatus.UnknownKey, $"Unknown or untrusted key_id: '{keyId}'");
            }

            // -----------------------------------------------------------------
            // 4. Cryptographic Signature Verification over Exact UTF-8 Bytes
            // -----------------------------------------------------------------
            byte[] signatureBytes;
            try
            {
                signatureBytes = Convert.FromBase64String(message.SignatureBase64);
            }
            catch (Exception ex)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.InvalidSignature, $"Malformed Base64 signature: {ex.Message}");
            }

            var rawBytes = Encoding.UTF8.GetBytes(message.RawPolicyJson);

            bool isSignatureValid;
            try
            {
                isSignatureValid = trustedRsa.VerifyData(
                    rawBytes,
                    signatureBytes,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "RSA-PSS signature verification threw exception");
                return new PolicyValidationResult(PolicyAcceptanceStatus.InvalidSignature, $"Signature verification failed: {ex.Message}");
            }

            if (!isSignatureValid)
            {
                _logger.LogWarning("Cryptographic verification failed for policy envelope.");
                return new PolicyValidationResult(PolicyAcceptanceStatus.InvalidSignature, "RSA-PSS signature mismatch.");
            }

            // -----------------------------------------------------------------
            // 5. Exam Context Binding
            // -----------------------------------------------------------------
            if (!root.GetProperty("exam_id").TryGetGuid(out var policyExamId))
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid, "Malformed exam_id UUID");
            }

            if (policyExamId != expectedExamId)
            {
                _logger.LogWarning("Exam mismatch: policy is for Exam '{PolicyExamId}', but endpoint is in Exam '{ExpectedExamId}'",
                    policyExamId, expectedExamId);
                return new PolicyValidationResult(PolicyAcceptanceStatus.ExamMismatch,
                    $"Policy exam_id '{policyExamId}' does not match expected active exam '{expectedExamId}'");
            }

            if (!root.GetProperty("policy_id").TryGetGuid(out var policyId))
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid, "Malformed policy_id UUID");
            }

            // -----------------------------------------------------------------
            // 6. Monotonic Version & Rollback Protection
            // -----------------------------------------------------------------
            if (!root.GetProperty("version").TryGetInt32(out var version) || version < 1)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid, "version must be positive integer >= 1");
            }

            var highestSeen = _journal.GetHighestPolicyVersion(expectedExamId);
            if (version <= highestSeen)
            {
                _logger.LogWarning("Rollback/Replay detected: received version {NewVersion} <= highest seen {HighestSeen}",
                    version, highestSeen);
                return new PolicyValidationResult(PolicyAcceptanceStatus.VersionReplay,
                    $"Policy version {version} rejected: must be strictly greater than active version {highestSeen}");
            }

            // -----------------------------------------------------------------
            // 7. Temporal & Validity Window Validation (Strict UTC)
            // -----------------------------------------------------------------
            var nbStr = root.GetProperty("not_before").GetString();
            var expStr = root.GetProperty("expires_at").GetString();

            if (!DateTimeOffset.TryParse(nbStr, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var notBefore) ||
                !DateTimeOffset.TryParse(expStr, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expiresAt))
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid, "Malformed ISO-8601 validity timestamps");
            }

            notBefore = notBefore.ToUniversalTime();
            expiresAt = expiresAt.ToUniversalTime();

            if (expiresAt <= notBefore)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.InvalidValidityWindow,
                    $"expires_at ({expiresAt:O}) must be strictly after not_before ({notBefore:O})");
            }

            var now = currentTimeUtc?.ToUniversalTime() ?? DateTimeOffset.UtcNow;
            if (now < notBefore)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.NotYetValid,
                    $"Policy not yet valid. Current time: {now:O}, not_before: {notBefore:O}");
            }

            if (now >= expiresAt)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.Expired,
                    $"Policy has expired. Current time: {now:O}, expires_at: {expiresAt:O}");
            }

            // -----------------------------------------------------------------
            // 8. Deserialize Destinations & Management Server
            // -----------------------------------------------------------------
            Guid? vendorProfileId = null;
            var vpProp = root.GetProperty("vendor_profile_id");
            if (vpProp.ValueKind == JsonValueKind.String && vpProp.TryGetGuid(out var parsedVpId))
            {
                vendorProfileId = parsedVpId;
            }

            var destinations = new List<PolicyDestination>();
            var allowedArray = root.GetProperty("allowed_destinations");
            if (allowedArray.ValueKind != JsonValueKind.Array)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid, "allowed_destinations must be an array");
            }

            foreach (var destEl in allowedArray.EnumerateArray())
            {
                var name = destEl.GetProperty("name").GetString() ?? "Unnamed";

                var domains = new List<string>();
                foreach (var d in destEl.GetProperty("domains").EnumerateArray())
                    if (d.GetString() is { } s) domains.Add(s);

                var ips = new List<string>();
                foreach (var ip in destEl.GetProperty("ip_ranges").EnumerateArray())
                    if (ip.GetString() is { } s) ips.Add(s);

                var tcp = new List<int>();
                foreach (var p in destEl.GetProperty("tcp_ports").EnumerateArray())
                    tcp.Add(p.GetInt32());

                var udp = new List<int>();
                foreach (var p in destEl.GetProperty("udp_ports").EnumerateArray())
                    udp.Add(p.GetInt32());

                destinations.Add(new PolicyDestination(name, domains, ips, tcp, udp));
            }

            var mgmtEl = root.GetProperty("management_server");
            var mgmtIps = new List<string>();
            foreach (var ip in mgmtEl.GetProperty("ip_addresses").EnumerateArray())
                if (ip.GetString() is { } s) mgmtIps.Add(s);

            var mgmtPort = mgmtEl.GetProperty("port").GetInt32();
            var expectedHost = mgmtEl.TryGetProperty("hostname", out var hostEl) ? hostEl.GetString() : null;
            var useTls = mgmtEl.TryGetProperty("use_tls", out var tlsEl) ? tlsEl.GetBoolean() : (mgmtPort == 443);
            var mgmtDest = new ManagementDestination(mgmtIps, mgmtPort, expectedHost, useTls);

            // -----------------------------------------------------------------
            // 9. Pre-Enforcement Management Server Connectivity Probe
            // -----------------------------------------------------------------
            var isMgmtReachable = await _connectivity.VerifyConnectivityAsync(mgmtDest, cancellationToken);
            if (!isMgmtReachable)
            {
                _logger.LogWarning("Pre-enforcement check failed: management server at {Port} is unreachable", mgmtPort);
                return new PolicyValidationResult(PolicyAcceptanceStatus.ManagementUnreachable,
                    "Pre-enforcement connectivity check failed: management server unreachable.");
            }

            // -----------------------------------------------------------------
            // 10. Persist Validated Monotonic Version & Return Result
            // -----------------------------------------------------------------
            if (commitVersion)
            {
                _journal.RecordPolicyVersion(expectedExamId, version);
            }

            var validatedPolicy = new ValidatedPolicy(
                SchemaVersion: schemaVersion,
                KeyId: keyId,
                ExamId: policyExamId,
                PolicyId: policyId,
                Version: version,
                VendorProfileId: vendorProfileId,
                AllowedDestinations: destinations,
                ManagementServer: mgmtDest,
                NotBefore: notBefore,
                ExpiresAt: expiresAt,
                RawPolicyJson: message.RawPolicyJson,
                SignatureBase64: message.SignatureBase64
            );

            _logger.LogInformation("Policy {PolicyId} (v{Version}) ACCEPTED for Exam {ExamId}",
                policyId, version, expectedExamId);

            return new PolicyValidationResult(
                Status: PolicyAcceptanceStatus.Accepted,
                Details: "Policy signature and all envelope invariants validated successfully.",
                ValidatedPolicy: validatedPolicy
            );
        }
    }
}
