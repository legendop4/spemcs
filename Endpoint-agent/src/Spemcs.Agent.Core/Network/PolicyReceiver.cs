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
    /// <summary>
    /// The one policy schema version this agent understands.
    /// <para>
    /// Schema 1.1 added the MANDATORY <c>approved_browser</c> field. The version was bumped
    /// rather than treating the field as optional so that a version skew fails loudly in BOTH
    /// directions: an old agent pinned to "1.0" rejects a 1.1 policy, and this agent rejects a
    /// 1.0 policy. Accepting both would mean a 1.0 policy silently produced firewall allow rules
    /// with no browser scoping - exactly the hole requirements 4 and 5 exist to close.
    /// Kept in sync with backend/backend/services/policy_signer.py :: CURRENT_SCHEMA_VERSION.
    /// </para>
    /// </summary>
    internal const string SupportedSchemaVersion = "1.1";

    /// <summary>
    /// The exact, complete set of top-level fields a signed policy may contain.
    /// <para>
    /// This set is used TWICE below: unknown fields are rejected, and every listed field is
    /// required. That dual use is deliberate - it makes "the signed payload and the agent's
    /// expectations are identical" a single, non-bypassable assertion. Adding a field here
    /// without the backend emitting it (or vice versa) is caught immediately instead of
    /// degrading silently.
    /// </para>
    /// <para>
    /// <c>approved_browser</c> belongs in the SIGNED payload specifically because firewall allow
    /// rules are scoped to that browser's executable. If it arrived out-of-band it could be
    /// swapped for another program while the signature still verified.
    /// </para>
    /// Kept in sync with backend/backend/services/policy_signer.py :: MANDATORY_PAYLOAD_FIELDS.
    /// </summary>
    private static readonly HashSet<string> AllowedTopLevelFields = new(StringComparer.Ordinal)
    {
        "schema_version",
        "key_id",
        "exam_id",
        "policy_id",
        "version",
        "vendor_profile_id",
        "approved_browser",
        "allowed_destinations",
        "management_server",
        "not_before",
        "expires_at"
    };

    /// <summary>
    /// Maps the signed <c>approved_browser</c> string onto <see cref="ApprovedBrowserFamily"/>.
    /// <para>
    /// Delegates to <see cref="ApprovedBrowserFamilies.TryParse"/> rather than carrying its own
    /// whitelist. The same string has to mean the same thing to the firewall (which scopes vendor
    /// allow rules to that browser's executable), to the process classifier (which grants it
    /// Allowed), and to the network policy evaluator (which suppresses its ordinary web traffic).
    /// Two independent copies of this switch is how those three quietly drift apart.
    /// </para>
    /// </summary>
    /// <param name="value">Raw string from the signed payload.</param>
    /// <param name="family">The mapped family; unspecified when this returns false.</param>
    /// <returns>False if the value is missing, malformed, or names an unsupported family.</returns>
    internal static bool TryParseApprovedBrowser(string? value, out ApprovedBrowserFamily family)
        => ApprovedBrowserFamilies.TryParse(value, out family);

    /// <summary>
    /// Reads a required array-of-strings property, reporting a reason instead of throwing.
    /// <para>
    /// The nested objects of a policy are not covered by the top-level mandatory-field check, so
    /// every nested read has to tolerate absence. <c>JsonElement.GetProperty</c> throws
    /// <see cref="KeyNotFoundException"/>, which inside the WebSocket receive loop would surface as
    /// a crashed connection rather than as a rejected policy - the operator would see the agent
    /// drop offline with no explanation of which field was wrong.
    /// </para>
    /// <para>
    /// Blank entries are skipped rather than rejected, matching the previous behaviour; a
    /// non-string entry is rejected, because it means the sender's schema differs from ours and
    /// guessing which is right is not the agent's job.
    /// </para>
    /// </summary>
    private static bool TryReadStringArray(
        JsonElement parent,
        string property,
        out List<string> values,
        out string? error)
    {
        values = new List<string>();

        if (!parent.TryGetProperty(property, out var element) ||
            element.ValueKind != JsonValueKind.Array)
        {
            error = $"missing or non-array '{property}'";
            return false;
        }

        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                error = $"'{property}' contains a non-string entry";
                return false;
            }

            var text = item.GetString();
            if (!string.IsNullOrWhiteSpace(text))
            {
                values.Add(text.Trim());
            }
        }

        error = null;
        return true;
    }

    /// <summary>
    /// Reads a required array-of-ports property, validating the 1-65535 range.
    /// <para>
    /// Port 0 and negative values are rejected rather than passed through: 0 is not a port, and a
    /// firewall rule built from one either fails to apply or applies to something unintended.
    /// </para>
    /// </summary>
    private static bool TryReadPortArray(
        JsonElement parent,
        string property,
        out List<int> values,
        out string? error)
    {
        values = new List<int>();

        if (!parent.TryGetProperty(property, out var element) ||
            element.ValueKind != JsonValueKind.Array)
        {
            error = $"missing or non-array '{property}'";
            return false;
        }

        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt32(out var port))
            {
                error = $"'{property}' contains an entry that is not a 32-bit integer";
                return false;
            }

            if (port < 1 || port > 65535)
            {
                error = $"'{property}' contains out-of-range port {port}";
                return false;
            }

            values.Add(port);
        }

        error = null;
        return true;
    }

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
            // The explicit null check is not redundant: string.Equals(string?, string?, ...) is
            // not annotated for null-state analysis, so without it `schemaVersion` stays
            // maybe-null and constructing ValidatedPolicy below would warn (warnings are errors).
            if (schemaVersion is null ||
                !string.Equals(schemaVersion, SupportedSchemaVersion, StringComparison.Ordinal))
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.UnsupportedSchema,
                    $"Unsupported schema_version: '{schemaVersion}' (this agent requires '{SupportedSchemaVersion}')");
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
            // 8. Approved Browser Identity, Destinations & Management Server
            // -----------------------------------------------------------------
            // Deliberately parsed AFTER signature verification (step 4). The browser identity is
            // only meaningful once the bytes are known to be authentic, and reporting
            // UnsupportedApprovedBrowser for an unsigned/forged envelope would mislabel a forgery
            // as a configuration problem in the operator's logs.
            var approvedBrowserRaw = root.GetProperty("approved_browser").GetString();
            if (!TryParseApprovedBrowser(approvedBrowserRaw, out var approvedBrowser))
            {
                _logger.LogError(
                    "Policy {PolicyId} names approved_browser '{ApprovedBrowser}', which this agent cannot scope firewall rules to. Failing closed.",
                    policyId, approvedBrowserRaw);
                return new PolicyValidationResult(PolicyAcceptanceStatus.UnsupportedApprovedBrowser,
                    $"approved_browser '{approvedBrowserRaw}' is not a browser family this agent can resolve to an executable. " +
                    "Vendor allow rules must be scoped to the approved browser, so enforcement cannot proceed.");
            }

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

            var destIndex = -1;
            foreach (var destEl in allowedArray.EnumerateArray())
            {
                destIndex++;

                if (destEl.ValueKind != JsonValueKind.Object)
                {
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                        $"allowed_destinations[{destIndex}] must be an object");
                }

                // Destination-level fields are NOT covered by the mandatory-field check above,
                // which only walks the top level. They have to be checked explicitly here:
                // GetProperty on an absent field throws KeyNotFoundException, which would escape
                // as an unhandled exception in the WebSocket receive loop instead of being
                // reported as the invalid policy it is.
                if (!destEl.TryGetProperty("name", out var nameEl) ||
                    nameEl.ValueKind != JsonValueKind.String)
                {
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                        $"allowed_destinations[{destIndex}] is missing a string 'name'");
                }

                var name = nameEl.GetString() ?? string.Empty;

                if (!TryReadStringArray(destEl, "domains", out var domains, out var domainsError))
                {
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                        $"allowed_destinations[{destIndex}]: {domainsError}");
                }

                if (!TryReadStringArray(destEl, "ip_ranges", out var ips, out var ipsError))
                {
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                        $"allowed_destinations[{destIndex}]: {ipsError}");
                }

                if (!TryReadPortArray(destEl, "tcp_ports", out var tcp, out var tcpError))
                {
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                        $"allowed_destinations[{destIndex}]: {tcpError}");
                }

                if (!TryReadPortArray(destEl, "udp_ports", out var udp, out var udpError))
                {
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                        $"allowed_destinations[{destIndex}]: {udpError}");
                }

                // Defense in depth. Every range below becomes an outbound allow rule scoped to the
                // examination browser, so the agent re-applies the address rules rather than
                // trusting that the signer applied them. See PolicyDestinationValidator for why a
                // verified signature is not sufficient authority for an address.
                if (!PolicyDestinationValidator.TryValidate(destIndex, name, ips, out var rejection))
                {
                    _logger.LogError(
                        "Policy {PolicyId} REJECTED for Exam {ExamId}: {Rejection}. The signature " +
                        "verified, so the backend and this agent disagree about what may be " +
                        "allowed; no firewall rules were built",
                        policyId, expectedExamId, rejection);
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                        rejection ?? "Destination rejected by endpoint address validation");
                }

                destinations.Add(new PolicyDestination(name, domains, ips, tcp, udp));
            }

            var mgmtEl = root.GetProperty("management_server");
            if (mgmtEl.ValueKind != JsonValueKind.Object)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                    "management_server must be an object");
            }

            if (!TryReadStringArray(mgmtEl, "ip_addresses", out var mgmtIps, out var mgmtIpsError))
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                    $"management_server: {mgmtIpsError}");
            }

            if (mgmtIps.Count == 0)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                    "management_server names no ip_addresses, so the agent would lose its " +
                    "management channel the moment default-deny engages");
            }

            // The management allow rule is deliberately NOT scoped to a program - it belongs to the
            // agent service, not the browser - so it is the one rule in the set that any process
            // could use. Its narrowness therefore rests entirely on the address being a single
            // host. A range, a wildcard, or an unspecified address here would become an
            // any-program outbound allow rule, which is a far wider hole than a bad destination.
            foreach (var mgmtIp in mgmtIps)
            {
                var problem = PolicyDestinationValidator.DescribeUnsafeManagementAddress(mgmtIp);
                if (problem is not null)
                {
                    _logger.LogError(
                        "Policy {PolicyId} REJECTED for Exam {ExamId}: management_server {Problem}",
                        policyId, expectedExamId, problem);
                    return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                        $"management_server: {problem}");
                }
            }

            if (!mgmtEl.TryGetProperty("port", out var portEl) ||
                portEl.ValueKind != JsonValueKind.Number ||
                !portEl.TryGetInt32(out var mgmtPort) ||
                mgmtPort < 1 || mgmtPort > 65535)
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                    "management_server.port must be an integer between 1 and 65535");
            }

            var expectedHost = mgmtEl.TryGetProperty("hostname", out var hostEl) &&
                               hostEl.ValueKind == JsonValueKind.String
                ? hostEl.GetString()
                : null;

            // Absent means "infer from the port", which is what plain-HTTP development deployments
            // rely on. Present-but-not-a-boolean is a schema mismatch rather than something to
            // guess at, and guessing wrong here decides whether the management channel is
            // encrypted.
            bool useTls;
            if (!mgmtEl.TryGetProperty("use_tls", out var tlsEl))
            {
                useTls = mgmtPort == 443;
            }
            else if (tlsEl.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                useTls = tlsEl.GetBoolean();
            }
            else
            {
                return new PolicyValidationResult(PolicyAcceptanceStatus.PolicyInvalid,
                    "management_server.use_tls must be a boolean when present");
            }

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
                ApprovedBrowser: approvedBrowser,
                AllowedDestinations: destinations,
                ManagementServer: mgmtDest,
                NotBefore: notBefore,
                ExpiresAt: expiresAt,
                RawPolicyJson: message.RawPolicyJson,
                SignatureBase64: message.SignatureBase64
            );

            _logger.LogInformation("Policy {PolicyId} (v{Version}) ACCEPTED for Exam {ExamId}; approved browser {ApprovedBrowser}",
                policyId, version, expectedExamId, approvedBrowser);

            return new PolicyValidationResult(
                Status: PolicyAcceptanceStatus.Accepted,
                Details: "Policy signature and all envelope invariants validated successfully.",
                ValidatedPolicy: validatedPolicy
            );
        }
    }
}
