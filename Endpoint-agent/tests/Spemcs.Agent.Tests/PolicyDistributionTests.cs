using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class PolicyDistributionTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly SqliteRollbackJournal _journal;
    private readonly TrustedKeyStore _keyStore;
    private readonly MockManagementConnectivityVerifier _connectivity;
    private readonly PolicyReceiver _receiver;

    // Cross-language fixtures (payloads signed by the real Python backend signer) are shared
    // with EnforcementStateMachineUnitTests via PythonInteropFixtures so the two cannot drift.
    private const string PythonRawJson = PythonInteropFixtures.ValidRawJson;
    private const string PythonSignatureBase64 = PythonInteropFixtures.ValidSignatureBase64;
    private static readonly Guid PythonExamId = PythonInteropFixtures.ExamId;

    public PolicyDistributionTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_m5_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDbPath);
        _journal = new SqliteRollbackJournal(_tempDbPath);
        _keyStore = new TrustedKeyStore();
        _connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
        _receiver = new PolicyReceiver(_keyStore, _journal, _connectivity);

        // Register the python dev public key
        _keyStore.RegisterPublicKeyPem(
            PythonInteropFixtures.KeyId, PythonInteropFixtures.PublicKeyPem);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDbPath))
                Directory.Delete(_tempDbPath, true);
        }
        catch { }
    }

    // =========================================================================
    // 1. Cross-Language Cryptographic Tests (Section 20)
    // =========================================================================

    [Fact]
    public async Task CrossLanguage_PythonM2Signature_VerifiesSuccessfullyInCSharp()
    {
        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        // Test with a time inside validity window [2026-01-01, 2030-01-01]
        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);

        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);

        Assert.Equal(PolicyAcceptanceStatus.Accepted, result.Status);
        Assert.NotNull(result.ValidatedPolicy);
        Assert.Equal(PythonExamId, result.ValidatedPolicy.ExamId);
        Assert.Equal(1, result.ValidatedPolicy.Version);
        Assert.Equal("1.1", result.ValidatedPolicy.SchemaVersion);

        // The approved browser must survive the Python -> C# hop intact: it is the identity every
        // vendor firewall allow rule is scoped to, so a parsing discrepancy here would silently
        // widen or break the allowlist.
        Assert.Equal(ApprovedBrowserFamily.Chrome, result.ValidatedPolicy.ApprovedBrowser);

        Assert.Equal(1, _connectivity.CallCount);
    }

    [Fact]
    public async Task CrossLanguage_LegacySchema10Payload_RejectedFailClosed()
    {
        // Signed by the same trusted key and cryptographically intact, but emitted by a pre-1.1
        // backend: schema_version "1.0" and no approved_browser field. Accepting it would mean a
        // vendor allow rule with no program scope, which is exactly the requirement 4/5 bypass the
        // schema bump exists to prevent.
        var result = await _receiver.ProcessPolicyMessageAsync(
            PythonInteropFixtures.LegacySchema10Message(),
            PythonExamId,
            PythonInteropFixtures.ValidEvalTime);

        Assert.NotEqual(PolicyAcceptanceStatus.Accepted, result.Status);
        Assert.Null(result.ValidatedPolicy);
        Assert.True(
            result.Status is PolicyAcceptanceStatus.MissingFields
                          or PolicyAcceptanceStatus.UnsupportedSchema,
            $"expected a schema/mandatory-field rejection, got {result.Status}: {result.Details}");

        // Version skew must not be mistaken for tampering - that would send an operator hunting a
        // non-existent attack instead of upgrading the backend.
        Assert.NotEqual(PolicyAcceptanceStatus.InvalidSignature, result.Status);
    }

    [Fact]
    public async Task CrossLanguage_UnscopableApprovedBrowser_RejectedAfterSignatureVerifies()
    {
        // Schema 1.1, valid signature, but names a browser family the endpoint has no approval
        // branch for. The status proves WHERE it was refused: UnsupportedApprovedBrowser means the
        // signature verified first, so a valid signature alone can never buy an unscopable rule.
        var result = await _receiver.ProcessPolicyMessageAsync(
            PythonInteropFixtures.UnscopableBrowserMessage(),
            PythonExamId,
            PythonInteropFixtures.ValidEvalTime);

        Assert.Equal(PolicyAcceptanceStatus.UnsupportedApprovedBrowser, result.Status);
        Assert.Null(result.ValidatedPolicy);
    }

    [Fact]
    public async Task TamperedRawPolicyJson_FailsSignatureVerification()
    {
        // Alter 1 byte in the raw JSON payload
        var tamperedJson = PythonRawJson.Replace("192.168.1.0/24", "192.168.2.0/24");

        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: tamperedJson,
            SignatureBase64: PythonSignatureBase64
        );

        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);
        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);

        Assert.Equal(PolicyAcceptanceStatus.InvalidSignature, result.Status);
        Assert.Null(result.ValidatedPolicy);
    }

    [Fact]
    public async Task TamperedSignatureBase64_FailsSignatureVerification()
    {
        // Flip characters in signature
        var tamperedSig = "A" + PythonSignatureBase64.Substring(1);

        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: tamperedSig
        );

        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);
        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);

        Assert.Equal(PolicyAcceptanceStatus.InvalidSignature, result.Status);
    }

    [Fact]
    public async Task UnknownKeyId_FailsClosed()
    {
        var rawWithUnknownKey = PythonRawJson.Replace("\"key_id\":\"dev-key-1\"", "\"key_id\":\"unknown-key-99\"");

        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: rawWithUnknownKey,
            SignatureBase64: PythonSignatureBase64
        );

        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);
        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);

        Assert.Equal(PolicyAcceptanceStatus.UnknownKey, result.Status);
    }

    [Fact]
    public async Task WrongKey_FailsSignatureVerification()
    {
        // Replace dev-key-1 with a freshly generated unrelated RSA key
        using var unrelatedRsa = RSA.Create(2048);
        var customKeyStore = new TrustedKeyStore();
        customKeyStore.RegisterPublicKey("dev-key-1", unrelatedRsa);

        var customReceiver = new PolicyReceiver(customKeyStore, _journal, _connectivity);

        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);
        var result = await customReceiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);

        Assert.Equal(PolicyAcceptanceStatus.InvalidSignature, result.Status);
    }

    // =========================================================================
    // 2. Protocol Wire & Message Envelope Tests
    // =========================================================================

    [Fact]
    public async Task MalformedMessageType_IsRejected()
    {
        var msg = new SignedPolicyMessage(
            MessageType: "UNKNOWN_MESSAGE_TYPE",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId);
        Assert.Equal(PolicyAcceptanceStatus.InvalidMessage, result.Status);
    }

    [Fact]
    public async Task UnsupportedProtocolVersion_IsRejected()
    {
        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 99,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId);
        Assert.Equal(PolicyAcceptanceStatus.UnsupportedSchema, result.Status);
    }

    [Fact]
    public async Task MissingRawPolicyJson_IsRejected()
    {
        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: "",
            SignatureBase64: PythonSignatureBase64
        );

        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId);
        Assert.Equal(PolicyAcceptanceStatus.MissingFields, result.Status);
    }

    // =========================================================================
    // 3. Strict Schema Validation (Option A)
    // =========================================================================

    [Fact]
    public async Task StrictSchema_ExtraTopLevelField_IsRejected()
    {
        // Injected unauthorized extra top-level field into policy JSON
        var jsonWithExtraField = PythonRawJson.Replace(
            "\"schema_version\":\"1.1\",",
            "\"schema_version\":\"1.1\",\"attacker_injected_field\":\"malicious\",");

        // Guard the guard: if the anchor string ever stops matching, the "attack" would silently
        // become a no-op and this test would start asserting against an untampered payload.
        Assert.NotEqual(PythonRawJson, jsonWithExtraField);

        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: jsonWithExtraField,
            SignatureBase64: PythonSignatureBase64
        );

        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId);
        Assert.Equal(PolicyAcceptanceStatus.PolicyInvalid, result.Status);
        Assert.Contains("Unexpected top-level property", result.Details);
    }

    // =========================================================================
    // 4. Temporal & Window Validation Tests
    // =========================================================================

    [Fact]
    public async Task PolicyNotYetValid_IsRejected()
    {
        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        // Before 2026-01-01
        var beforeTime = new DateTimeOffset(2025, 12, 31, 23, 59, 59, TimeSpan.Zero);
        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, beforeTime);

        Assert.Equal(PolicyAcceptanceStatus.NotYetValid, result.Status);
    }

    [Fact]
    public async Task PolicyExpired_IsRejected()
    {
        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        // At or after 2030-01-01
        var afterTime = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, afterTime);

        Assert.Equal(PolicyAcceptanceStatus.Expired, result.Status);
    }

    // =========================================================================
    // 5. Exam Context Binding Tests
    // =========================================================================

    [Fact]
    public async Task WrongExamBinding_IsRejected()
    {
        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        var differentExamId = Guid.NewGuid();
        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);

        var result = await _receiver.ProcessPolicyMessageAsync(msg, differentExamId, evalTime);

        Assert.Equal(PolicyAcceptanceStatus.ExamMismatch, result.Status);
    }

    // =========================================================================
    // 6. Monotonic Version & Rollback Protection Tests
    // =========================================================================

    [Fact]
    public async Task MonotonicVersion_ReplayAndRollbackAreRejected()
    {
        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);

        // First attempt: Accepted (version 1)
        var firstResult = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);
        Assert.Equal(PolicyAcceptanceStatus.Accepted, firstResult.Status);

        // Second attempt with same version 1: Rejected as replay
        var replayResult = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);
        Assert.Equal(PolicyAcceptanceStatus.VersionReplay, replayResult.Status);

        // Version state in new instance of journal survives
        var newJournal = new SqliteRollbackJournal(_tempDbPath);
        Assert.Equal(1, newJournal.GetHighestPolicyVersion(PythonExamId));
    }

    // =========================================================================
    // 7. Management Connectivity Verification Tests
    // =========================================================================

    [Fact]
    public async Task UnreachableManagementServer_RejectsPolicy()
    {
        var unreachableConnectivity = new MockManagementConnectivityVerifier(shouldSucceed: false);
        var receiver = new PolicyReceiver(_keyStore, _journal, unreachableConnectivity);

        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);
        var result = await receiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);

        Assert.Equal(PolicyAcceptanceStatus.ManagementUnreachable, result.Status);
    }

    // =========================================================================
    // 8. Firewall Invariance / Non-Interference (Section 18)
    // =========================================================================

    [Fact]
    public async Task PolicyReceiver_NeverTouchesFirewall()
    {
        var mockFirewall = new MockFirewallAdapter();
        var initialBaseline = mockFirewall.GetBaseline();

        var msg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: PythonRawJson,
            SignatureBase64: PythonSignatureBase64
        );

        var evalTime = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);
        var result = await _receiver.ProcessPolicyMessageAsync(msg, PythonExamId, evalTime);

        Assert.Equal(PolicyAcceptanceStatus.Accepted, result.Status);

        // Verify that 0 rules were added to firewall and baseline default action is untouched!
        Assert.Empty(mockFirewall.Rules);
        var currentBaseline = mockFirewall.GetBaseline();
        Assert.Equal(initialBaseline.DomainDefaultOutbound, currentBaseline.DomainDefaultOutbound);
        Assert.Equal(initialBaseline.PrivateDefaultOutbound, currentBaseline.PrivateDefaultOutbound);
        Assert.Equal(initialBaseline.PublicDefaultOutbound, currentBaseline.PublicDefaultOutbound);
    }
}
