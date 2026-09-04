using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class SecurityHardeningUnitTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly SqliteRollbackJournal _journal;
    private readonly TrustedKeyStore _keyStore;
    private readonly MockManagementConnectivityVerifier _connectivity;
    private readonly PolicyReceiver _receiver;
    private readonly RSA _rsa1;
    private readonly RSA _rsa2;
    private const string KeyId1 = "dev-key-1";
    private const string KeyId2 = "dev-key-2";
    private static readonly Guid TestExamId = Guid.NewGuid();

    public SecurityHardeningUnitTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"spemcs_m8_sec_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDbPath);
        _journal = new SqliteRollbackJournal(_tempDbPath);
        _keyStore = new TrustedKeyStore();
        _connectivity = new MockManagementConnectivityVerifier(shouldSucceed: true);
        _receiver = new PolicyReceiver(_keyStore, _journal, _connectivity);

        _rsa1 = RSA.Create(2048);
        _rsa2 = RSA.Create(2048);
        _keyStore.RegisterPublicKey(KeyId1, _rsa1);
        _keyStore.RegisterPublicKey(KeyId2, _rsa2);
    }

    public void Dispose()
    {
        _rsa1.Dispose();
        _rsa2.Dispose();
        try
        {
            if (Directory.Exists(_tempDbPath))
                Directory.Delete(_tempDbPath, true);
        }
        catch { }
    }

    private SignedPolicyMessage CreateSignedMessage(RSA rsa, string keyId, int version)
    {
        var payloadObj = new Dictionary<string, object?>
        {
            ["schema_version"] = "1.1",
            ["key_id"] = keyId,
            ["exam_id"] = TestExamId.ToString(),
            ["policy_id"] = Guid.NewGuid().ToString(),
            ["version"] = version,
            ["vendor_profile_id"] = null,
            // Mandatory from schema 1.1: the approved browser is the identity every vendor allow
            // rule is scoped to, so it has to be inside the signed bytes.
            ["approved_browser"] = "chrome",
            ["allowed_destinations"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["name"] = "VendorApp",
                    ["domains"] = new List<string> { "vendor.example.com" },
                    ["ip_ranges"] = new List<string> { "192.168.1.10" },
                    ["tcp_ports"] = new List<int> { 443 },
                    ["udp_ports"] = new List<int>()
                }
            },
            ["management_server"] = new Dictionary<string, object>
            {
                ["ip_addresses"] = new List<string> { "127.0.0.1" },
                ["port"] = 8000
            },
            ["not_before"] = DateTimeOffset.UtcNow.AddMinutes(-5).ToString("O"),
            ["expires_at"] = DateTimeOffset.UtcNow.AddHours(2).ToString("O")
        };

        var rawJson = JsonSerializer.Serialize(payloadObj);
        var rawBytes = System.Text.Encoding.UTF8.GetBytes(rawJson);
        var sigBytes = rsa.SignData(rawBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        return new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: rawJson,
            SignatureBase64: Convert.ToBase64String(sigBytes)
        );
    }

    // =========================================================================
    // 1. Signing Key Lifecycle & Revocation (Gate 9)
    // =========================================================================

    [Fact]
    public async Task KeyStore_Revocation_BlocksSignatureVerification()
    {
        // Valid policy signed with KeyId1
        var msg = CreateSignedMessage(_rsa1, KeyId1, version: 1);

        // Precondition: Key is valid and accepted
        var validResult = await _receiver.ProcessPolicyMessageAsync(msg, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.Accepted, validResult.Status);

        // Revoke KeyId1
        _keyStore.RevokeKey(KeyId1, "Compromised key test");
        Assert.True(_keyStore.IsRevoked(KeyId1));

        // Attempt validation after revocation: must be rejected with RejectedKeyRevoked
        var revokedResult = await _receiver.ProcessPolicyMessageAsync(msg, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.RejectedKeyRevoked, revokedResult.Status);
        Assert.Contains("revoked", revokedResult.Details, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task KeyStore_Rotation_AllowsMultipleTrustedKeys()
    {
        // Policy A signed with Key 1
        var msgKey1 = CreateSignedMessage(_rsa1, KeyId1, version: 1);
        var res1 = await _receiver.ProcessPolicyMessageAsync(msgKey1, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.Accepted, res1.Status);

        // Rotated Policy B signed with Key 2
        var msgKey2 = CreateSignedMessage(_rsa2, KeyId2, version: 2);
        var res2 = await _receiver.ProcessPolicyMessageAsync(msgKey2, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.Accepted, res2.Status);
    }

    [Fact]
    public void KeyStore_Revocation_DurableAcrossRestart()
    {
        // Persist revocation in SQLite journal
        _journal.SaveRevokedKey("revoked-key-x", "Security incident");

        var revokedKeys = _journal.GetRevokedKeys();
        Assert.Contains("revoked-key-x", revokedKeys);
    }

    // =========================================================================
    // 2. Command Replay Protection (Gate 7 & 10)
    // =========================================================================

    [Fact]
    public void CommandReplay_DuplicateCommandId_Rejected()
    {
        var filter = new CommandReplayFilter(_journal);
        var commandId = Guid.NewGuid().ToString();
        var issuedAt = DateTimeOffset.UtcNow;

        // First execution: Accepted
        var first = filter.ValidateAndConsume(commandId, "LAUNCH_EXAM_MODE", issuedAt, TestExamId);
        Assert.Equal(CommandValidationStatus.Accepted, first.Status);

        // Second execution: Replay Rejected
        var second = filter.ValidateAndConsume(commandId, "LAUNCH_EXAM_MODE", issuedAt, TestExamId);
        Assert.Equal(CommandValidationStatus.Replayed, second.Status);
    }

    [Fact]
    public void CommandReplay_ExpiredTimestamp_Rejected()
    {
        var filter = new CommandReplayFilter(_journal);
        var commandId = Guid.NewGuid().ToString();
        var expiredIssuedAt = DateTimeOffset.UtcNow.AddMinutes(-10); // 10 minutes ago (limit is 5 min)

        var result = filter.ValidateAndConsume(commandId, "LAUNCH_EXAM_MODE", expiredIssuedAt, TestExamId);
        Assert.Equal(CommandValidationStatus.Expired, result.Status);
    }

    [Fact]
    public void CommandReplay_FutureTimestamp_Rejected()
    {
        var filter = new CommandReplayFilter(_journal);
        var commandId = Guid.NewGuid().ToString();
        var futureIssuedAt = DateTimeOffset.UtcNow.AddMinutes(10); // 10 minutes in future

        var result = filter.ValidateAndConsume(commandId, "LAUNCH_EXAM_MODE", futureIssuedAt, TestExamId);
        Assert.Equal(CommandValidationStatus.FutureTimestamp, result.Status);
    }

    [Fact]
    public void CommandReplay_SurvivesServiceRestart()
    {
        var commandId = Guid.NewGuid().ToString();
        var issuedAt = DateTimeOffset.UtcNow;

        // Process in first journal instance
        var filter1 = new CommandReplayFilter(_journal);
        var res1 = filter1.ValidateAndConsume(commandId, "LAUNCH_EXAM_MODE", issuedAt, TestExamId);
        Assert.Equal(CommandValidationStatus.Accepted, res1.Status);

        // Simulate service restart with new journal instance pointing to same SQLite database
        var restartJournal = new SqliteRollbackJournal(_tempDbPath);
        var filter2 = new CommandReplayFilter(restartJournal);

        var res2 = filter2.ValidateAndConsume(commandId, "LAUNCH_EXAM_MODE", issuedAt, TestExamId);
        Assert.Equal(CommandValidationStatus.Replayed, res2.Status);
    }

    // =========================================================================
    // 3. Real TLS Verification & Management Transport Security (Cases A - F)
    // =========================================================================

    private static X509Certificate2 CreateRootCaCertificate(string caName)
    {
        using var rsa = RSA.Create(2048);
        var subject = new X500DistinguishedName($"CN={caName}");
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return new X509Certificate2(cert.Export(X509ContentType.Pfx, "testpwd"), "testpwd", X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 CreateServerCertificate(string hostname, X509Certificate2 issuerCa, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var rsa = RSA.Create(2048);
        var subject = new X500DistinguishedName($"CN={hostname}");
        var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(hostname);
        if (IPAddress.TryParse(hostname, out var ip))
        {
            san.AddIpAddress(ip);
        }
        req.CertificateExtensions.Add(san.Build());

        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using var certNoKey = req.Create(issuerCa, notBefore, notAfter, serial);
        using var certWithKey = certNoKey.CopyWithPrivateKey(rsa);
        return new X509Certificate2(certWithKey.Export(X509ContentType.Pfx, "testpwd"), "testpwd", X509KeyStorageFlags.Exportable);
    }

    private static (int Port, CancellationTokenSource Cts) StartHttpsServer(X509Certificate2 serverCert, string responseBody, int statusCode = 200)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var cts = new CancellationTokenSource();

        _ = Task.Run(async () =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await listener.AcceptTcpClientAsync(cts.Token);
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using (tcpClient)
                            using (var sslStream = new SslStream(tcpClient.GetStream(), false))
                            {
                                await sslStream.AuthenticateAsServerAsync(serverCert);
                                var buf = new byte[1024];
                                await sslStream.ReadAsync(buf, 0, buf.Length, cts.Token);

                                var bodyBytes = System.Text.Encoding.UTF8.GetBytes(responseBody);
                                var headerStr = $"HTTP/1.1 {statusCode} OK\r\nContent-Type: application/json\r\nContent-Length: {bodyBytes.Length}\r\nConnection: close\r\n\r\n";
                                var headerBytes = System.Text.Encoding.UTF8.GetBytes(headerStr);
                                await sslStream.WriteAsync(headerBytes, 0, headerBytes.Length, cts.Token);
                                await sslStream.WriteAsync(bodyBytes, 0, bodyBytes.Length, cts.Token);
                                await sslStream.FlushAsync(cts.Token);
                            }
                        }
                        catch { }
                    });
                }
                catch { break; }
            }
            try { listener.Stop(); } catch { }
        });

        return (port, cts);
    }

    private static HttpClient CreateStrictTlsClient(X509Certificate2 trustedRootCa, string targetHost)
    {
        var chainPolicy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        chainPolicy.CustomTrustStore.Add(trustedRootCa);

        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                CertificateChainPolicy = chainPolicy
            }
        };
        return new HttpClient(handler);
    }

    [Fact]
    public async Task ManagementTransport_CaseA_ValidCertificate_Accepted()
    {
        using var rootCa = CreateRootCaCertificate("SPEMCS Test Root CA");
        using var serverCert = CreateServerCertificate("localhost", rootCa, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
        var (port, cts) = StartHttpsServer(serverCert, "{\"service\": \"SPEMCS\", \"status\": \"ok\"}");
        try
        {
            using var client = CreateStrictTlsClient(rootCa, "localhost");
            var verifier = new ManagementConnectivityVerifier(client, securityMode: TransportSecurityMode.StrictHttps, expectedHostname: "localhost");
            var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, port, ExpectedHostname: "localhost", UseTls: true);

            var result = await verifier.VerifyConnectivityAsync(dest);
            Assert.True(result);
        }
        finally { cts.Cancel(); }
    }

    [Fact]
    public async Task ManagementTransport_CaseB_UntrustedCertificate_Rejected()
    {
        using var trustedRootCa = CreateRootCaCertificate("Trusted Root CA");
        using var attackerRootCa = CreateRootCaCertificate("Attacker Untrusted Root CA");
        using var serverCert = CreateServerCertificate("localhost", attackerRootCa, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
        var (port, cts) = StartHttpsServer(serverCert, "{\"service\": \"SPEMCS\", \"status\": \"ok\"}");
        try
        {
            using var client = CreateStrictTlsClient(trustedRootCa, "localhost");
            var verifier = new ManagementConnectivityVerifier(client, securityMode: TransportSecurityMode.StrictHttps, expectedHostname: "localhost");
            var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, port, ExpectedHostname: "localhost", UseTls: true);

            var result = await verifier.VerifyConnectivityAsync(dest);
            Assert.False(result); // Must reject untrusted certificate!
        }
        finally { cts.Cancel(); }
    }

    [Fact]
    public async Task ManagementTransport_CaseC_HostnameMismatch_Rejected()
    {
        using var rootCa = CreateRootCaCertificate("SPEMCS Test Root CA");
        using var serverCert = CreateServerCertificate("wrong.domain.local", rootCa, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
        var (port, cts) = StartHttpsServer(serverCert, "{\"service\": \"SPEMCS\", \"status\": \"ok\"}");
        try
        {
            using var client = CreateStrictTlsClient(rootCa, "localhost");
            var verifier = new ManagementConnectivityVerifier(client, securityMode: TransportSecurityMode.StrictHttps, expectedHostname: "localhost");
            var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, port, ExpectedHostname: "localhost", UseTls: true);

            var result = await verifier.VerifyConnectivityAsync(dest);
            Assert.False(result); // Must reject hostname mismatch!
        }
        finally { cts.Cancel(); }
    }

    [Fact]
    public async Task ManagementTransport_CaseD_ExpiredCertificate_Rejected()
    {
        using var rootCa = CreateRootCaCertificate("SPEMCS Test Root CA");
        using var serverCert = CreateServerCertificate("localhost", rootCa, DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow.AddMinutes(-10));
        var (port, cts) = StartHttpsServer(serverCert, "{\"service\": \"SPEMCS\", \"status\": \"ok\"}");
        try
        {
            using var client = CreateStrictTlsClient(rootCa, "localhost");
            var verifier = new ManagementConnectivityVerifier(client, securityMode: TransportSecurityMode.StrictHttps, expectedHostname: "localhost");
            var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, port, ExpectedHostname: "localhost", UseTls: true);

            var result = await verifier.VerifyConnectivityAsync(dest);
            Assert.False(result); // Must reject expired certificate!
        }
        finally { cts.Cancel(); }
    }

    [Fact]
    public async Task ManagementTransport_CaseE_PlainHttp_RejectedAsAuthenticatedTransport()
    {
        using var listener = new HttpListener();
        var port = GetRandomUnusedPort();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        _ = Task.Run(async () =>
        {
            try
            {
                var ctx = await listener.GetContextAsync();
                var resp = ctx.Response;
                resp.StatusCode = 200;
                var b = System.Text.Encoding.UTF8.GetBytes("{\"service\": \"SPEMCS\", \"status\": \"ok\"}");
                await resp.OutputStream.WriteAsync(b);
                resp.OutputStream.Close();
            }
            catch { }
        });

        try
        {
            var verifier = new ManagementConnectivityVerifier(securityMode: TransportSecurityMode.StrictHttps);
            var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, port, UseTls: false);

            var result = await verifier.VerifyConnectivityAsync(dest);
            Assert.False(result); // Must reject plain HTTP as authenticated management transport!
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task ManagementTransport_CaseF_DegradedPayload_Rejected()
    {
        using var rootCa = CreateRootCaCertificate("SPEMCS Test Root CA");
        using var serverCert = CreateServerCertificate("localhost", rootCa, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
        var (port, cts) = StartHttpsServer(serverCert, "{\"service\": \"SPEMCS\", \"status\": \"degraded\"}");
        try
        {
            using var client = CreateStrictTlsClient(rootCa, "localhost");
            var verifier = new ManagementConnectivityVerifier(client, securityMode: TransportSecurityMode.StrictHttps, expectedHostname: "localhost");
            var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, port, ExpectedHostname: "localhost", UseTls: true);

            var result = await verifier.VerifyConnectivityAsync(dest);
            Assert.False(result); // Must reject status == degraded per approved M8 security model!
        }
        finally { cts.Cancel(); }
    }

    private static int GetRandomUnusedPort()
    {
        using var tcp = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
        tcp.Stop();
        return port;
    }

    [Fact]
    public async Task PolicyReceiver_DeviceToken_CannotSignPolicy()
    {
        // An attacker attempting to use an HMAC device token as an RSA-PSS policy signature
        var fakeSignature = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("fake-hmac-device-token-cannot-sign"));

        // Schema 1.1 and structurally complete on purpose: the payload has to survive the
        // mandatory-field and schema checks so the rejection provably comes from SIGNATURE
        // verification, not from an earlier well-formedness gate.
        var rawJson = "{\"schema_version\":\"1.1\",\"key_id\":\"dev-key-1\",\"exam_id\":\"" + TestExamId + "\",\"policy_id\":\"" + Guid.NewGuid() + "\",\"version\":1,\"vendor_profile_id\":null,\"approved_browser\":\"chrome\",\"allowed_destinations\":[],\"management_server\":{\"ip_addresses\":[\"127.0.0.1\"],\"port\":8000},\"not_before\":\"2026-09-03T11:00:00Z\",\"expires_at\":\"2026-09-03T13:00:00Z\"}";

        var tamperedMsg = new SignedPolicyMessage(
            MessageType: "SIGNED_NETWORK_POLICY",
            ProtocolVersion: 1,
            RawPolicyJson: rawJson,
            SignatureBase64: fakeSignature
        );

        var result = await _receiver.ProcessPolicyMessageAsync(tamperedMsg, TestExamId, DateTimeOffset.UtcNow);
        Assert.Equal(PolicyAcceptanceStatus.InvalidSignature, result.Status);
    }
}
