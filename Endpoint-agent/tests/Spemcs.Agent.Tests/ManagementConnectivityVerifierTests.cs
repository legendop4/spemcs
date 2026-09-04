using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class ManagementConnectivityVerifierTests
{
    private sealed class InspectingHandler : HttpMessageHandler
    {
        public Uri? LastRequestUri { get; private set; }
        public string? LastHostHeader { get; private set; }
        public Func<HttpRequestMessage, HttpResponseMessage>? ResponseFactory { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequestUri = request.RequestUri;
            LastHostHeader = request.Headers.Host;

            if (ResponseFactory != null)
            {
                return Task.FromResult(ResponseFactory(request));
            }

            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"service\":\"SPEMCS\",\"status\":\"ok\",\"version\":\"1.0\"}", Encoding.UTF8, "application/json")
            };
            return Task.FromResult(resp);
        }
    }

    [Fact]
    public async Task Destination127001_IsNotRewrittenToLocalhost()
    {
        var handler = new InspectingHandler();
        using var client = new HttpClient(handler);
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.AllowInsecureHttpForTesting,
            expectedHostname: "localhost" // Even if expectedHostname is localhost
        );

        var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, 8002, UseTls: false);
        var result = await verifier.VerifyConnectivityAsync(dest);

        Assert.True(result);
        Assert.NotNull(handler.LastRequestUri);
        Assert.Equal("http://127.0.0.1:8002/api/v1/management/health", handler.LastRequestUri.ToString());
        Assert.DoesNotContain("localhost", handler.LastRequestUri.Host, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AllowInsecureHttpForTesting_AcceptsHttpDestination()
    {
        var handler = new InspectingHandler();
        using var client = new HttpClient(handler);
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.AllowInsecureHttpForTesting
        );

        var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, 8002, UseTls: false);
        var result = await verifier.VerifyConnectivityAsync(dest);

        Assert.True(result);
    }

    [Fact]
    public async Task StrictHttps_RejectsHttpDestination_WithoutSendingRequest()
    {
        var handler = new InspectingHandler();
        using var client = new HttpClient(handler);
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.StrictHttps
        );

        var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, 8002, UseTls: false);
        var result = await verifier.VerifyConnectivityAsync(dest);

        Assert.False(result);
        Assert.Null(handler.LastRequestUri); // No network probe sent
    }

    [Fact]
    public async Task StrictHttps_AllowsHttpsDestination()
    {
        var handler = new InspectingHandler();
        using var client = new HttpClient(handler);
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.StrictHttps
        );

        var dest = new ManagementDestination(new List<string> { "10.0.0.5" }, 443, ExpectedHostname: "mgmt.example.com", UseTls: true);
        var result = await verifier.VerifyConnectivityAsync(dest);

        Assert.True(result);
        Assert.NotNull(handler.LastRequestUri);
        Assert.Equal("https://10.0.0.5/api/v1/management/health", handler.LastRequestUri.ToString());
        Assert.Equal("mgmt.example.com", handler.LastHostHeader);
    }

    [Fact]
    public async Task ValidPayload_ServiceSpemcsStatusOk_Accepted()
    {
        var handler = new InspectingHandler
        {
            ResponseFactory = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"service\":\"SPEMCS\",\"status\":\"ok\",\"database\":\"connected\"}", Encoding.UTF8, "application/json")
            }
        };
        using var client = new HttpClient(handler);
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.AllowInsecureHttpForTesting
        );

        var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, 8002, UseTls: false);
        var result = await verifier.VerifyConnectivityAsync(dest);

        Assert.True(result);
    }

    [Theory]
    [InlineData("{\"service\":\"OTHER\",\"status\":\"ok\"}")]
    [InlineData("{\"service\":\"SPEMCS\",\"status\":\"degraded\"}")]
    [InlineData("{\"service\":\"SPEMCS\",\"status\":\"error\"}")]
    [InlineData("{}")]
    public async Task InvalidPayload_Rejected(string responseBody)
    {
        var handler = new InspectingHandler
        {
            ResponseFactory = _ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/json")
            }
        };
        using var client = new HttpClient(handler);
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.AllowInsecureHttpForTesting
        );

        var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, 8002, UseTls: false);
        var result = await verifier.VerifyConnectivityAsync(dest);

        Assert.False(result);
    }

    [Fact]
    public async Task UnreachableEndpoint_ReturnsFalse()
    {
        var handler = new InspectingHandler
        {
            ResponseFactory = _ => throw new HttpRequestException("Connection refused")
        };
        using var client = new HttpClient(handler);
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.AllowInsecureHttpForTesting
        );

        var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, 8002, UseTls: false);
        var result = await verifier.VerifyConnectivityAsync(dest);

        Assert.False(result);
    }

    /// <summary>
    /// Whether anything is actually listening on the dev/lab management server endpoint.
    /// <para>
    /// This exists to CLASSIFY <see cref="LiveBackend_VerifyConnectivityAsync_Succeeds"/> at run time,
    /// not to skip it. The suite has no <c>Skip=</c> convention and no skippable-fact package, so the
    /// established idiom is a runtime branch inside the <c>[Fact]</c> that still asserts something
    /// real on each side - the same shape as
    /// <c>WindowsTrafficEnforcementIntegrationTests.ControlledTrafficEnforcement_Verification</c>,
    /// which branches on elevation.
    /// </para>
    /// </summary>
    private static async Task<bool> IsBackendListeningAsync(string host, int port, int timeoutMs = 750)
    {
        try
        {
            using var probe = new TcpClient();
            using var cts = new CancellationTokenSource(timeoutMs);
            await probe.ConnectAsync(IPAddress.Parse(host), port, cts.Token);
            return probe.Connected;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>
    /// Environment-dependent by design: the only test in this class that talks to a real backend.
    /// The success path requires uvicorn serving <c>GET /api/v1/management/health</c> on
    /// <c>http://127.0.0.1:8002</c> and returning <c>service == "SPEMCS"</c> and
    /// <c>status == "ok"</c> - <c>degraded</c> is refused by the M8 security model. No credentials
    /// are involved.
    /// <para>
    /// Rather than pass vacuously when the backend is absent, the two branches assert the two halves
    /// of one contract: with a backend reachable, verification must SUCCEED; with nothing listening,
    /// it must FAIL CLOSED rather than assume reachability. Both branches assert, so this test cannot
    /// go green for the wrong reason, and a regression that made the verifier optimistic would be
    /// caught even on a machine with no backend running.
    /// </para>
    /// </summary>
    [Fact]
    public async Task LiveBackend_VerifyConnectivityAsync_Succeeds()
    {
        const string host = "127.0.0.1";
        const int port = 8002;

        var backendIsListening = await IsBackendListeningAsync(host, port);

        using var client = new HttpClient { BaseAddress = new Uri($"http://{host}:{port}/") };
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.AllowInsecureHttpForTesting,
            expectedHostname: host
        );

        var dest = new ManagementDestination(new List<string> { host }, port, UseTls: false);
        var result = await verifier.VerifyConnectivityAsync(dest);

        if (backendIsListening)
        {
            Assert.True(result,
                $"A management backend is listening on {host}:{port}, so connectivity verification " +
                "must succeed. GET /api/v1/management/health has to return service == \"SPEMCS\" " +
                "and status == \"ok\" exactly.");
        }
        else
        {
            Assert.False(result,
                $"Nothing is listening on {host}:{port}, so connectivity verification must fail " +
                "closed. Start the backend (uvicorn on port 8002) to exercise this test's success " +
                "path.");
        }
    }
}
