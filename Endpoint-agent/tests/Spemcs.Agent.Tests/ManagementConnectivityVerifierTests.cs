using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
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

    [Fact]
    public async Task LiveBackend_VerifyConnectivityAsync_Succeeds()
    {
        using var client = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:8002/") };
        var verifier = new ManagementConnectivityVerifier(
            httpClient: client,
            securityMode: TransportSecurityMode.AllowInsecureHttpForTesting,
            expectedHostname: "127.0.0.1"
        );

        var dest = new ManagementDestination(new List<string> { "127.0.0.1" }, 8002, UseTls: false);
        var result = await verifier.VerifyConnectivityAsync(dest);

        Assert.True(result);
    }
}
