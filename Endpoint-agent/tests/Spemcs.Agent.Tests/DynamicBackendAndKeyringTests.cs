using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Spemcs.Agent.Core.Network;
using Spemcs.Agent.Service;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class DynamicBackendAndKeyringTests : IDisposable
{
    private readonly string _testDir;
    private readonly string _configPath;
    private readonly string? _originalBackendUrl;

    public DynamicBackendAndKeyringTests()
    {
        _originalBackendUrl = Environment.GetEnvironmentVariable("SPEMCS_BACKEND_URL");
        Environment.SetEnvironmentVariable("SPEMCS_BACKEND_URL", null);
        _testDir = Path.Combine(Path.GetTempPath(), "spemcs_dynamic_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
        _configPath = Path.Combine(_testDir, "config.json");
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("SPEMCS_BACKEND_URL", _originalBackendUrl);
        try
        {
            if (Directory.Exists(_testDir))
            {
                Directory.Delete(_testDir, true);
            }
        }
        catch { }
    }

    private sealed class InspectingHandler : DelegatingHandler
    {
        public HttpRequestMessage? LastRequest { get; private set; }
        public HttpResponseMessage ResponseToReturn { get; set; } = new(HttpStatusCode.OK);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(ResponseToReturn);
        }
    }

    [Fact]
    public async Task DynamicBackendAddressHandler_RewritesStartupLocalhost_ToEnrolledServerUrl()
    {
        // 1. Initial state: service starts with fallback URL
        var initialUrl = "http://127.0.0.1:8000/";
        var inspectingHandler = new InspectingHandler();
        var dynamicHandler = new DynamicBackendAddressHandler(_configPath, initialUrl)
        {
            InnerHandler = inspectingHandler
        };

        using var client = new HttpClient(dynamicHandler)
        {
            BaseAddress = new Uri(initialUrl)
        };

        // Before enrollment: request goes to initialUrl
        var resp1 = await client.GetAsync("api/policies/signing-key/public");
        Assert.Equal(HttpStatusCode.OK, resp1.StatusCode);
        Assert.Equal("127.0.0.1", inspectingHandler.LastRequest?.RequestUri?.Host);
        Assert.Equal(8000, inspectingHandler.LastRequest?.RequestUri?.Port);

        // 2. SetupWizard enrolls workstation and writes config.json
        var enrolledServerUrl = "http://192.168.11.200:8000";
        var configDoc = new
        {
            registered = true,
            serverUrl = enrolledServerUrl,
            hardwareUuid = "NetworkLab-PC2557",
            deviceName = "NetworkLab-PC2557",
            deviceToken = "test-token"
        };
        File.WriteAllText(_configPath, JsonSerializer.Serialize(configDoc));

        // 3. Next request automatically routes to enrolledServerUrl without restarting service
        var resp2 = await client.GetAsync("api/policies/signing-key/public?test=1");
        Assert.Equal(HttpStatusCode.OK, resp2.StatusCode);
        Assert.NotNull(inspectingHandler.LastRequest?.RequestUri);
        Assert.Equal("192.168.11.200", inspectingHandler.LastRequest!.RequestUri!.Host);
        Assert.Equal(8000, inspectingHandler.LastRequest.RequestUri.Port);
        Assert.Equal("/api/policies/signing-key/public", inspectingHandler.LastRequest.RequestUri.AbsolutePath);
        Assert.Equal("?test=1", inspectingHandler.LastRequest.RequestUri.Query);

        // Verify BaseAddress of client was NOT mutated globally
        Assert.Equal(new Uri(initialUrl), client.BaseAddress);
    }

    [Fact]
    public async Task DynamicBackendAddressHandler_DoesNotTouchUnrelatedExternalUrls()
    {
        var inspectingHandler = new InspectingHandler();
        var dynamicHandler = new DynamicBackendAddressHandler(_configPath, "http://127.0.0.1:8000/")
        {
            InnerHandler = inspectingHandler
        };
        using var client = new HttpClient(dynamicHandler);

        var externalUri = new Uri("https://example.com/api/test");
        var resp = await client.GetAsync(externalUri);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("example.com", inspectingHandler.LastRequest?.RequestUri?.Host);
        Assert.Equal("https", inspectingHandler.LastRequest?.RequestUri?.Scheme);
    }

    [Fact]
    public void ServiceConfigResolver_ResolveCurrentServerUrl_DetectsConfigCreationDynamically()
    {
        // Before config.json exists
        var urlBefore = ServiceConfigResolver.ResolveCurrentServerUrl(_configPath);
        Assert.Equal(ServiceConfigResolver.CompiledDefault, urlBefore);

        // Write config.json
        var enrolledUrl = "http://10.0.0.50:9000";
        File.WriteAllText(_configPath, JsonSerializer.Serialize(new { serverUrl = enrolledUrl, registered = true }));

        var urlAfter = ServiceConfigResolver.ResolveCurrentServerUrl(_configPath);
        Assert.Equal("http://10.0.0.50:9000/", urlAfter);
    }

    private sealed class SimpleHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpMessageHandler _handler;
        public SimpleHttpClientFactory(HttpMessageHandler handler) => _handler = handler;
        public HttpClient CreateClient(string name) => new HttpClient(_handler, disposeHandler: false);
    }

    [Fact]
    public async Task KeyringSyncService_EnsureKeyStoreInitializedAsync_WithServerUrl_PopulatesKeystore()
    {
        var keyStore = new TrustedKeyStore();
        var journal = new SqliteRollbackJournal(Path.Combine(_testDir, "journal1.db"));

        var keyringResponse = new
        {
            active_key_id = PythonInteropFixtures.KeyId,
            keys = new[]
            {
                new
                {
                    key_id = PythonInteropFixtures.KeyId,
                    public_key_pem = PythonInteropFixtures.PublicKeyPem,
                    state = "active"
                }
            },
            revoked_key_ids = Array.Empty<string>(),
            ephemeral = false
        };

        var inspectingHandler = new InspectingHandler
        {
            ResponseToReturn = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(keyringResponse), System.Text.Encoding.UTF8, "application/json")
            }
        };

        var factory = new SimpleHttpClientFactory(inspectingHandler);
        var syncService = new KeyringSyncService(keyStore, journal, factory, NullLogger<KeyringSyncService>.Instance);

        var result = await syncService.EnsureKeyStoreInitializedAsync("http://192.168.11.200:8000");

        Assert.True(result);
        Assert.True(syncService.HasKeys);
        Assert.NotNull(keyStore.GetPublicKey(PythonInteropFixtures.KeyId));
        Assert.Equal("192.168.11.200", inspectingHandler.LastRequest?.RequestUri?.Host);
        Assert.Equal("/api/policies/signing-key/keyring", inspectingHandler.LastRequest?.RequestUri?.AbsolutePath);
    }

    [Fact]
    public async Task KeyringSyncService_TryLoadActiveKeyOnlyAsync_QueriesCanonicalPublicEndpoint()
    {
        var keyStore = new TrustedKeyStore();
        var journal = new SqliteRollbackJournal(Path.Combine(_testDir, "journal2.db"));

        var activeKeyResponse = new
        {
            key_id = PythonInteropFixtures.KeyId,
            public_key_pem = PythonInteropFixtures.PublicKeyPem,
            state = "active"
        };

        var customHandler = new CallbackHandler(req =>
        {
            if (req.RequestUri!.AbsolutePath.EndsWith("/keyring"))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
            if (req.RequestUri!.AbsolutePath.EndsWith("/public"))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(activeKeyResponse), System.Text.Encoding.UTF8, "application/json")
                };
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var factory = new SimpleHttpClientFactory(customHandler);
        var syncService = new KeyringSyncService(keyStore, journal, factory, NullLogger<KeyringSyncService>.Instance);

        var result = await syncService.ForceRefreshAsync("http://192.168.11.200:8000");

        Assert.True(result);
        Assert.True(syncService.HasKeys);
        Assert.NotNull(keyStore.GetPublicKey(PythonInteropFixtures.KeyId));
    }

    private sealed class CallbackHandler : DelegatingHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _callback;
        public CallbackHandler(Func<HttpRequestMessage, HttpResponseMessage> callback) => _callback = callback;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_callback(request));
    }
}
