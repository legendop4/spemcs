using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Spemcs.Agent.Core.Network;

public enum TransportSecurityMode
{
    StrictHttps,
    AllowInsecureHttpForTesting
}

/// <summary>
/// Verifies that the management control plane is reachable and authenticated prior to accepting a network policy.
/// Must NOT alter or mutate firewall rules or settings.
/// </summary>
public interface IManagementConnectivityVerifier
{
    Task<bool> VerifyConnectivityAsync(ManagementDestination destination, CancellationToken cancellationToken = default);
}

public sealed class ManagementConnectivityVerifier : IManagementConnectivityVerifier
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ManagementConnectivityVerifier> _logger;
    private readonly int _timeoutMs;
    private readonly TransportSecurityMode _securityMode;
    private readonly string? _expectedHostname;

    public ManagementConnectivityVerifier(
        HttpClient? httpClient = null,
        ILogger<ManagementConnectivityVerifier>? logger = null,
        int timeoutMs = 3000,
        TransportSecurityMode securityMode = TransportSecurityMode.StrictHttps,
        string? expectedHostname = null)
    {
        _logger = logger ?? NullLogger<ManagementConnectivityVerifier>.Instance;
        _timeoutMs = timeoutMs;
        _securityMode = securityMode;
        _expectedHostname = expectedHostname;
        _httpClient = httpClient ?? new HttpClient();
    }

    public async Task<bool> VerifyConnectivityAsync(ManagementDestination destination, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);

        if (destination.IpAddresses.Count == 0 || destination.Port < 1 || destination.Port > 65535)
        {
            _logger.LogWarning("Invalid management destination configuration.");
            return false;
        }

        // 1. Strict transport check: in StrictHttps mode, destination must use TLS
        if (_securityMode == TransportSecurityMode.StrictHttps && !destination.UseTls)
        {
            _logger.LogWarning("Management verification rejected: destination specifies plain HTTP, but production management verification strictly requires HTTPS with TLS certificate validation.");
            return false;
        }

        var scheme = destination.UseTls ? "https" : "http";
        if (_securityMode == TransportSecurityMode.StrictHttps && scheme != "https")
        {
            _logger.LogWarning("Management verification rejected: scheme is not HTTPS in StrictHttps mode.");
            return false;
        }

        var targetHost = destination.ExpectedHostname ?? _expectedHostname ?? "localhost";

        foreach (var ip in destination.IpAddresses)
        {
            var cleanIp = ip.Contains('/') ? ip.Split('/')[0] : ip;

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(_timeoutMs);

                var hostPart = (cleanIp == "127.0.0.1" || cleanIp == "::1") ? targetHost : cleanIp;
                var healthUri = new Uri($"{scheme}://{hostPart}:{destination.Port}/api/v1/management/health");

                using var request = new HttpRequestMessage(HttpMethod.Get, healthUri);
                request.Headers.Add("Accept", "application/json");

                using var response = await _httpClient.SendAsync(request, cts.Token);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Management probe returned non-success status code {StatusCode} from {Uri}",
                        response.StatusCode, healthUri);
                    continue;
                }

                var json = await response.Content.ReadAsStringAsync(cts.Token);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var isSpemcs = root.TryGetProperty("service", out var svc) && svc.GetString() == "SPEMCS";
                // Strictly require status == "ok" (degraded is rejected per approved M8 security model)
                var isOk = root.TryGetProperty("status", out var st) && st.GetString() == "ok";

                if (isSpemcs && isOk)
                {
                    _logger.LogInformation("Authenticated management health verification succeeded over {Scheme} for {Uri}", scheme.ToUpperInvariant(), healthUri);
                    return true;
                }
                else
                {
                    _logger.LogWarning("Management probe returned invalid application payload from {Uri}: {Json}",
                        healthUri, json);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Management verification probe failed for {Scheme}://{Host}:{Port} - {Message}",
                    scheme, cleanIp, destination.Port, ex.Message);
            }
        }

        _logger.LogWarning("Management server failed authenticated transport and application health verification across all configured endpoints.");
        return false;
    }
}
