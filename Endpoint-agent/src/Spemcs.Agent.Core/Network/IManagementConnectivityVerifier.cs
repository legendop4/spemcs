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

        _logger.LogInformation(
            "Management verification started. Destination: IPs=[{IPs}], Port={Port}, ExpectedHost='{ExpectedHost}', UseTls={UseTls}. Configured SecurityMode={SecurityMode}, ExpectedHostname='{ExpectedHostname}'",
            string.Join(",", destination.IpAddresses), destination.Port, destination.ExpectedHostname, destination.UseTls, _securityMode, _expectedHostname);

        if (destination.IpAddresses.Count == 0 || destination.Port < 1 || destination.Port > 65535)
        {
            _logger.LogWarning("Management destination invalid: empty IPs or port out of range ({Port}). Verification result: FALSE", destination.Port);
            return false;
        }

        // 1. Strict transport check: in StrictHttps mode, destination must use TLS
        if (_securityMode == TransportSecurityMode.StrictHttps && !destination.UseTls)
        {
            _logger.LogWarning("Management verification rejected: destination specifies plain HTTP (UseTls=false), but production management verification strictly requires HTTPS (SecurityMode={SecurityMode}). Verification result: FALSE", _securityMode);
            return false;
        }

        var scheme = destination.UseTls ? "https" : "http";
        if (_securityMode == TransportSecurityMode.StrictHttps && scheme != "https")
        {
            _logger.LogWarning("Management verification rejected: scheme is not HTTPS in StrictHttps mode. Verification result: FALSE");
            return false;
        }

        _logger.LogInformation("Transport security check passed. Scheme: {Scheme}, Destination IPs count: {Count}", scheme, destination.IpAddresses.Count);

        foreach (var ip in destination.IpAddresses)
        {
            var cleanIp = ip.Contains('/') ? ip.Split('/')[0] : ip;

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(_timeoutMs);

                // Use the explicit destination IP directly (e.g. 127.0.0.1) to avoid IPv6/localhost resolution delay.
                // Do NOT rewrite 127.0.0.1 or any explicit IP to localhost.
                var hostPart = cleanIp.Contains(':') ? $"[{cleanIp}]" : cleanIp;
                var healthUri = new Uri($"{scheme}://{hostPart}:{destination.Port}/api/v1/management/health");

                using var request = new HttpRequestMessage(HttpMethod.Get, healthUri);
                request.Headers.Add("Accept", "application/json");
                if (!string.IsNullOrWhiteSpace(destination.ExpectedHostname) && !string.Equals(destination.ExpectedHostname, cleanIp, StringComparison.OrdinalIgnoreCase))
                {
                    request.Headers.Host = destination.Port is 80 or 443 ? destination.ExpectedHostname : $"{destination.ExpectedHostname}:{destination.Port}";
                }

                _logger.LogInformation("Sending probe request: GET {Uri} (Timeout: {Timeout}ms, HostHeader: '{Host}')",
                    healthUri, _timeoutMs, request.Headers.Host ?? "(default)");

                var sw = System.Diagnostics.Stopwatch.StartNew();
                using var response = await _httpClient.SendAsync(request, cts.Token);
                sw.Stop();

                _logger.LogInformation("Probe response received from {Uri} in {ElapsedMs}ms: StatusCode={StatusCode} ({StatusCodeInt})",
                    healthUri, sw.ElapsedMilliseconds, response.StatusCode, (int)response.StatusCode);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Management probe returned non-success status code {StatusCode} from {Uri}",
                        response.StatusCode, healthUri);
                    continue;
                }

                var json = await response.Content.ReadAsStringAsync(cts.Token);
                _logger.LogInformation("Probe payload received from {Uri}: {Json}", healthUri, json);

                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var isSpemcs = root.TryGetProperty("service", out var svc) && svc.GetString() == "SPEMCS";
                // Strictly require status == "ok" (degraded is rejected per approved M8 security model)
                var isOk = root.TryGetProperty("status", out var st) && st.GetString() == "ok";

                _logger.LogInformation("Payload validation for {Uri}: isSpemcs={IsSpemcs} (service='{Service}'), isOk={IsOk} (status='{Status}')",
                    healthUri, isSpemcs, svc.GetString(), isOk, st.GetString());

                if (isSpemcs && isOk)
                {
                    _logger.LogInformation("Authenticated management health verification succeeded over {Scheme} for {Uri}. Verification result: TRUE", scheme.ToUpperInvariant(), healthUri);
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
                _logger.LogWarning(ex, "Management verification probe failed for {Scheme}://{CleanIp}:{Port} - Exception: {ExceptionType}, Message: {Message}",
                    scheme, cleanIp, destination.Port, ex.GetType().FullName, ex.Message);
            }
        }

        _logger.LogWarning("Management server failed authenticated transport and application health verification across all configured endpoints. Verification result: FALSE");
        return false;
    }
}
