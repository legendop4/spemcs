using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Spemcs.Agent.UI.Models;

namespace Spemcs.Agent.UI.Services;

public interface ICentralApiClient
{
    Task<bool> CheckHealthAsync(string serverUrl, CancellationToken cancellationToken = default);
    Task<List<LabDto>> FetchLabsAsync(string serverUrl, CancellationToken cancellationToken = default);
    Task<DeviceRegistrationResponse> RegisterDeviceAsync(string serverUrl, DeviceRegistrationRequest request, CancellationToken cancellationToken = default);
}

public class CentralApiClient : ICentralApiClient
{
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public CentralApiClient(HttpClient? httpClient = null)
    {
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
    }

    private static string NormalizeBaseUrl(string serverUrl)
    {
        var url = (serverUrl ?? string.Empty).Trim();
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            url = "http://" + url;
        }
        return url.TrimEnd('/');
    }

    public async Task<bool> CheckHealthAsync(string serverUrl, CancellationToken cancellationToken = default)
    {
        try
        {
            var baseUri = NormalizeBaseUrl(serverUrl);
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{baseUri}/health");
            using var res = await _http.SendAsync(req, cancellationToken);
            return res.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public async Task<List<LabDto>> FetchLabsAsync(string serverUrl, CancellationToken cancellationToken = default)
    {
        var baseUri = NormalizeBaseUrl(serverUrl);
        var url = $"{baseUri}/api/labs";
        
        try
        {
            var labs = await _http.GetFromJsonAsync<List<LabDto>>(url, JsonOptions, cancellationToken);
            return labs ?? new List<LabDto>();
        }
        catch (HttpRequestException ex)
        {
            throw new Exception($"Failed to connect to Central Server at {url}: {ex.Message}", ex);
        }
        catch (Exception ex)
        {
            throw new Exception($"Error parsing labs from Central Server: {ex.Message}", ex);
        }
    }

    public async Task<DeviceRegistrationResponse> RegisterDeviceAsync(string serverUrl, DeviceRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var baseUri = NormalizeBaseUrl(serverUrl);
        var url = $"{baseUri}/api/v1/devices/register";

        try
        {
            var response = await _http.PostAsJsonAsync(url, request, cancellationToken);
            
            if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
            {
                var conflictDetail = "This workstation or PC Number is already registered in the selected lab.";
                try
                {
                    var errorObj = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                    if (errorObj.TryGetProperty("detail", out var detailProp))
                    {
                        conflictDetail = detailProp.GetString() ?? conflictDetail;
                    }
                }
                catch { }

                throw new InvalidOperationException($"Registration Conflict: {conflictDetail}");
            }

            if (!response.IsSuccessStatusCode)
            {
                var errorMsg = $"Server returned HTTP {(int)response.StatusCode} ({response.ReasonPhrase})";
                try
                {
                    var errorObj = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                    if (errorObj.TryGetProperty("detail", out var detailProp))
                    {
                        errorMsg = detailProp.GetString() ?? errorMsg;
                    }
                }
                catch { }

                throw new Exception($"Registration failed: {errorMsg}");
            }

            var result = await response.Content.ReadFromJsonAsync<DeviceRegistrationResponse>(JsonOptions, cancellationToken);
            return result ?? new DeviceRegistrationResponse { DeviceName = request.DeviceName, Registered = true };
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (HttpRequestException ex)
        {
            throw new Exception($"Unable to reach Central Server at {url}. Please check IP/URL and network connectivity.", ex);
        }
        catch (Exception ex)
        {
            throw new Exception($"Registration error: {ex.Message}", ex);
        }
    }
}
