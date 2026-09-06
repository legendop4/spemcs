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
    /// <summary>Header carrying the bootstrap enrolment key. Matches the backend's alias exactly.</summary>
    public const string EnrollmentKeyHeader = "X-Enrollment-Key";

    /// <summary>
    /// Enrolment-scoped lab discovery. NOT <c>/api/labs</c>, which is staff-gated and which this
    /// application has no credential for: the wizard needs a lab before it can register, and
    /// registration is what issues the device token, so neither existing credential type can be
    /// present at this point. See <c>routes/agent_api.py::list_enrollment_labs</c>.
    /// </summary>
    public const string EnrollmentLabsPath = "/api/v1/enrollment/labs";

    private readonly HttpClient _http;
    private readonly Func<string?> _enrollmentKeyResolver;
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    /// <param name="httpClient">Transport. A caller-supplied client is used as given.</param>
    /// <param name="enrollmentKeyResolver">
    /// Supplies the bootstrap enrolment key. Injected rather than called statically so a test can
    /// drive the real request-construction path without writing to %ProgramData% or to the
    /// machine's environment - the two places <see cref="EnrollmentKeyProvider"/> reads. Defaults to
    /// that provider, so production behaviour is unchanged.
    /// </param>
    public CentralApiClient(HttpClient? httpClient = null, Func<string?>? enrollmentKeyResolver = null)
    {
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
        _enrollmentKeyResolver = enrollmentKeyResolver ?? (() => EnrollmentKeyProvider.Resolve());
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
        var url = $"{baseUri}{EnrollmentLabsPath}";

        // Resolved here rather than in the constructor so that an operator who sets the key after
        // the wizard is already open does not have to restart it.
        var enrollmentKey = _enrollmentKeyResolver();
        if (string.IsNullOrWhiteSpace(enrollmentKey))
        {
            // Named as a local configuration problem, because that is what it is. Letting this fall
            // through would produce a 401 from the server and a message about the *server* refusing
            // us, sending the operator to look at the backend for a key that is missing here.
            throw new InvalidOperationException(
                "No enrollment key is configured on this workstation, so labs cannot be fetched. " +
                $"Set '{EnrollmentKeyProvider.ConfigPropertyName}' in {EnrollmentKeyProvider.DefaultConfigPath()} " +
                $"or the {EnrollmentKeyProvider.EnvironmentVariableName} environment variable.");
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation(EnrollmentKeyHeader, enrollmentKey);

            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                // Status-specific text, because the three failures have three different fixes and
                // the previous catch-all reported every one of them as a parsing error. The 401 in
                // particular used to surface as "Error parsing labs from Central Server", which
                // points at the wrong machine entirely.
                throw new InvalidOperationException(
                    await DescribeLabFetchFailureAsync(response, cancellationToken).ConfigureAwait(false));
            }

            var labs = await response.Content
                .ReadFromJsonAsync<List<LabDto>>(JsonOptions, cancellationToken)
                .ConfigureAwait(false);
            return labs ?? new List<LabDto>();
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (HttpRequestException ex)
        {
            throw new Exception($"Failed to connect to Central Server at {url}: {ex.Message}", ex);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            // A client-side timeout arrives as TaskCanceledException, and the old catch-all relabelled
            // it "Error parsing labs" - which is how a timeout came to be reported as a JSON problem.
            throw new Exception(
                $"Timed out after {_http.Timeout.TotalSeconds:0.#}s waiting for the Central Server at {url}.", ex);
        }
        catch (Exception ex)
        {
            throw new Exception($"Error parsing labs from Central Server: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Turns a failed lab-fetch response into text naming the machine that has to change.
    /// </summary>
    /// <remarks>
    /// The enrolment key is never echoed. A 401 says the key was refused, never what was sent.
    /// </remarks>
    private static async Task<string> DescribeLabFetchFailureAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var detail = await TryReadDetailAsync(response, cancellationToken).ConfigureAwait(false);

        return (int)response.StatusCode switch
        {
            401 => "The Central Server rejected this workstation's enrollment key. Confirm that "
                   + $"'{EnrollmentKeyProvider.ConfigPropertyName}' in {EnrollmentKeyProvider.DefaultConfigPath()} "
                   + "matches the ENROLLMENT_BOOTSTRAP_KEY configured on the server.",
            503 => "The Central Server has no ENROLLMENT_BOOTSTRAP_KEY configured, so it cannot "
                   + "enroll workstations. This must be fixed on the server.",
            404 => "The Central Server does not provide the enrollment lab list "
                   + $"({EnrollmentLabsPath}). It is probably running an older build than this agent.",
            _ => $"The Central Server returned HTTP {(int)response.StatusCode} "
                 + $"({response.ReasonPhrase}) for the lab list"
                 + (string.IsNullOrWhiteSpace(detail) ? "." : $": {detail}"),
        };
    }

    private static async Task<string?> TryReadDetailAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty("detail", out var detailProp)
                && detailProp.ValueKind == JsonValueKind.String)
            {
                return detailProp.GetString();
            }
        }
        catch (JsonException)
        {
        }
        catch (HttpRequestException)
        {
        }

        return null;
    }

    public async Task<DeviceRegistrationResponse> RegisterDeviceAsync(string serverUrl, DeviceRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var baseUri = NormalizeBaseUrl(serverUrl);
        var url = $"{baseUri}/api/v1/devices/register";

        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = JsonContent.Create(request),
            };

            // Also sent as a header. The backend accepts either position
            // (`req.enrollmentKey or request.headers.get("X-Enrollment-Key")`), and the header is the
            // better one: a body is more likely to be logged verbatim by an intermediary than a
            // header whose name is recognisably a credential. The body field is left populated for
            // compatibility with a server that predates the header form.
            if (!string.IsNullOrWhiteSpace(request.EnrollmentKey))
            {
                message.Headers.TryAddWithoutValidation(EnrollmentKeyHeader, request.EnrollmentKey);
            }

            using var response = await _http.SendAsync(message, cancellationToken).ConfigureAwait(false);

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
