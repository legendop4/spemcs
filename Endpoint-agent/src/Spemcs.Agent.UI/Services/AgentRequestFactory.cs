using System;
using System.Net.Http;
using System.Net.Http.Json;

namespace Spemcs.Agent.UI.Services;

/// <summary>
/// Builds agent-authenticated HTTP requests for the interactive UI process.
/// </summary>
/// <remarks>
/// <para>
/// The UI runs in the desktop session, in a different process from the Windows service, so it cannot
/// share the service's <c>DeviceCredentialStore</c> singleton or its <c>AgentHttp</c> helper. It
/// reads the same device token out of the same shared config.json instead.
/// </para>
/// <para>
/// This type exists because the token was previously not sent AT ALL from this process:
/// <c>api/v1/events</c> and <c>api/v1/sessions/start</c> were posted through a bare
/// <see cref="HttpClient"/> with no default headers, so every violation this agent observed was
/// refused with 401 and the failure was swallowed by a <c>catch { }</c>. The visible symptom was an
/// empty alerts dashboard during a live exam, which reads as "nothing happened" rather than as
/// "nothing was delivered".
/// </para>
/// <para>
/// The header name is duplicated from the service's <c>AgentHttp.DeviceTokenHeader</c> rather than
/// shared, because <c>Spemcs.Agent.Service</c> declares it <c>internal</c> and the UI does not
/// reference that project. <see cref="DeviceTokenHeader"/> and the backend's
/// <c>X-Device-Token</c> alias in <c>dependencies.py::require_device</c> must stay in step; a
/// regression test pins the literal.
/// </para>
/// </remarks>
public static class AgentRequestFactory
{
    /// <summary>Header the backend reads a device enrolment token from.</summary>
    public const string DeviceTokenHeader = "X-Device-Token";

    /// <summary>
    /// Builds a JSON POST carrying the device token when one is available.
    /// </summary>
    /// <remarks>
    /// A blank token adds no header, which produces a 401 the caller can report, rather than an
    /// empty header value the backend would have to interpret. Either way the request is refused;
    /// the difference is that "absent" is diagnosable and "present but empty" looks like corruption.
    /// </remarks>
    public static HttpRequestMessage CreateJsonPost<T>(string requestUri, T body, string? deviceToken)
    {
        var message = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = JsonContent.Create(body),
        };

        if (!string.IsNullOrWhiteSpace(deviceToken))
        {
            message.Headers.TryAddWithoutValidation(DeviceTokenHeader, deviceToken);
        }

        return message;
    }

    /// <summary>
    /// Describes an agent POST outcome for the local log, with no credential material in it.
    /// </summary>
    /// <remarks>
    /// Reports only whether a token was attached - never the token, its length, or any prefix of it.
    /// "Token present" plus an HTTP status is enough to separate every hypothesis that matters
    /// (nothing sent, sent and refused, sent and accepted) without putting a 30-day credential into
    /// a plaintext file on a machine a candidate physically controls.
    /// </remarks>
    public static string DescribeOutcome(string requestUri, bool tokenAttached, int statusCode)
    {
        var credential = tokenAttached ? "device token attached" : "NO device token available";
        return $"POST {requestUri} -> HTTP {statusCode} ({credential})";
    }
}
