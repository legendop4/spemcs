using Microsoft.Extensions.Logging;

namespace Spemcs.Agent.Service;

/// <summary>
/// Resolves the backend API URL from the available configuration sources in strict priority order.
/// </summary>
/// <remarks>
/// <para>
/// The configuration precedence is:
/// <list type="number">
///   <item><description><c>config.json</c> <c>"serverUrl"</c> — written by the enrollment wizard.
///     This is the AUTHORITATIVE source after a successful enrollment and is never overridden by
///     a lower-priority source, regardless of its port number or hostname.</description></item>
///   <item><description>Environment variable <c>SPEMCS_BACKEND_URL</c> — for managed/scripted
///     deployment where a fleet tool pushes a URL before the service starts.</description></item>
///   <item><description><c>appsettings.json</c> <c>"BackendApiUrl"</c> — development-time
///     convenience, read through <c>IConfiguration</c>.</description></item>
///   <item><description>Compiled default <c>http://127.0.0.1:8000/</c> — absolute last resort.
///     </description></item>
/// </list>
/// </para>
/// <para>
/// The previous implementation contained a <c>backendUrl.Contains(":8000")</c> check that silently
/// demoted any enrolled URL on port 8000 to the <c>appsettings.json</c> fallback. That was a
/// development guard that matched production URLs and broke every deployment whose backend
/// happened to listen on port 8000.
/// </para>
/// <para>
/// <b>Credential safety</b>: the <see cref="ResolvedUrl"/> and <see cref="Source"/> properties
/// are safe to log. The resolver never reads, stores, or returns enrollment keys, device tokens,
/// JWTs, HMAC secrets, or any other credential material.
/// </para>
/// </remarks>
public sealed class ServiceConfigResolver
{
    /// <summary>Fallback when every other source is empty.</summary>
    public const string CompiledDefault = "http://127.0.0.1:8000/";

    /// <summary>The resolved backend API URL, always with a trailing slash.</summary>
    public string ResolvedUrl { get; }

    /// <summary>Human-readable provenance label safe to log (never contains credentials).</summary>
    public string Source { get; }

    private ServiceConfigResolver(string url, string source)
    {
        ResolvedUrl = NormalizeUrl(url);
        Source = source;
    }

    /// <summary>
    /// Resolves the backend URL from the available sources in priority order.
    /// </summary>
    /// <param name="configJsonServerUrl">
    ///   The <c>"serverUrl"</c> value read from <c>config.json</c>, or null/empty if absent.
    /// </param>
    /// <param name="environmentUrl">
    ///   The value of the <c>SPEMCS_BACKEND_URL</c> environment variable, or null if unset.
    /// </param>
    /// <param name="appsettingsUrl">
    ///   The <c>"BackendApiUrl"</c> value from <c>appsettings.json</c> via <c>IConfiguration</c>,
    ///   or null if absent.
    /// </param>
    /// <returns>A <see cref="ServiceConfigResolver"/> whose properties are safe to log.</returns>
    public static ServiceConfigResolver Resolve(
        string? configJsonServerUrl,
        string? environmentUrl,
        string? appsettingsUrl)
    {
        // 1. config.json — enrollment authority. Never overridden.
        if (!string.IsNullOrWhiteSpace(configJsonServerUrl))
            return new ServiceConfigResolver(configJsonServerUrl, "config.json");

        // 2. Environment variable — managed deployment.
        if (!string.IsNullOrWhiteSpace(environmentUrl))
            return new ServiceConfigResolver(environmentUrl, "environment variable SPEMCS_BACKEND_URL");

        // 3. appsettings.json — development convenience.
        if (!string.IsNullOrWhiteSpace(appsettingsUrl))
            return new ServiceConfigResolver(appsettingsUrl, "appsettings.json");

        // 4. Compiled default — absolute last resort.
        return new ServiceConfigResolver(CompiledDefault, "compiled default");
    }

    /// <summary>
    /// Ensures the URL ends with exactly one <c>/</c>.
    /// </summary>
    public static string NormalizeUrl(string url)
    {
        var trimmed = (url ?? "").Trim().TrimEnd('/');
        return string.IsNullOrEmpty(trimmed)
            ? CompiledDefault
            : trimmed + "/";
    }

    /// <summary>
    /// Logs the resolved configuration at Information level. Only the URL and its provenance
    /// source are logged — never any credential material.
    /// </summary>
    public void LogResolution(ILogger logger)
    {
        logger.LogInformation(
            "Resolved backend URL: {BackendUrl} (source: {Source})",
            ResolvedUrl, Source);
    }
}
