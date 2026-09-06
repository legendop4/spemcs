using System;
using System.IO;
using System.Text.Json;

namespace Spemcs.Agent.UI.Services;

/// <summary>
/// Resolves the bootstrap enrolment key used to authorise device registration.
/// </summary>
/// <remarks>
/// <para>
/// The key is a shared secret: presenting it is what entitles a machine to enrol and thereby to
/// receive the device token that authenticates every subsequent agent call. It therefore must not
/// be compiled into the agent, which is installed on every examination workstation and is readable
/// by anyone who can copy the binary - a candidate included.
/// </para>
/// <para>
/// Resolution order is deployment-shaped rather than developer-shaped: the machine-wide config
/// file an installer writes, then the environment variable an operator can set for a one-off
/// enrolment. There is no fallback beyond those two, on purpose. A missing key produces a 401 from
/// the backend that names the problem; a defaulted key produces a working enrolment against a
/// secret that is public, which is worse and is invisible.
/// </para>
/// </remarks>
public static class EnrollmentKeyProvider
{
    /// <summary>Environment variable consulted when the config file carries no key.</summary>
    public const string EnvironmentVariableName = "SPEMCS_ENROLLMENT_KEY";

    /// <summary>Property name read from the agent's machine-wide config.json.</summary>
    public const string ConfigPropertyName = "enrollmentKey";

    /// <summary>
    /// Returns the configured enrolment key, or <see langword="null"/> when none is configured.
    /// </summary>
    /// <param name="configPath">
    /// Optional explicit path to config.json. When null the standard machine-wide location under
    /// %ProgramData%\Spemcs\Endpoint Agent is used.
    /// </param>
    public static string? Resolve(string? configPath = null)
    {
        var fromFile = ReadFromConfig(configPath ?? DefaultConfigPath());
        if (!string.IsNullOrWhiteSpace(fromFile))
        {
            return fromFile;
        }

        var fromEnvironment = Environment.GetEnvironmentVariable(EnvironmentVariableName);
        return string.IsNullOrWhiteSpace(fromEnvironment) ? null : fromEnvironment;
    }

    /// <summary>The machine-wide config.json path the service also reads.</summary>
    public static string DefaultConfigPath() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Spemcs", "Endpoint Agent", "config.json");

    private static string? ReadFromConfig(string path)
    {
        // A malformed or unreadable config file yields null rather than throwing: an enrolment
        // that fails with "no key configured" is a diagnosable state, whereas a crashed setup
        // wizard is not. The 401 that follows says the same thing more precisely.
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.TryGetProperty(ConfigPropertyName, out var property)
                && property.ValueKind == JsonValueKind.String)
            {
                var value = property.GetString();
                return string.IsNullOrWhiteSpace(value) ? null : value;
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (JsonException)
        {
        }

        return null;
    }
}
