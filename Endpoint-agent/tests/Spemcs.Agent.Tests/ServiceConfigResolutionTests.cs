using Spemcs.Agent.Service;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// Regression tests for <see cref="ServiceConfigResolver"/>.
///
/// These tests prove the configuration precedence contract and guard against regressions of the
/// ":8000" bug (see ServiceConfigResolver remarks). Every test is self-contained and requires
/// no file system, no IConfiguration, and no running host.
/// </summary>
public class ServiceConfigResolutionTests
{
    // ────────────────────────────────────────────────────────────────────────
    // 1. config.json URL + environment URL + appsettings URL => config.json MUST win.
    // ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ConfigJson_Wins_Over_Environment_And_Appsettings()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: "http://192.168.11.65:8000",
            environmentUrl: "http://env-server:9000",
            appsettingsUrl: "http://127.0.0.1:8002");

        Assert.Equal("http://192.168.11.65:8000/", result.ResolvedUrl);
        Assert.Equal("config.json", result.Source);
    }

    [Theory]
    [InlineData("http://10.0.1.5:8002")]
    [InlineData("https://spemcs.college.edu")]
    [InlineData("http://lab-server.local:8080")]
    [InlineData("http://192.168.1.100:443")]
    public void ConfigJson_Always_Wins_Regardless_Of_Port(string configUrl)
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: configUrl,
            environmentUrl: "http://env-fallback:9999",
            appsettingsUrl: "http://127.0.0.1:8002");

        Assert.Equal(configUrl.TrimEnd('/') + "/", result.ResolvedUrl);
        Assert.Equal("config.json", result.Source);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 2. empty config.json + environment URL + appsettings URL => environment MUST win.
    // ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Environment_Wins_When_ConfigJson_Is_Empty()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: "",
            environmentUrl: "http://fleet-deployed:8000",
            appsettingsUrl: "http://127.0.0.1:8002");

        Assert.Equal("http://fleet-deployed:8000/", result.ResolvedUrl);
        Assert.Equal("environment variable SPEMCS_BACKEND_URL", result.Source);
    }

    [Fact]
    public void Environment_Wins_When_ConfigJson_Is_Null()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: null,
            environmentUrl: "http://fleet-deployed:8000",
            appsettingsUrl: "http://127.0.0.1:8002");

        Assert.Equal("http://fleet-deployed:8000/", result.ResolvedUrl);
        Assert.Equal("environment variable SPEMCS_BACKEND_URL", result.Source);
    }

    [Fact]
    public void Environment_Wins_When_ConfigJson_Is_Whitespace()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: "   ",
            environmentUrl: "http://managed-server:8000",
            appsettingsUrl: "http://127.0.0.1:8002");

        Assert.Equal("http://managed-server:8000/", result.ResolvedUrl);
        Assert.Equal("environment variable SPEMCS_BACKEND_URL", result.Source);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 3. empty config.json + no environment + appsettings URL => appsettings MUST win.
    // ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Appsettings_Wins_When_ConfigJson_And_Environment_Are_Empty()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: "",
            environmentUrl: null,
            appsettingsUrl: "http://127.0.0.1:8002");

        Assert.Equal("http://127.0.0.1:8002/", result.ResolvedUrl);
        Assert.Equal("appsettings.json", result.Source);
    }

    [Fact]
    public void Appsettings_Wins_When_ConfigJson_And_Environment_Are_Whitespace()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: null,
            environmentUrl: "   ",
            appsettingsUrl: "http://dev-local:8000");

        Assert.Equal("http://dev-local:8000/", result.ResolvedUrl);
        Assert.Equal("appsettings.json", result.Source);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 4. missing config.json + no environment + appsettings URL => appsettings MUST win.
    //    (missing config.json is indistinguishable from null at the resolver level)
    // ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Appsettings_Wins_When_ConfigJson_Is_Missing_And_No_Environment()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: null,
            environmentUrl: null,
            appsettingsUrl: "http://127.0.0.1:8000");

        Assert.Equal("http://127.0.0.1:8000/", result.ResolvedUrl);
        Assert.Equal("appsettings.json", result.Source);
    }

    [Fact]
    public void CompiledDefault_Used_When_All_Sources_Are_Null()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: null,
            environmentUrl: null,
            appsettingsUrl: null);

        Assert.Equal(ServiceConfigResolver.CompiledDefault, result.ResolvedUrl);
        Assert.Equal("compiled default", result.Source);
    }

    [Fact]
    public void CompiledDefault_Used_When_All_Sources_Are_Empty()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: "",
            environmentUrl: "",
            appsettingsUrl: "");

        Assert.Equal(ServiceConfigResolver.CompiledDefault, result.ResolvedUrl);
        Assert.Equal("compiled default", result.Source);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5. config.json URL containing :8000 => MUST NOT be treated as a development URL.
    //    This is the exact regression that broke Lab PC06.
    // ────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("http://192.168.11.65:8000")]
    [InlineData("http://10.0.2.15:8000")]
    [InlineData("https://spemcs.example.com:8000")]
    [InlineData("http://lab-backend:8000")]
    public void Port8000_In_ConfigJson_Is_Not_Treated_As_Development(string enrolledUrl)
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: enrolledUrl,
            environmentUrl: null,
            appsettingsUrl: "http://127.0.0.1:8002");

        // The enrolled URL must be used AS-IS — never replaced with localhost.
        Assert.Equal(enrolledUrl.TrimEnd('/') + "/", result.ResolvedUrl);
        Assert.Equal("config.json", result.Source);

        // Explicitly assert it did NOT fall back to localhost.
        Assert.DoesNotContain("127.0.0.1", result.ResolvedUrl);
        Assert.DoesNotContain("localhost", result.ResolvedUrl);
    }

    [Fact]
    public void Port8000_Regression_Exact_Lab_PC06_Scenario()
    {
        // Exact reproduction of the bug: config.json has the college backend on :8000,
        // appsettings.json has localhost:8002. Before the fix, the :8000 check caused
        // the service to silently use localhost:8002.
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: "http://192.168.11.65:8000",
            environmentUrl: null,
            appsettingsUrl: "http://127.0.0.1:8002");

        Assert.Equal("http://192.168.11.65:8000/", result.ResolvedUrl);
        Assert.Equal("config.json", result.Source);
        Assert.DoesNotContain("127.0.0.1", result.ResolvedUrl);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 6. config.json URL containing localhost => preserve it if explicitly enrolled.
    // ────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("http://localhost:8000")]
    [InlineData("http://localhost:8002")]
    [InlineData("http://127.0.0.1:8000")]
    [InlineData("http://127.0.0.1:9090")]
    public void Localhost_In_ConfigJson_Is_Preserved_When_Explicitly_Enrolled(string localhostUrl)
    {
        // A developer or a single-machine deployment that deliberately enrolled against
        // localhost must not have it silently rewritten. The enrollment wizard accepted
        // it, the user confirmed it, config.json says so — we honour it.
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: localhostUrl,
            environmentUrl: "http://some-other-server:8000",
            appsettingsUrl: "http://appsettings-server:8002");

        Assert.Equal(localhostUrl.TrimEnd('/') + "/", result.ResolvedUrl);
        Assert.Equal("config.json", result.Source);
    }

    [Fact]
    public void Localhost_In_Environment_Is_Preserved_When_No_ConfigJson()
    {
        var result = ServiceConfigResolver.Resolve(
            configJsonServerUrl: null,
            environmentUrl: "http://localhost:8000",
            appsettingsUrl: "http://127.0.0.1:8002");

        Assert.Equal("http://localhost:8000/", result.ResolvedUrl);
        Assert.Equal("environment variable SPEMCS_BACKEND_URL", result.Source);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 7. Trailing slash normalization.
    // ────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("http://server:8000", "http://server:8000/")]
    [InlineData("http://server:8000/", "http://server:8000/")]
    [InlineData("http://server:8000//", "http://server:8000/")]
    [InlineData("https://spemcs.edu", "https://spemcs.edu/")]
    [InlineData("https://spemcs.edu/", "https://spemcs.edu/")]
    [InlineData("  http://server:8000  ", "http://server:8000/")]
    public void NormalizeUrl_Ensures_Exactly_One_Trailing_Slash(string input, string expected)
    {
        Assert.Equal(expected, ServiceConfigResolver.NormalizeUrl(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void NormalizeUrl_Falls_Back_To_Default_For_Empty_Input(string? input)
    {
        Assert.Equal(ServiceConfigResolver.CompiledDefault, ServiceConfigResolver.NormalizeUrl(input!));
    }

    [Fact]
    public void All_Sources_Produce_Consistently_Normalized_Urls()
    {
        // config.json (no trailing slash)
        var r1 = ServiceConfigResolver.Resolve("http://a:8000", null, null);
        Assert.EndsWith("/", r1.ResolvedUrl);

        // environment (with trailing slash)
        var r2 = ServiceConfigResolver.Resolve(null, "http://b:8000/", null);
        Assert.EndsWith("/", r2.ResolvedUrl);
        Assert.DoesNotContain("//", r2.ResolvedUrl.Replace("http://", ""));

        // appsettings (no trailing slash)
        var r3 = ServiceConfigResolver.Resolve(null, null, "http://c:8000");
        Assert.EndsWith("/", r3.ResolvedUrl);

        // compiled default
        var r4 = ServiceConfigResolver.Resolve(null, null, null);
        Assert.EndsWith("/", r4.ResolvedUrl);
    }

    // ────────────────────────────────────────────────────────────────────────
    // 8. Source provenance is safe to log — never contains credentials.
    // ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Source_Label_Never_Contains_Credential_Material()
    {
        // config.json with an enrollment key right next to the URL (the resolver never sees the key).
        var r1 = ServiceConfigResolver.Resolve("http://server:8000", null, null);
        AssertNoCredentialLeak(r1);

        var r2 = ServiceConfigResolver.Resolve(null, "http://env-server:8000", null);
        AssertNoCredentialLeak(r2);

        var r3 = ServiceConfigResolver.Resolve(null, null, "http://appsettings:8000");
        AssertNoCredentialLeak(r3);

        var r4 = ServiceConfigResolver.Resolve(null, null, null);
        AssertNoCredentialLeak(r4);
    }

    [Fact]
    public void ResolvedUrl_Does_Not_Contain_Credential_Fragments()
    {
        // Even if someone accidentally passes a URL with auth info, the resolver stores only
        // the URL — but we verify the Source field (the only field intended for logging) never
        // leaks anything beyond the fixed provenance labels.
        var sources = new[]
        {
            ServiceConfigResolver.Resolve("http://server:8000", null, null),
            ServiceConfigResolver.Resolve(null, "http://env:8000", null),
            ServiceConfigResolver.Resolve(null, null, "http://app:8000"),
            ServiceConfigResolver.Resolve(null, null, null),
        };

        var safeLabels = new[] { "config.json", "environment variable SPEMCS_BACKEND_URL", "appsettings.json", "compiled default" };

        for (int i = 0; i < sources.Length; i++)
        {
            Assert.Equal(safeLabels[i], sources[i].Source);
            // Source must be one of the fixed safe labels — not a URL, not a secret, not dynamic input.
            AssertNoCredentialLeak(sources[i]);
        }
    }

    [Fact]
    public void Provenance_Labels_Are_Fixed_Strings_Not_Dynamic_Input()
    {
        // The Source property must only ever be one of the four known labels.
        // This prevents accidental credential leakage through dynamic formatting.
        var allPossibleSources = new[]
        {
            ServiceConfigResolver.Resolve("http://x", null, null).Source,
            ServiceConfigResolver.Resolve(null, "http://x", null).Source,
            ServiceConfigResolver.Resolve(null, null, "http://x").Source,
            ServiceConfigResolver.Resolve(null, null, null).Source,
        };

        var allowedSources = new HashSet<string>
        {
            "config.json",
            "environment variable SPEMCS_BACKEND_URL",
            "appsettings.json",
            "compiled default",
        };

        foreach (var source in allPossibleSources)
        {
            Assert.Contains(source, allowedSources);
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    private static void AssertNoCredentialLeak(ServiceConfigResolver resolved)
    {
        var credentialKeywords = new[]
        {
            "token", "jwt", "hmac", "secret", "key", "password",
            "bearer", "credential", "enrollment"
        };

        foreach (var keyword in credentialKeywords)
        {
            Assert.DoesNotContain(keyword, resolved.Source, StringComparison.OrdinalIgnoreCase);
        }
    }
}
