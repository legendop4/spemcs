using System.Text;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Outcome of resolving an <see cref="ApprovedBrowserFamily"/> to a concrete executable on disk.
/// </summary>
/// <param name="Success">True only when <paramref name="ExecutablePath"/> is a verified path.</param>
/// <param name="ExecutablePath">
/// Absolute path to the approved examination browser executable, or null when resolution failed.
/// This is the exact string written to the Windows Firewall rule's ApplicationName property.
/// </param>
/// <param name="Details">
/// Human-readable diagnostic. On failure it enumerates every candidate that was considered and
/// why each was rejected, so an operator can fix the deployment without a debugger.
/// </param>
/// <param name="IsUserWritableLocation">
/// True when the resolved executable lives under a per-user, user-writable directory
/// (a Chrome per-user install). The firewall matches on path, so a user-writable image path is a
/// materially weaker posture than a machine-wide install; callers should surface this.
/// </param>
public sealed record BrowserResolution(
    bool Success,
    string? ExecutablePath,
    string Details,
    bool IsUserWritableLocation = false)
{
    /// <summary>Creates a successful resolution.</summary>
    public static BrowserResolution Resolved(string executablePath, string details, bool isUserWritableLocation = false)
        => new(true, executablePath, details, isUserWritableLocation);

    /// <summary>Creates a failed resolution. Callers MUST fail closed on this.</summary>
    public static BrowserResolution Failed(string details) => new(false, null, details);
}

/// <summary>
/// Resolves the approved examination browser family named in the SIGNED policy to a concrete,
/// trust-verified executable path.
/// </summary>
public interface IBrowserExecutableResolver
{
    /// <summary>
    /// Resolves <paramref name="family"/> to an executable path, or returns a failed
    /// <see cref="BrowserResolution"/> explaining why no acceptable candidate was found.
    /// Implementations MUST NOT return a "best guess" path: an unverified path would be baked
    /// into a firewall allow rule.
    /// </summary>
    BrowserResolution Resolve(ApprovedBrowserFamily family);
}

/// <summary>
/// Locates the approved examination browser executable for firewall rule scoping
/// (requirements 4 and 5).
///
/// <para><b>Why this type exists.</b> Every vendor/exam destination allow rule is scoped to the
/// approved browser's executable via the firewall rule's ApplicationName. Without that scoping,
/// the allowlist is reachable by any process on the machine - curl.exe, python.exe, a
/// student-supplied tunnelling client - which defeats the entire lockdown. So the agent needs a
/// single, auditable answer to "which file on disk is the approved browser?".</para>
///
/// <para><b>Why it is deliberately narrow.</b> The candidate set is restricted to the same
/// install locations and publishers that <c>ConfigurableProcessClassifier</c> uses to grant
/// browser approval. Keeping the two in agreement is what makes an exam internally consistent:
/// the binary the firewall permits is exactly the binary the process monitor treats as the
/// approved browser. A PATH lookup, registry App Paths lookup, or "first chrome.exe found"
/// search would all let a student-controlled binary named chrome.exe become the firewall's
/// allowlisted program.</para>
///
/// <para><b>Trust check is stricter than the classifier's.</b> The classifier currently accepts a
/// publisher-name match without asserting <see cref="FileTrustResult.IsTrusted"/>. This resolver
/// requires BOTH a valid Authenticode chain AND the expected publisher, because the consequence
/// here (a permanent hole in the allowlist for the duration of the exam) is worse than the
/// consequence there (a monitoring event). Strictly stronger, so the two can never disagree in
/// the unsafe direction.</para>
///
/// <para><b>Fails closed.</b> If nothing resolves, callers must abort activation rather than
/// install an unscoped rule. An exam that cannot start is a recoverable operational problem; an
/// exam that starts with a machine-wide allowlist is a silent integrity failure.</para>
/// </summary>
public sealed class BrowserExecutableResolver : IBrowserExecutableResolver
{
    /// <summary>Relative path of chrome.exe beneath any Chrome install root.</summary>
    internal const string ChromeRelativePath = @"Google\Chrome\Application\chrome.exe";

    /// <summary>Relative path of msedge.exe beneath any Edge install root.</summary>
    internal const string EdgeRelativePath = @"Microsoft\Edge\Application\msedge.exe";

    private const string ChromePublisherToken = "Google";
    private const string EdgePublisherToken = "Microsoft";

    private readonly IFileTrustVerifier _trust;
    private readonly IReadOnlyList<string> _machineRoots;
    private readonly string? _perUserRoot;
    private readonly Func<string, bool> _fileExists;

    /// <summary>
    /// Production constructor: discovers machine-wide Program Files roots and the current user's
    /// LocalAppData root from the environment.
    /// </summary>
    /// <param name="trust">
    /// Authenticode verifier. Injected so tests can exercise trusted/untrusted/wrong-publisher
    /// paths without needing a real signed binary.
    /// </param>
    public BrowserExecutableResolver(IFileTrustVerifier? trust = null)
        : this(trust, DiscoverMachineRoots(), DiscoverPerUserRoot(), fileExists: null)
    {
    }

    /// <summary>
    /// Test/advanced constructor with every filesystem dependency injected.
    /// </summary>
    /// <param name="trust">Authenticode verifier (defaults to the real one).</param>
    /// <param name="machineRoots">
    /// Ordered machine-wide install roots (normally ProgramFiles / ProgramFiles(x86)). Searched
    /// first because they are administrator-writable only.
    /// </param>
    /// <param name="perUserRoot">
    /// Per-user install root (normally %LOCALAPPDATA%), or null to disable the per-user fallback
    /// entirely. Searched last and flagged, because it is student-writable.
    /// </param>
    /// <param name="fileExists">File existence predicate (defaults to <see cref="File.Exists"/>).</param>
    internal BrowserExecutableResolver(
        IFileTrustVerifier? trust,
        IReadOnlyList<string> machineRoots,
        string? perUserRoot,
        Func<string, bool>? fileExists)
    {
        _trust = trust ?? new AuthenticodeTrustVerifier();
        _machineRoots = machineRoots ?? Array.Empty<string>();
        _perUserRoot = string.IsNullOrWhiteSpace(perUserRoot) ? null : perUserRoot;
        _fileExists = fileExists ?? File.Exists;
    }

    /// <inheritdoc />
    public BrowserResolution Resolve(ApprovedBrowserFamily family)
    {
        string relativePath;
        string publisherToken;
        bool allowPerUserFallback;

        switch (family)
        {
            case ApprovedBrowserFamily.Chrome:
                relativePath = ChromeRelativePath;
                publisherToken = ChromePublisherToken;
                // Chrome genuinely ships a per-user installer and it is common on unmanaged
                // machines, so it is permitted as a last resort - but reported.
                allowPerUserFallback = true;
                break;

            case ApprovedBrowserFamily.Edge:
                relativePath = EdgeRelativePath;
                publisherToken = EdgePublisherToken;
                // Edge is machine-wide on every supported Windows build. Refusing a per-user
                // Edge costs nothing real and removes a student-writable image path.
                allowPerUserFallback = false;
                break;

            default:
                // Unreachable while ApprovedBrowserFamily only has resolvable members, but an
                // added-and-forgotten member must fail closed rather than fall through to null.
                return BrowserResolution.Failed(
                    $"No executable mapping is defined for approved browser family '{family}'. " +
                    "Every ApprovedBrowserFamily member must be resolvable; refusing to continue.");
        }

        var rejections = new StringBuilder();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (root, isUserWritable) in EnumerateRoots(allowPerUserFallback))
        {
            string candidate;
            try
            {
                candidate = Path.GetFullPath(Path.Combine(root, relativePath));
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                Append(rejections, Path.Combine(root, relativePath), $"unusable path ({ex.GetType().Name})");
                continue;
            }

            // ProgramFiles and ProgramFiles(x86) collapse to the same string on 32-bit hosts, and
            // a caller may pass duplicate roots; only evaluate (and only report) each path once.
            if (!seen.Add(candidate))
                continue;

            if (!_fileExists(candidate))
            {
                Append(rejections, candidate, "not present");
                continue;
            }

            FileTrustResult trust;
            try
            {
                trust = _trust.Verify(candidate);
            }
            catch (Exception ex)
            {
                // A verifier that throws must not be treated as a pass.
                Append(rejections, candidate, $"trust verification threw {ex.GetType().Name}");
                continue;
            }

            if (!trust.IsTrusted)
            {
                Append(rejections, candidate, $"Authenticode not trusted ({trust.Reason})");
                continue;
            }

            if (trust.Publisher is null ||
                !trust.Publisher.Contains(publisherToken, StringComparison.OrdinalIgnoreCase))
            {
                Append(rejections, candidate,
                    $"publisher '{trust.Publisher ?? "<none>"}' does not match expected '{publisherToken}'");
                continue;
            }

            var location = isUserWritable
                ? "per-user install (USER-WRITABLE image path: a local attacker who can replace " +
                  "this file inherits the exam allowlist; prefer a machine-wide install)"
                : "machine-wide install";

            return BrowserResolution.Resolved(
                candidate,
                $"{family} resolved to '{candidate}' ({location}); publisher '{trust.Publisher}', {trust.Reason}",
                isUserWritable);
        }

        var considered = rejections.Length == 0 ? "no candidate locations were configured" : rejections.ToString();
        return BrowserResolution.Failed(
            $"Could not resolve a trusted executable for approved browser '{family}'. Candidates: {considered}");
    }

    private IEnumerable<(string Root, bool IsUserWritable)> EnumerateRoots(bool allowPerUserFallback)
    {
        foreach (var root in _machineRoots)
        {
            if (!string.IsNullOrWhiteSpace(root))
                yield return (root, false);
        }

        if (allowPerUserFallback && _perUserRoot is not null)
            yield return (_perUserRoot, true);
    }

    private static void Append(StringBuilder sb, string candidate, string reason)
    {
        if (sb.Length > 0)
            sb.Append("; ");
        sb.Append('\'').Append(candidate).Append("' -> ").Append(reason);
    }

    /// <summary>
    /// Machine-wide install roots, most-preferred first.
    /// <para>
    /// ProgramW6432 is consulted explicitly because when the agent runs as a 32-bit process on a
    /// 64-bit host, SpecialFolder.ProgramFiles is redirected to "Program Files (x86)" and the
    /// 64-bit Chrome/Edge install would otherwise be invisible.
    /// </para>
    /// </summary>
    private static IReadOnlyList<string> DiscoverMachineRoots()
    {
        var roots = new List<string>(4);

        void Add(string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
                roots.Add(value);
        }

        Add(Environment.GetEnvironmentVariable("ProgramW6432"));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

        return roots;
    }

    private static string? DiscoverPerUserRoot()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrWhiteSpace(localAppData) ? null : localAppData;
    }
}
