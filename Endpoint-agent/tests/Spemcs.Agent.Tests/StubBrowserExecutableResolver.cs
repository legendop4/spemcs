using Spemcs.Agent.Core;
using Spemcs.Agent.Core.Network;

namespace Spemcs.Agent.Tests;

/// <summary>
/// Deterministic <see cref="IBrowserExecutableResolver"/> for tests.
/// <para>
/// The real <see cref="BrowserExecutableResolver"/> touches the filesystem and Authenticode, so a
/// test that used it would pass or fail depending on whether the build agent happens to have Chrome
/// installed. Every test that drives <c>EnforcementStateMachine</c> injects this instead, so the
/// browser-scoping behaviour under test is the state machine's, not the host's.
/// </para>
/// </summary>
public sealed class StubBrowserExecutableResolver : IBrowserExecutableResolver
{
    /// <summary>
    /// Canonical machine-wide Chrome path used across the enforcement tests.
    /// Deliberately an absolute path: <c>BuildSessionRules</c> rejects relative paths.
    /// </summary>
    public const string DefaultChromePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe";

    /// <summary>Canonical machine-wide Edge path, for browser-change/mismatch tests.</summary>
    public const string DefaultEdgePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";

    private readonly string? _forcedPath;
    private readonly bool _succeed;
    private readonly bool _isUserWritable;

    /// <summary>Number of times <see cref="Resolve"/> has been called (activation must resolve exactly once).</summary>
    public int ResolveCallCount { get; private set; }

    /// <summary>The last family the state machine asked about - proves the SIGNED value is used.</summary>
    public ApprovedBrowserFamily? LastRequestedFamily { get; private set; }

    private StubBrowserExecutableResolver(bool succeed, string? forcedPath, bool isUserWritable)
    {
        _succeed = succeed;
        _forcedPath = forcedPath;
        _isUserWritable = isUserWritable;
    }

    /// <summary>Resolves whichever family is requested to its canonical path.</summary>
    public static StubBrowserExecutableResolver Succeeding() => new(true, null, false);

    /// <summary>Resolves every family to <paramref name="path"/>, regardless of what was asked.</summary>
    public static StubBrowserExecutableResolver Returning(string path, bool isUserWritableLocation = false)
        => new(true, path, isUserWritableLocation);

    /// <summary>Always fails - used to assert activation aborts fail-closed.</summary>
    public static StubBrowserExecutableResolver Failing() => new(false, null, false);

    /// <inheritdoc />
    public BrowserResolution Resolve(ApprovedBrowserFamily family)
    {
        ResolveCallCount++;
        LastRequestedFamily = family;

        if (!_succeed)
        {
            return BrowserResolution.Failed(
                $"stub resolver configured to fail for '{family}'");
        }

        var path = _forcedPath ?? family switch
        {
            ApprovedBrowserFamily.Edge => DefaultEdgePath,
            _ => DefaultChromePath
        };

        return BrowserResolution.Resolved(path, $"stub resolution for '{family}'", _isUserWritable);
    }
}
