using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// P1-I: the browser DNS policy set, and the honest-failure decision built on it.
/// </summary>
/// <remarks>
/// <para>
/// NOTHING IN THIS FILE TOUCHES THE REGISTRY, and that is the reason the descriptor was extracted
/// in the first place. <c>BrowserPolicyEnforcer.DisableSecureDns</c> opens
/// <c>HKLM\SOFTWARE\Policies\Microsoft\Edge</c> and <c>...\Google\Chrome</c> for write; calling it
/// from a test would mutate machine-wide browser policy on whatever box runs <c>dotnet test</c>, and
/// would silently succeed when the test host happens to be elevated. This is the same hazard that
/// keeps <c>AgentWorkerStartupOrderTests</c> from ever letting startup recovery complete.
/// </para>
/// <para>
/// So the two things worth testing were made reachable without a registry:
/// <see cref="BrowserDnsPolicy.RequiredEntries"/> (pure data - WHICH values must be written) and
/// <see cref="BrowserDnsPolicy.Summarize"/> (a pure function - WHETHER the write outcomes amount to
/// success). No <c>IRegistry</c> seam is introduced, because the thin part that actually calls
/// <c>Registry.LocalMachine</c> has no logic left in it worth a fake.
/// </para>
/// </remarks>
public sealed class BrowserDnsPolicyTests
{
    private static BrowserDnsPolicyWriteOutcome AllLandedIn(
        BrowserDnsPolicyEntry entry,
        BrowserDnsPolicyHive hive,
        string? error = null) => new(entry, hive, error);

    private static List<BrowserDnsPolicyWriteOutcome> AllSucceededMachineWide() =>
        BrowserDnsPolicy.RequiredEntries
            .Select(e => AllLandedIn(e, BrowserDnsPolicyHive.LocalMachine))
            .ToList();

    // ─────────────────────────────────────────────────────────────────────
    // The required set itself
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void RequiredEntries_CoverBothBrowsers_WithBothValues()
    {
        var entries = BrowserDnsPolicy.RequiredEntries;

        // Four entries: two browsers x two values. Asserted as an exact count so
        // adding a browser or a value without deciding what it means here fails.
        Assert.Equal(4, entries.Count);

        foreach (var keyPath in new[] { BrowserDnsPolicy.EdgePolicyKeyPath, BrowserDnsPolicy.ChromePolicyKeyPath })
        {
            var forBrowser = entries.Where(e => e.PolicyKeyPath == keyPath).ToList();
            Assert.Equal(2, forBrowser.Count);
            Assert.Contains(forBrowser, e => e.ValueName == BrowserDnsPolicy.DnsOverHttpsModeValueName);
            Assert.Contains(forBrowser, e => e.ValueName == BrowserDnsPolicy.BuiltInDnsClientEnabledValueName);
        }
    }

    [Fact]
    public void RequiredEntries_IncludeBuiltInDnsClient_NotJustDoH()
    {
        // The regression this pins: before P1-I only DnsOverHttpsMode was written.
        // That leaves the browser's own embedded plain-DNS stub resolver enabled -
        // not DoH, so DnsOverHttpsMode does not cover it, and it bypasses the
        // Windows DNS Client service and therefore the ETW monitor entirely. Because
        // it originates in the approved browser executable it also sits inside the
        // program scope every allow rule is pinned to.
        var builtIn = BrowserDnsPolicy.RequiredEntries
            .Where(e => e.ValueName == BrowserDnsPolicy.BuiltInDnsClientEnabledValueName)
            .ToList();

        Assert.Equal(2, builtIn.Count);
        foreach (var entry in builtIn)
        {
            Assert.Equal(RegistryValueKind.DWord, entry.Kind);
            Assert.Equal(0, entry.Value);
        }
    }

    [Fact]
    public void RequiredEntries_DisableDoH_WithTheStringValueThePolicyExpects()
    {
        var doh = BrowserDnsPolicy.RequiredEntries
            .Where(e => e.ValueName == BrowserDnsPolicy.DnsOverHttpsModeValueName)
            .ToList();

        Assert.Equal(2, doh.Count);
        foreach (var entry in doh)
        {
            // Chromium reads this as a string enum; a DWord here is ignored silently,
            // which would leave DoH on while the apply reported success.
            Assert.Equal(RegistryValueKind.String, entry.Kind);
            Assert.Equal("off", entry.Value);
        }
    }

    [Fact]
    public void RequiredEntries_NeverReachOutsideTheEnterprisePolicySubtree()
    {
        // A write outside SOFTWARE\Policies\ would be general machine configuration,
        // not browser policy - and SPEMCS has no mandate to change that. This is the
        // guard on future entries, not on the current four.
        foreach (var entry in BrowserDnsPolicy.RequiredEntries)
        {
            Assert.StartsWith(BrowserDnsPolicy.PolicyKeyPrefix, entry.PolicyKeyPath, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("..", entry.PolicyKeyPath, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void RequiredEntries_HaveNoDuplicateTargets()
    {
        // Summarize matches an outcome to a requirement by (key path, value name).
        // A duplicated pair would make that match ambiguous and could let a failed
        // write be summarised using a different entry's successful outcome.
        var targets = BrowserDnsPolicy.RequiredEntries
            .Select(e => $"{e.PolicyKeyPath.ToUpperInvariant()}|{e.ValueName.ToUpperInvariant()}")
            .ToList();

        Assert.Equal(targets.Count, targets.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void RequiredEntries_EachCarryARationale()
    {
        // The rationale is the only place the reason for each value is recorded next
        // to the value. An entry without one is an entry nobody can safely remove.
        foreach (var entry in BrowserDnsPolicy.RequiredEntries)
        {
            Assert.False(string.IsNullOrWhiteSpace(entry.Rationale));
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Summarize - the honest-failure decision
    // ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Summarize_AllMachineWide_IsTheOnlySuccess()
    {
        var success = BrowserDnsPolicy.Summarize(AllSucceededMachineWide(), out var message);

        Assert.True(success);
        Assert.Contains("Applied machine-wide", message, StringComparison.Ordinal);
        Assert.DoesNotContain("DEGRADED", message, StringComparison.Ordinal);
        Assert.DoesNotContain("NOT APPLIED", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Summarize_TotalFailure_DoesNotReportSuccess()
    {
        // THE REGRESSION THIS FILE EXISTS FOR. DisableSecureDns used to declare
        // `bool success = true;` and never assign it again, so this exact situation -
        // every registry write refused - returned true. The caller in AgentWorker
        // logs the true branch as "Browser Secure DNS policy enforced", so a total
        // failure to disable DoH was reported as enforcement, and the LogWarning
        // branch was unreachable code.
        var outcomes = BrowserDnsPolicy.RequiredEntries
            .Select(e => AllLandedIn(e, BrowserDnsPolicyHive.None, "HKLM: Access to the registry key is denied.; HKCU: denied"))
            .ToList();

        var success = BrowserDnsPolicy.Summarize(outcomes, out var message);

        Assert.False(success);
        Assert.Contains("NOT APPLIED", message, StringComparison.Ordinal);
        Assert.Contains("denied", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Summarize_CurrentUserFallback_IsReportedAsDegradedNotSuccess()
    {
        // An HKCU fallback does apply to the candidate's session, so it is tempting
        // to call it success. It is not: it covers only one user, and it lives in a
        // hive the candidate can rewrite without elevation. Reporting it as a clean
        // apply would hide the fact that the agent is not running with the rights it
        // needs - which in production (LocalSystem) should never happen.
        var outcomes = AllSucceededMachineWide();
        outcomes[0] = AllLandedIn(outcomes[0].Entry, BrowserDnsPolicyHive.CurrentUser, "Access to the registry key is denied.");

        var success = BrowserDnsPolicy.Summarize(outcomes, out var message);

        Assert.False(success);
        Assert.Contains("DEGRADED", message, StringComparison.Ordinal);
        Assert.Contains("current-user hive only", message, StringComparison.Ordinal);
        // The machine-wide successes are still named, so the operator can see how far it got.
        Assert.Contains("Applied machine-wide", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Summarize_OneMissingValue_IsAFailureNotAnOmission()
    {
        // A caller that stops attempting one entry must not get a pass for the
        // three it did attempt. Requiring positive evidence per entry - rather than
        // scanning the outcomes it happens to be handed - is what makes that true.
        var outcomes = AllSucceededMachineWide();
        var dropped = outcomes[^1];
        outcomes.RemoveAt(outcomes.Count - 1);

        var success = BrowserDnsPolicy.Summarize(outcomes, out var message);

        Assert.False(success);
        Assert.Contains("never attempted", message, StringComparison.Ordinal);
        Assert.Contains(dropped.Entry.ValueName, message, StringComparison.Ordinal);
    }

    [Fact]
    public void Summarize_NoOutcomesAtAll_IsAFailure()
    {
        var success = BrowserDnsPolicy.Summarize(Array.Empty<BrowserDnsPolicyWriteOutcome>(), out var message);

        Assert.False(success);
        Assert.Contains("NOT APPLIED", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Summarize_UnrelatedExtraOutcomes_CannotManufactureSuccess()
    {
        // Success is decided by the required set, not by the length of the outcome
        // list, so padding it with unrelated successes changes nothing.
        var fake = new BrowserDnsPolicyEntry(
            "Not A Browser",
            @"SOFTWARE\Policies\Unrelated\Thing",
            "SomeOtherValue",
            1,
            RegistryValueKind.DWord,
            "not part of the required set");

        var outcomes = new List<BrowserDnsPolicyWriteOutcome>
        {
            AllLandedIn(fake, BrowserDnsPolicyHive.LocalMachine),
            AllLandedIn(fake with { ValueName = "AnotherValue" }, BrowserDnsPolicyHive.LocalMachine),
            AllLandedIn(fake with { ValueName = "AThirdValue" }, BrowserDnsPolicyHive.LocalMachine),
            AllLandedIn(fake with { ValueName = "AFourthValue" }, BrowserDnsPolicyHive.LocalMachine),
        };

        var success = BrowserDnsPolicy.Summarize(outcomes, out var message);

        Assert.False(success);
        Assert.Contains("never attempted", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Summarize_NullOutcomes_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => BrowserDnsPolicy.Summarize(null!, out _));
    }

    [Fact]
    public void Summarize_MatchesOutcomesCaseInsensitively()
    {
        // Registry paths and value names are case-insensitive on Windows. If matching
        // were case-sensitive, a caller spelling the path differently would produce
        // "never attempted" for a value that was in fact written - a false failure.
        var outcomes = BrowserDnsPolicy.RequiredEntries
            .Select(e => AllLandedIn(
                e with
                {
                    PolicyKeyPath = e.PolicyKeyPath.ToUpperInvariant(),
                    ValueName = e.ValueName.ToLowerInvariant()
                },
                BrowserDnsPolicyHive.LocalMachine))
            .ToList();

        Assert.True(BrowserDnsPolicy.Summarize(outcomes, out _));
    }
}
