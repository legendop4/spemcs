using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Spemcs.Agent.Core.Network;

namespace Spemcs.Agent.Tests;

public sealed class MockFirewallAdapter : IFirewallAdapter
{
    public FirewallAction DomainDefaultOutbound { get; set; } = FirewallAction.Allow;
    public FirewallAction PrivateDefaultOutbound { get; set; } = FirewallAction.Allow;
    public FirewallAction PublicDefaultOutbound { get; set; } = FirewallAction.Allow;
    public FirewallProfiles ActiveProfiles { get; set; } = FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public;

    public List<FirewallRuleModel> Rules { get; } = new();

    /// <summary>
    /// Rules on the machine that SPEMCS did not create - Windows built-ins, other security products,
    /// enterprise configuration - and that must survive every SPEMCS operation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are REMOVABLE, and that is the point. Until Phase 18 <see cref="RemoveRule"/> only ever
    /// touched <see cref="Rules"/>, which made this list physically impossible to delete from - so
    /// every "unrelated rules preserved" assertion in the suite was guaranteed to pass no matter what
    /// the production code did. A test that cannot fail proves nothing, and this one was standing in
    /// for requirement 9's central promise.
    /// </para>
    /// <para>
    /// The list deliberately includes a rule named <c>"Codex"</c>. The project owner's standing
    /// instruction is that SPEMCS must never enable, disable, modify or delete that rule, and it is
    /// specifically not to be removed as part of SPEMCS rollback. Encoding it here turns that
    /// instruction into something the suite checks on every run rather than something a reader has to
    /// take on trust. It is a string in a test double; nothing in this file, or reachable from it,
    /// talks to the real Windows Firewall.
    /// </para>
    /// </remarks>
    /// <summary>
    /// The rule the project owner has explicitly placed off-limits: SPEMCS must never enable, disable,
    /// modify or delete it, and it is specifically not to be removed as part of SPEMCS rollback.
    /// </summary>
    public const string OffLimitsUnrelatedRuleName = "Codex";

    /// <summary>
    /// The unrelated rules every <see cref="MockFirewallAdapter"/> starts with. Exposed so a test can
    /// assert the SET is intact rather than that its COUNT is some magic number - which also means
    /// adding an entry here does not require editing unrelated assertions.
    /// </summary>
    public static IReadOnlyList<string> DefaultUnrelatedRuleNames { get; } = new[]
    {
        "Core Networking (DNS-Out)",
        "Remote Desktop (TCP-In)",
        "Custom Enterprise App",
        OffLimitsUnrelatedRuleName
    };

    public List<string> UnrelatedRuleNames { get; } = new(DefaultUnrelatedRuleNames);

    /// <summary>
    /// Every rule name <see cref="RemoveRule"/> was asked to delete, in order, whether or not such a
    /// rule existed. Lets a test assert that a name was never even ATTEMPTED, which is stronger than
    /// asserting that it survived - a rule can survive a delete attempt by accident.
    /// </summary>
    public List<string> RemovalAttempts { get; } = new();

    /// <summary>
    /// Every <see cref="SetDefaultOutboundAction"/> call, in order, as (profile mask, action) - even
    /// when the call was a no-op because the profile already held that action. Lets a test assert that
    /// a profile outside the target set was never WRITTEN, which a final-state assertion cannot
    /// distinguish from "written back to the same value it already had".
    /// </summary>
    public List<(FirewallProfiles Profiles, FirewallAction Action)> DefaultActionWrites { get; } = new();

    public bool ThrowOnAddRule { get; set; }
    public bool ThrowOnSetBlock { get; set; }

    /// <summary>
    /// Profiles that silently refuse to hold <see cref="FirewallAction.Block"/>.
    /// </summary>
    /// <remarks>
    /// Models the failure mode that readback verification exists to catch: a Group Policy that
    /// re-asserts its own outbound default, or a profile the COM call reported success for but did
    /// not actually change. It is silent rather than throwing precisely because a throw would be
    /// caught by the ordinary error path - the dangerous case is the one where SPEMCS believes it
    /// locked the profile down and no exception was raised.
    /// </remarks>
    public FirewallProfiles ProfilesIgnoringBlock { get; set; } = FirewallProfiles.None;

    public FirewallProfileBaseline GetBaseline()
    {
        return new FirewallProfileBaseline(
            DomainDefaultOutbound: DomainDefaultOutbound,
            PrivateDefaultOutbound: PrivateDefaultOutbound,
            PublicDefaultOutbound: PublicDefaultOutbound,
            ActiveProfiles: ActiveProfiles,
            CapturedUtc: DateTimeOffset.UtcNow
        );
    }

    public void SetDefaultOutboundAction(FirewallProfiles profile, FirewallAction action)
    {
        if (ThrowOnSetBlock && action == FirewallAction.Block)
        {
            throw new InvalidOperationException("Simulated firewall failure while applying default block.");
        }

        DefaultActionWrites.Add((profile, action));

        // Applied per profile so a single ignored profile can be simulated without affecting the
        // others: the caller passes a combined mask, but each profile settles independently.
        void Apply(FirewallProfiles single, Action<FirewallAction> assign)
        {
            if (!profile.HasFlag(single)) return;
            if (action == FirewallAction.Block && ProfilesIgnoringBlock.HasFlag(single)) return;
            assign(action);
        }

        Apply(FirewallProfiles.Domain, a => DomainDefaultOutbound = a);
        Apply(FirewallProfiles.Private, a => PrivateDefaultOutbound = a);
        Apply(FirewallProfiles.Public, a => PublicDefaultOutbound = a);
    }

    public void AddRule(FirewallRuleModel rule)
    {
        if (ThrowOnAddRule)
        {
            throw new InvalidOperationException("Simulated firewall failure while adding rule.");
        }
        Rules.RemoveAll(r => r.Name.Equals(rule.Name, StringComparison.OrdinalIgnoreCase));
        Rules.Add(rule);
    }

    /// <summary>
    /// Deletes a rule by name from EITHER collection, exactly as the real adapter would.
    /// </summary>
    /// <remarks>
    /// Reaching into <see cref="UnrelatedRuleNames"/> is intentional. The real
    /// <c>WindowsFirewallAdapter.RemoveRule</c> hands the name to
    /// <c>INetFwRules.Remove</c>, which does not care who created the rule; a test double that could
    /// only ever delete SPEMCS's own rules would model a safety property the production code does not
    /// have, and would silently pass any regression that started deleting other products' rules.
    /// </remarks>
    public bool RemoveRule(string ruleName)
    {
        RemovalAttempts.Add(ruleName);
        var removedSpemcs = Rules.RemoveAll(r => r.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase)) > 0;
        var removedUnrelated = UnrelatedRuleNames.RemoveAll(n => n.Equals(ruleName, StringComparison.OrdinalIgnoreCase)) > 0;
        return removedSpemcs || removedUnrelated;
    }

    public bool RuleExists(string ruleName)
    {
        return Rules.Any(r => r.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase)) ||
               UnrelatedRuleNames.Contains(ruleName, StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyList<string> GetRuleNamesByGroup(string group)
    {
        return Rules
            .Where(r => string.Equals(r.Group, group, StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Name)
            .ToList();
    }

    public IReadOnlyList<FirewallRuleModel> GetRulesByGroup(string group)
    {
        var matched = Rules.Where(r => string.Equals(r.Group, group, StringComparison.OrdinalIgnoreCase));

        if (!SimulateWindowsAddressNormalization)
        {
            return matched.ToList();
        }

        return matched
            .Select(r => r with
            {
                RemoteAddresses = ToWindowsRepresentation(r.RemoteAddresses),
                LocalAddresses = ToWindowsRepresentation(r.LocalAddresses),
            })
            .ToList();
    }

    /// <summary>
    /// When true, <see cref="GetRulesByGroup"/> returns addresses in the representation Windows
    /// Defender Firewall actually hands back rather than the verbatim string that was added: IPv4
    /// CIDR rewritten to a dotted-decimal subnet mask, a bare IPv4 host given an explicit
    /// /255.255.255.255, a bare IPv6 host expanded into a degenerate range. IPv6 prefixes and
    /// ranges round trip unchanged.
    ///
    /// Off by default, so no existing test changes behaviour. It exists because a mock that echoes
    /// back exactly what it was given cannot reveal a readback-verification defect - which is why
    /// the whole suite stayed green while NetworkEnforcer would have rejected every IPv4 rule it
    /// installed on a real host.
    /// </summary>
    public bool SimulateWindowsAddressNormalization { get; set; }

    private static string ToWindowsRepresentation(string spec)
    {
        if (string.IsNullOrWhiteSpace(spec) || string.Equals(spec, "*", StringComparison.Ordinal))
        {
            return spec;
        }

        var tokens = spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(',', tokens.Select(ToWindowsToken));
    }

    private static string ToWindowsToken(string token)
    {
        var slash = token.IndexOf('/', StringComparison.Ordinal);

        if (slash < 0)
        {
            if (!IPAddress.TryParse(token, out var host))
            {
                return token;
            }

            return host.AddressFamily == AddressFamily.InterNetworkV6
                ? string.Concat(host.ToString(), "-", host.ToString())
                : string.Concat(host.ToString(), "/255.255.255.255");
        }

        // Only IPv4 prefixes are rewritten; IPv6 prefixes and explicit ranges are returned as given.
        if (!IPAddress.TryParse(token[..slash], out var network) ||
            network.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(token[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) ||
            prefix < 0 || prefix > 32)
        {
            return token;
        }

        var bits = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var mask = new IPAddress(new[] { (byte)(bits >> 24), (byte)(bits >> 16), (byte)(bits >> 8), (byte)bits });
        return string.Concat(network.ToString(), "/", mask.ToString());
    }
}
