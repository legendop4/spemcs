using System;
using System.Collections.Generic;
using System.Linq;
using Spemcs.Agent.Core.Network;

namespace Spemcs.Agent.Tests;

public sealed class MockFirewallAdapter : IFirewallAdapter
{
    public FirewallAction DomainDefaultOutbound { get; set; } = FirewallAction.Allow;
    public FirewallAction PrivateDefaultOutbound { get; set; } = FirewallAction.Allow;
    public FirewallAction PublicDefaultOutbound { get; set; } = FirewallAction.Allow;
    public FirewallProfiles ActiveProfiles { get; set; } = FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public;

    public List<FirewallRuleModel> Rules { get; } = new();
    public List<string> UnrelatedRuleNames { get; } = new() { "Core Networking (DNS-Out)", "Remote Desktop (TCP-In)", "Custom Enterprise App" };

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

    public bool RemoveRule(string ruleName)
    {
        return Rules.RemoveAll(r => r.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase)) > 0;
    }

    public bool RuleExists(string ruleName)
    {
        return Rules.Any(r => r.Name.Equals(ruleName, StringComparison.OrdinalIgnoreCase)) ||
               UnrelatedRuleNames.Contains(ruleName);
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
        return Rules
            .Where(r => string.Equals(r.Group, group, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }
}
