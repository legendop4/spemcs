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

        if (profile.HasFlag(FirewallProfiles.Domain)) DomainDefaultOutbound = action;
        if (profile.HasFlag(FirewallProfiles.Private)) PrivateDefaultOutbound = action;
        if (profile.HasFlag(FirewallProfiles.Public)) PublicDefaultOutbound = action;
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
