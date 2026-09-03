using System;
using System.Collections.Generic;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Low-level abstraction over the Windows Defender Firewall COM subsystem.
/// </summary>
public interface IFirewallAdapter
{
    /// <summary>Reads current default outbound actions across profiles.</summary>
    FirewallProfileBaseline GetBaseline();

    /// <summary>Sets default outbound action (Block/Allow) for specific profiles.</summary>
    void SetDefaultOutboundAction(FirewallProfiles profile, FirewallAction action);

    /// <summary>Adds a new firewall rule.</summary>
    void AddRule(FirewallRuleModel rule);

    /// <summary>Removes a firewall rule by exact name.</summary>
    bool RemoveRule(string ruleName);

    /// <summary>Checks whether a rule exists by exact name.</summary>
    bool RuleExists(string ruleName);

    /// <summary>Enumerates rule names belonging strictly to the specified rule group.</summary>
    IReadOnlyList<string> GetRuleNamesByGroup(string group);

    /// <summary>Enumerates all rule models currently in the specified rule group.</summary>
    IReadOnlyList<FirewallRuleModel> GetRulesByGroup(string group);
}
