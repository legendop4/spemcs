using System;
using System.Linq;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

public class WindowsFirewallAdapterIntegrationTests
{
    [Fact]
    public void WindowsFirewall_CanReadActualHostBaseline()
    {
        var adapter = new WindowsFirewallAdapter();
        var baseline = adapter.GetBaseline();

        Assert.NotNull(baseline);
        Assert.True(baseline.ActiveProfiles > 0);
        // Default outbound actions must be either Allow (1) or Block (0)
        Assert.True(baseline.DomainDefaultOutbound == FirewallAction.Allow || baseline.DomainDefaultOutbound == FirewallAction.Block);
        Assert.True(baseline.PrivateDefaultOutbound == FirewallAction.Allow || baseline.PrivateDefaultOutbound == FirewallAction.Block);
        Assert.True(baseline.PublicDefaultOutbound == FirewallAction.Allow || baseline.PublicDefaultOutbound == FirewallAction.Block);
    }

    [Fact]
    public void WindowsFirewall_CanCreateInspectAndRemove_IPv4AndIPv6Rules()
    {
        var adapter = new WindowsFirewallAdapter();
        var testSessionId = Guid.NewGuid();

        var ipv4Rule = FirewallRuleModel.CreateOutboundAllow(
            testSessionId,
            "IntegrationIPv4",
            FirewallProtocol.TCP,
            "192.168.250.0/24",
            "8443"
        );

        var ipv6Rule = FirewallRuleModel.CreateOutboundAllow(
            testSessionId,
            "IntegrationIPv6",
            FirewallProtocol.TCP,
            "2001:db8:cafe:1234::/64",
            "8443"
        );

        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        bool isElevated = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

        if (!isElevated)
        {
            // When running in an unelevated standard user context, Windows Defender Firewall COM
            // strictly prevents rule modification, throwing UnauthorizedAccessException (0x80070005 E_ACCESSDENIED).
            // This verifies the critical Windows privilege boundary: only LocalSystem/Administrator can modify rules.
            var ex = Assert.Throws<UnauthorizedAccessException>(() => adapter.AddRule(ipv4Rule));
            Assert.Contains("Access is denied", ex.Message);
            return;
        }

        try
        {
            // 1. Add IPv4 and IPv6 rules
            adapter.AddRule(ipv4Rule);
            adapter.AddRule(ipv6Rule);

            // 2. Inspect: both rules must exist
            Assert.True(adapter.RuleExists(ipv4Rule.Name), $"IPv4 rule {ipv4Rule.Name} should exist in Windows Firewall");
            Assert.True(adapter.RuleExists(ipv6Rule.Name), $"IPv6 rule {ipv6Rule.Name} should exist in Windows Firewall");

            // 3. Inspect ownership group: both rules must belong to SPEMCS-EXAM-ENFORCEMENT
            var groupRuleNames = adapter.GetRuleNamesByGroup(FirewallRuleModel.SpemcsRuleGroup);
            Assert.Contains(ipv4Rule.Name, groupRuleNames);
            Assert.Contains(ipv6Rule.Name, groupRuleNames);

            // 4. Verify properties of discovered rule models
            var groupModels = adapter.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup);
            var v4Model = groupModels.FirstOrDefault(r => r.Name.Equals(ipv4Rule.Name, StringComparison.OrdinalIgnoreCase));
            var v6Model = groupModels.FirstOrDefault(r => r.Name.Equals(ipv6Rule.Name, StringComparison.OrdinalIgnoreCase));

            Assert.NotNull(v4Model);
            Assert.NotNull(v6Model);
            Assert.Equal(FirewallProtocol.TCP, v4Model.Protocol);
            Assert.Equal(FirewallDirection.Outbound, v4Model.Direction);
            Assert.Equal(FirewallAction.Allow, v4Model.Action);
            Assert.Contains("192.168.250.0/24", v4Model.RemoteAddresses);
            Assert.Contains("2001:db8:cafe:1234::/64", v6Model.RemoteAddresses);
        }
        finally
        {
            // 5. Cleanup: remove test rules and verify removal
            adapter.RemoveRule(ipv4Rule.Name);
            adapter.RemoveRule(ipv6Rule.Name);

            Assert.False(adapter.RuleExists(ipv4Rule.Name), $"IPv4 rule {ipv4Rule.Name} should have been removed");
            Assert.False(adapter.RuleExists(ipv6Rule.Name), $"IPv6 rule {ipv6Rule.Name} should have been removed");
        }
    }
}
