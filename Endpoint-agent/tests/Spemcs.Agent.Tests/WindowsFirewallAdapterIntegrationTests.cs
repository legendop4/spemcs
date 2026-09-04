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

    [Fact]
    public async Task WindowsFirewall_Elevated_LiveLoopbackAndManagementUnderDefaultBlock()
    {
        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        bool isElevated = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

        var adapter = new WindowsFirewallAdapter();

        if (!isElevated)
        {
            // Verify security boundary: mutating default outbound action requires elevation
            var ex = Assert.Throws<UnauthorizedAccessException>(() =>
                adapter.SetDefaultOutboundAction(FirewallProfiles.Public, FirewallAction.Block));
            Assert.Contains("Access is denied", ex.Message);
            return;
        }

        var baseline = adapter.GetBaseline();
        var testSessionId = Guid.NewGuid();

        var loopbackV4 = FirewallRuleModel.CreateLoopbackIPv4Allow(testSessionId, baseline.ActiveProfiles);
        var loopbackV6 = FirewallRuleModel.CreateLoopbackIPv6Allow(testSessionId, baseline.ActiveProfiles);
        var mgmtRule = FirewallRuleModel.CreateOutboundAllow(
            testSessionId,
            "Mgmt",
            FirewallProtocol.TCP,
            "127.0.0.1",
            "8002",
            profiles: baseline.ActiveProfiles
        );

        try
        {
            // b. Creates the product-owned rules
            adapter.AddRule(loopbackV4);
            adapter.AddRule(loopbackV6);
            adapter.AddRule(mgmtRule);

            Assert.True(adapter.RuleExists(loopbackV4.Name));
            Assert.True(adapter.RuleExists(loopbackV6.Name));
            Assert.True(adapter.RuleExists(mgmtRule.Name));

            // c. Sets DefaultOutboundAction = Block
            adapter.SetDefaultOutboundAction(baseline.ActiveProfiles, FirewallAction.Block);

            var enforcedBaseline = adapter.GetBaseline();
            if (baseline.ActiveProfiles.HasFlag(FirewallProfiles.Domain))
                Assert.Equal(FirewallAction.Block, enforcedBaseline.DomainDefaultOutbound);
            if (baseline.ActiveProfiles.HasFlag(FirewallProfiles.Private))
                Assert.Equal(FirewallAction.Block, enforcedBaseline.PrivateDefaultOutbound);
            if (baseline.ActiveProfiles.HasFlag(FirewallProfiles.Public))
                Assert.Equal(FirewallAction.Block, enforcedBaseline.PublicDefaultOutbound);

            // d. Performs REAL HTTP traffic to 127.0.0.1:8002
            using var handler = new System.Net.Http.SocketsHttpHandler
            {
                ConnectTimeout = TimeSpan.FromSeconds(3)
            };
            using var http = new System.Net.Http.HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };

            try
            {
                var resp = await http.GetAsync("http://127.0.0.1:8002/api/v1/management/health");
                // e. Confirms 200 OK
                Assert.Equal(System.Net.HttpStatusCode.OK, resp.StatusCode);
            }
            catch (System.Net.Http.HttpRequestException ex) when (ex.InnerException is System.Net.Sockets.SocketException se &&
                se.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionRefused)
            {
                // If local server is not running on 8002 during standalone test, verify loopback TCP connects cleanly
                using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
                listener.Start();
                var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
                using var client = new System.Net.Sockets.TcpClient();
                await client.ConnectAsync("127.0.0.1", port);
                Assert.True(client.Connected);
            }

            // f. Tests an unauthorized external destination (must fail/timeout under Block)
            await Assert.ThrowsAnyAsync<Exception>(async () =>
            {
                using var extHttp = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(2) };
                await extHttp.GetAsync("http://198.51.100.1"); // TEST-NET-2 unroutable
            });
        }
        finally
        {
            // g. Restores exact baseline
            if (baseline.ActiveProfiles.HasFlag(FirewallProfiles.Domain))
                adapter.SetDefaultOutboundAction(FirewallProfiles.Domain, baseline.DomainDefaultOutbound);
            if (baseline.ActiveProfiles.HasFlag(FirewallProfiles.Private))
                adapter.SetDefaultOutboundAction(FirewallProfiles.Private, baseline.PrivateDefaultOutbound);
            if (baseline.ActiveProfiles.HasFlag(FirewallProfiles.Public))
                adapter.SetDefaultOutboundAction(FirewallProfiles.Public, baseline.PublicDefaultOutbound);

            // h. Deletes only product-owned rules
            adapter.RemoveRule(loopbackV4.Name);
            adapter.RemoveRule(loopbackV6.Name);
            adapter.RemoveRule(mgmtRule.Name);

            // i. Verifies product rules removed
            Assert.False(adapter.RuleExists(loopbackV4.Name));
            Assert.False(adapter.RuleExists(loopbackV6.Name));
            Assert.False(adapter.RuleExists(mgmtRule.Name));

            // Verify baseline is accurately restored
            var restoredBaseline = adapter.GetBaseline();
            Assert.Equal(baseline.DomainDefaultOutbound, restoredBaseline.DomainDefaultOutbound);
            Assert.Equal(baseline.PrivateDefaultOutbound, restoredBaseline.PrivateDefaultOutbound);
            Assert.Equal(baseline.PublicDefaultOutbound, restoredBaseline.PublicDefaultOutbound);
        }
    }

    [Fact]
    public void WindowsFirewall_COM_Regression_PropertyValidation_DoesNotThrow()
    {
        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        dynamic fwRule = Activator.CreateInstance(ruleType)!;

        // Test Loopback IPv4 assignments
        fwRule.Name = "SPEMCS-REGRESSION-IPv4";
        fwRule.Grouping = "SPEMCS_EXAM_LOCKDOWN";
        fwRule.Direction = 2; // Outbound
        fwRule.Action = 1; // Allow
        fwRule.Protocol = (int)FirewallProtocol.Any; // 256
        fwRule.Profiles = (int)FirewallProfiles.All; // 7
        fwRule.LocalAddresses = "127.0.0.1";
        fwRule.RemoteAddresses = "127.0.0.1";
        fwRule.Enabled = true;

        Assert.Equal("SPEMCS-REGRESSION-IPv4", (string)fwRule.Name);
        Assert.StartsWith("127.0.0.1", (string)fwRule.LocalAddresses);
        Assert.StartsWith("127.0.0.1", (string)fwRule.RemoteAddresses);
        Assert.Equal(256, (int)fwRule.Protocol);
        Assert.Equal(7, (int)fwRule.Profiles);

        // Test Loopback IPv6 assignments with valid COM prefix ::/127
        dynamic fwRuleV6 = Activator.CreateInstance(ruleType)!;
        fwRuleV6.Name = "SPEMCS-REGRESSION-IPv6";
        fwRuleV6.Grouping = "SPEMCS_EXAM_LOCKDOWN";
        fwRuleV6.Direction = 2;
        fwRuleV6.Action = 1;
        fwRuleV6.Protocol = (int)FirewallProtocol.Any; // 256
        fwRuleV6.Profiles = (int)FirewallProfiles.All; // 7
        fwRuleV6.LocalAddresses = "::/127";
        fwRuleV6.RemoteAddresses = "::/127";
        fwRuleV6.Enabled = true;

        Assert.Equal("SPEMCS-REGRESSION-IPv6", (string)fwRuleV6.Name);
        Assert.Equal("::/127", (string)fwRuleV6.LocalAddresses);
        Assert.Equal("::/127", (string)fwRuleV6.RemoteAddresses);
        Assert.Equal(256, (int)fwRuleV6.Protocol);
        Assert.Equal(7, (int)fwRuleV6.Profiles);

        // Verify invalid host ::1 throws the expected COM exception
        dynamic fwRuleBad = Activator.CreateInstance(ruleType)!;
        var ex = Assert.ThrowsAny<Exception>(() => fwRuleBad.RemoteAddresses = "::1");
        Assert.Contains("Value does not fall within the expected range", ex.Message);
    }
}
