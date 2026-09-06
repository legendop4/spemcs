using System;
using System.IO;
using System.Threading.Tasks;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// Pins the address-set comparison that <c>NetworkEnforcer.LogAndVerifyRules</c> depends on.
/// The positive cases are the exact rewrites Windows Defender Firewall performs on readback,
/// captured from a detached HNetCfg.FWRule COM object; the negative cases exist so the
/// canonicaliser cannot decay into something that calls every pair of addresses equivalent.
/// </summary>
public class FirewallAddressSpecTests
{
    [Theory]
    [InlineData("192.168.250.0/24", "192.168.250.0/255.255.255.0")]
    [InlineData("10.0.0.0/8", "10.0.0.0/255.0.0.0")]
    [InlineData("127.0.0.1", "127.0.0.1/255.255.255.255")]
    [InlineData("198.51.100.7", "198.51.100.7/32")]
    [InlineData("2001:db8:cafe:1234::/64", "2001:db8:cafe:1234::/64")]
    [InlineData("::/127", "::/127")]
    [InlineData("2001:db8::1", "2001:db8::1-2001:db8::1")]
    [InlineData("2001:DB8::1/128", "2001:db8::1/128")]
    [InlineData("*", "*")]
    [InlineData("LocalSubnet", "localsubnet")]
    [InlineData("192.168.250.0/24,203.0.113.0/24", "203.0.113.0/255.255.255.0,192.168.250.0/255.255.255.0")]
    public void EquivalentSpecifications_AreRecognised(string expected, string actual)
    {
        Assert.True(
            FirewallAddressSpec.AreEquivalent(expected, actual),
            $"'{expected}' and '{actual}' denote the same addresses but were reported as different");
    }

    [Theory]
    [InlineData("192.168.250.0/24", "192.168.250.0/255.255.0.0")]
    [InlineData("192.168.250.0/24", "192.168.251.0/255.255.255.0")]
    [InlineData("127.0.0.1", "127.0.0.2/255.255.255.255")]
    [InlineData("198.51.100.7", "198.51.100.7/24")]
    [InlineData("2001:db8:cafe:1234::/64", "2001:db8:cafe:1234::/63")]
    [InlineData("::/127", "::/128")]
    [InlineData("192.168.250.0/24", "*")]
    [InlineData("192.168.250.0/24", "192.168.250.0/24,203.0.113.0/24")]
    [InlineData("LocalSubnet", "DefaultGateway")]
    // 255.0.255.0 is not a prefix. Reading it as one via a population count would call it /16 and
    // silently accept a rule covering addresses that were never approved.
    [InlineData("192.168.250.0/24", "192.168.250.0/255.0.255.0")]
    public void DifferentSpecifications_AreNotConflated(string expected, string actual)
    {
        Assert.False(
            FirewallAddressSpec.AreEquivalent(expected, actual),
            $"'{expected}' and '{actual}' denote different addresses but were reported as equivalent");
    }

    /// <summary>
    /// The defect this guards is not a test-expectation problem: <c>LogAndVerifyRules</c> compares
    /// every installed rule against its readback and throws on any mismatch, before the default
    /// outbound block is applied. With a literal comparison, the loopback IPv4 rule ("127.0.0.1"
    /// read back as "127.0.0.1/255.255.255.255") and every policy destination expressed as IPv4
    /// CIDR fail that check, so enforcement aborts on a real host and no exam can ever arm.
    /// The suite missed it because MockFirewallAdapter echoes addresses back verbatim.
    /// </summary>
    [Fact]
    public async Task Enforcement_Succeeds_WhenTheFirewallReturnsAddressesInItsOwnRepresentation()
    {
        var testDir = Path.Combine(Path.GetTempPath(), "spemcs-addrspec-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);

        try
        {
            var firewall = new MockFirewallAdapter { SimulateWindowsAddressNormalization = true };
            var journal = new SqliteRollbackJournal(testDir);
            var enforcer = new NetworkEnforcer(firewall, journal);

            var sessionId = Guid.NewGuid();
            var session = new EnforcementSession(
                SessionId: sessionId,
                PolicyId: Guid.NewGuid(),
                PolicyVersion: 1,
                Rules: new[]
                {
                    FirewallRuleModel.CreateLoopbackIPv4Allow(sessionId),
                    FirewallRuleModel.CreateLoopbackIPv6Allow(sessionId),
                    FirewallRuleModel.CreateOutboundAllow(sessionId, "Vendor", FirewallProtocol.TCP, "198.51.100.0/24", "443"),
                    FirewallRuleModel.CreateOutboundAllow(sessionId, "Mgmt", FirewallProtocol.TCP, "198.51.100.7", "8002"),
                },
                TargetProfiles: FirewallProfiles.Private | FirewallProfiles.Public,
                CreatedUtc: DateTimeOffset.UtcNow
            );

            var result = await enforcer.ApplyEnforcementAsync(session);

            Assert.True(result.Success, $"Enforcement failed against a normalising firewall: {result.ErrorMessage}");
            Assert.Equal(EnforcementPhase.Active, result.Phase);
            Assert.Equal(4, result.RulesInstalledCount);
            Assert.Equal(FirewallAction.Block, firewall.PrivateDefaultOutbound);
            Assert.Equal(FirewallAction.Block, firewall.PublicDefaultOutbound);
        }
        finally
        {
            try { Directory.Delete(testDir, recursive: true); } catch (IOException) { }
        }
    }

    /// <summary>
    /// Proves the test above is not vacuous: the simulated firewall really does hand back a
    /// different string from the one it was given, so a literal comparison would have failed.
    /// </summary>
    [Fact]
    public void TheSimulatedFirewallActuallyRewritesAddresses()
    {
        var sessionId = Guid.NewGuid();
        var firewall = new MockFirewallAdapter { SimulateWindowsAddressNormalization = true };
        var rule = FirewallRuleModel.CreateOutboundAllow(sessionId, "Vendor", FirewallProtocol.TCP, "198.51.100.0/24", "443");

        firewall.AddRule(rule);
        var readback = Assert.Single(firewall.GetRulesByGroup(FirewallRuleModel.SpemcsRuleGroup));

        Assert.NotEqual(rule.RemoteAddresses, readback.RemoteAddresses);
        Assert.Equal("198.51.100.0/255.255.255.0", readback.RemoteAddresses);
        Assert.True(FirewallAddressSpec.AreEquivalent(rule.RemoteAddresses, readback.RemoteAddresses));
    }
}
