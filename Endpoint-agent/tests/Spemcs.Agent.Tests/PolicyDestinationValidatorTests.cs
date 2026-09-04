using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Spemcs.Agent.Core.Network;
using Xunit;

namespace Spemcs.Agent.Tests;

/// <summary>
/// Drives <see cref="PolicyDestinationValidator"/> - the agent's independent re-check of an
/// already-signature-verified policy - against the corpus in
/// <see cref="AddressValidationFixtures"/>.
/// <para>
/// The expected verdicts in that fixture are not this validator's current behaviour recorded as
/// gospel. They are <c>backend/backend/services/policy_compiler.py</c>'s behaviour, established by
/// <c>Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py</c>, which
/// transliterates this validator and differential-tests the transliteration against the backend
/// over 4534 address strings. So a failure here means the agent and the backend disagree about what
/// a legal destination is, which is the only interesting way for this file to fail: agreement in
/// both directions is what makes the agent's check defense in depth rather than decoration. If the
/// agent were stricter, a correctly compiled policy would be rejected on exam day for no reason. If
/// it were laxer, it would not actually be backing anything up.
/// </para>
/// <para>
/// Two kinds of test live here on purpose. The corpus replays catch drift in bulk. The named facts
/// below them restate the requirements in their own terms - default-deny cannot be nullified
/// (requirement 1), only vendor destinations are reachable (requirement 2), destinations are
/// validated and normalized (requirement 3), IPv6 transition mechanisms are contained
/// (requirement 7) - so that deleting or regenerating the fixture cannot quietly delete the
/// requirement along with it.
/// </para>
/// </summary>
public sealed class PolicyDestinationValidatorTests
{
    private const string GoodRange = "203.0.113.0/24";

    private static readonly string[] OneGoodRange = { GoodRange };
    private static readonly string[] NoRanges = Array.Empty<string>();
    private static readonly string[] GoodThenDefaultRouteThenLoopback =
        { GoodRange, "0.0.0.0/0", "127.0.0.0/8" };

    /// <summary>
    /// Every literal in the validator's own forbidden tables, restated here independently. The
    /// reason each is refused differs - some overlap a forbidden range, some are simply broader
    /// than the widest allowed prefix - so this asserts only refusal.
    /// </summary>
    private static readonly string[] ForbiddenRangeLiterals =
    {
        "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128", "::1/128", "fe80::/10", "ff00::/8", "::ffff:0:0/96", "2002::/16", "2001::/32"
    };

    /// <summary>
    /// Destinations a real exam policy contains. Listed so that a change which tightens the
    /// validator into uselessness fails loudly instead of looking like extra security.
    /// </summary>
    private static readonly string[] LegitimateDestinations =
    {
        "203.0.113.0/24",   // a vendor's public range
        "8.8.8.8/32",       // a single public host
        "52.94.0.0/16",     // a cloud-hosted exam platform
        "10.0.0.0/8",       // an on-premises deployment, at the widest allowed IPv4 prefix
        "172.16.0.0/12",
        "192.168.1.0/24",
        "2001:db8::/32",    // IPv6 at the widest allowed prefix
        "2600:1f18::/32",
        "fd12:3456::/32"    // unique-local IPv6, which is not link-local and not multicast
    };

    private static readonly char[] ForbiddenNameCharacters = { '|', '"', '\'', '`', '\\', '/' };

    // =========================================================================
    // 1. Corpus replay - does the agent agree with the backend?
    // =========================================================================

    [Fact]
    public void EveryDestinationAddressInTheCorpus_GetsTheBackendsVerdict()
    {
        var mismatches = new List<string>();

        foreach (var (value, expectedAllowed) in AddressValidationFixtures.DestinationAddresses)
        {
            var problem = PolicyDestinationValidator.DescribeUnsafeAddress(value);
            var actuallyAllowed = problem is null;

            if (actuallyAllowed != expectedAllowed)
            {
                mismatches.Add(expectedAllowed
                    ? $"  '{value}': backend allows it, agent refused it - '{problem}'"
                    : $"  '{value}': backend refuses it, agent allowed it");
            }
        }

        Assert.True(
            mismatches.Count == 0,
            Summarize(
                mismatches,
                AddressValidationFixtures.DestinationAddresses.Length,
                "destination ip_ranges entries"));
    }

    [Fact]
    public void EveryManagementAddressInTheCorpus_GetsTheBackendsVerdict()
    {
        var mismatches = new List<string>();

        foreach (var (value, expectedAllowed) in AddressValidationFixtures.ManagementAddresses)
        {
            var problem = PolicyDestinationValidator.DescribeUnsafeManagementAddress(value);
            var actuallyAllowed = problem is null;

            if (actuallyAllowed != expectedAllowed)
            {
                mismatches.Add(expectedAllowed
                    ? $"  '{value}': should be usable as a management address, agent refused it - '{problem}'"
                    : $"  '{value}': must not be usable as a management address, agent allowed it");
            }
        }

        Assert.True(
            mismatches.Count == 0,
            Summarize(
                mismatches,
                AddressValidationFixtures.ManagementAddresses.Length,
                "management_server.ip_addresses entries"));
    }

    [Fact]
    public void EveryDestinationNameInTheCorpus_GetsTheBackendsVerdict()
    {
        var mismatches = new List<string>();

        foreach (var (value, expectedAllowed) in AddressValidationFixtures.DestinationNames)
        {
            var problem = PolicyDestinationValidator.DescribeUnsafeName(value);
            var actuallyAllowed = problem is null;

            if (actuallyAllowed != expectedAllowed)
            {
                mismatches.Add(expectedAllowed
                    ? $"  '{Printable(value)}': backend allows this name, agent refused it - '{problem}'"
                    : $"  '{Printable(value)}': backend refuses this name, agent allowed it");
            }
        }

        Assert.True(
            mismatches.Count == 0,
            Summarize(
                mismatches,
                AddressValidationFixtures.DestinationNames.Length,
                "destination names"));
    }

    /// <summary>
    /// Cases where several rules would all reject the input and only the most specific message is
    /// useful to an operator. Asserting the message, not just the verdict, is what stops a narrower
    /// branch from being deleted unnoticed because a broader one happens to catch the same input.
    /// </summary>
    [Fact]
    public void RejectionMessages_NameTheSpecificRuleThatFired()
    {
        var wrong = new List<string>();

        foreach (var (value, expectedFragment) in AddressValidationFixtures.RejectionReasons)
        {
            var problem = PolicyDestinationValidator.DescribeUnsafeAddress(value);

            if (problem is null)
            {
                wrong.Add($"  '{value}': expected refusal mentioning '{expectedFragment}', was allowed");
            }
            else if (!problem.Contains(expectedFragment, StringComparison.Ordinal))
            {
                wrong.Add($"  '{value}': expected '{expectedFragment}' in the reason, got '{problem}'");
            }
        }

        Assert.True(
            wrong.Count == 0,
            Summarize(wrong, AddressValidationFixtures.RejectionReasons.Length, "reason assertions"));
    }

    /// <summary>
    /// The replays above are only as good as the corpus they replay. An empty or single-verdict
    /// fixture would make all three of them pass while proving nothing, and the fixture is produced
    /// by a script - so the floors below assert the corpus still has enough of both verdicts to be
    /// capable of failing. They are floors rather than exact counts so that regenerating with a
    /// larger corpus is not a test failure.
    /// </summary>
    [Fact]
    public void TheCorpusItself_StillContainsEnoughOfBothVerdictsToBeCapableOfFailing()
    {
        var addresses = AddressValidationFixtures.DestinationAddresses;
        Assert.True(addresses.Length >= 500, $"destination corpus shrank to {addresses.Length} cases");
        Assert.True(
            addresses.Count(c => !c.Allowed) >= 300,
            $"only {addresses.Count(c => !c.Allowed)} refused cases; the corpus has stopped exercising the rules");
        Assert.True(
            addresses.Count(c => c.Allowed) >= 100,
            $"only {addresses.Count(c => c.Allowed)} allowed cases; a validator that refuses everything would pass");

        var management = AddressValidationFixtures.ManagementAddresses;
        Assert.True(management.Length >= 12, $"management corpus shrank to {management.Length} cases");
        Assert.True(management.Count(c => c.Allowed) >= 4, "management corpus has too few accepted cases");
        Assert.True(management.Count(c => !c.Allowed) >= 6, "management corpus has too few refused cases");

        var names = AddressValidationFixtures.DestinationNames;
        Assert.True(names.Length >= 15, $"name corpus shrank to {names.Length} cases");
        Assert.True(names.Count(c => c.Allowed) >= 5, "name corpus has too few accepted cases");
        Assert.True(names.Count(c => !c.Allowed) >= 8, "name corpus has too few refused cases");

        Assert.True(
            AddressValidationFixtures.RejectionReasons.Length >= 10,
            "reason assertions have been thinned out");
    }

    // =========================================================================
    // 2. Requirement 1 - nothing may nullify default-deny
    // =========================================================================

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    public void TheDefaultRoute_IsRefusedAndSaidSo(string defaultRoute)
    {
        var problem = PolicyDestinationValidator.DescribeUnsafeAddress(defaultRoute);

        Assert.NotNull(problem);

        // Reported as nullifying default-deny rather than merely as "too broad", because those are
        // different operator problems: one is a policy that would re-open the internet while every
        // signature check passed, the other is a prefix that needs narrowing.
        Assert.Contains("nullify default-deny", problem);
    }

    [Fact]
    public void HalfTheInternet_IsRefusedEvenThoughItDoesNotMatchEveryAddress()
    {
        // 128.0.0.0/1 is the obvious way around a check that only looks for /0.
        var problem = PolicyDestinationValidator.DescribeUnsafeAddress("128.0.0.0/1");

        Assert.NotNull(problem);
        Assert.Contains("widest allowed IPv4 prefix", problem);
    }

    [Fact]
    public void PrefixesAtTheWidestAllowedBoundary_AreStillAccepted()
    {
        // The boundary is inclusive on purpose: a legitimate on-premises 10.0.0.0/8 has to work.
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeAddress(
            $"10.0.0.0/{PolicyDestinationValidator.MinPrefixV4.ToString(CultureInfo.InvariantCulture)}"));
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeAddress(
            $"2001:db8::/{PolicyDestinationValidator.MinPrefixV6.ToString(CultureInfo.InvariantCulture)}"));

        Assert.NotNull(PolicyDestinationValidator.DescribeUnsafeAddress("10.0.0.0/7"));
        Assert.NotNull(PolicyDestinationValidator.DescribeUnsafeAddress("2000::/31"));
    }

    // =========================================================================
    // 3. Requirement 2/3 - only real destinations, validated and normalized
    // =========================================================================

    [Fact]
    public void EveryForbiddenRangeLiteral_IsRefusedAsItself()
    {
        var allowed = ForbiddenRangeLiterals
            .Where(cidr => PolicyDestinationValidator.DescribeUnsafeAddress(cidr) is null)
            .ToList();

        Assert.True(
            allowed.Count == 0,
            $"these ranges must never become an allow rule: {string.Join(", ", allowed)}");
    }

    [Fact]
    public void EveryLegitimateDestination_IsAccepted()
    {
        var refused = LegitimateDestinations
            .Select(cidr => (Cidr: cidr, Problem: PolicyDestinationValidator.DescribeUnsafeAddress(cidr)))
            .Where(x => x.Problem is not null)
            .Select(x => $"  '{x.Cidr}': {x.Problem}")
            .ToList();

        // A validator that refuses everything satisfies requirement 1 and fails the exam.
        Assert.True(
            refused.Count == 0,
            $"{refused.Count.ToString(CultureInfo.InvariantCulture)} legitimate destinations were " +
            "refused, which would break a correctly compiled policy:" +
            Environment.NewLine + string.Join(Environment.NewLine, refused));
    }

    /// <summary>
    /// Containment is tested as overlap, not membership. A membership-only check ("is the candidate
    /// inside a forbidden range?") gets these three wrong: each is a supernet whose own base address
    /// is unremarkable, but which spans a forbidden range entirely.
    /// </summary>
    [Theory]
    [InlineData("169.252.0.0/14", "169.254.0.0/16")]
    [InlineData("169.128.0.0/9", "169.254.0.0/16")]
    [InlineData("::fffe:0:0/95", "::ffff:0:0/96")]
    public void ASupernetOfAForbiddenRange_IsRefusedAndNamesTheRangeItSpans(
        string supernet, string spannedRange)
    {
        var problem = PolicyDestinationValidator.DescribeUnsafeAddress(supernet);

        Assert.NotNull(problem);

        // Naming the spanned range proves the overlap branch fired rather than the min-prefix
        // branch, which would reject these for an unrelated reason and hide the bug.
        Assert.Contains($"overlaps {spannedRange}", problem);
    }

    [Fact]
    public void CloudInstanceMetadata_IsRefused()
    {
        var problem = PolicyDestinationValidator.DescribeUnsafeAddress("169.254.169.254/32");

        Assert.NotNull(problem);
        Assert.Contains("169.254.0.0/16", problem);
    }

    [Fact]
    public void TheLocalDnsStub_IsRefused()
    {
        // 127.0.0.53 is systemd-resolved's stub; more generally a loopback destination cannot leave
        // the machine, so an allow rule for one only ever widens what a local listener can be
        // reached through. Requirement 8 is why this one is called out by name.
        var problem = PolicyDestinationValidator.DescribeUnsafeAddress("127.0.0.53/32");

        Assert.NotNull(problem);
        Assert.Contains("127.0.0.0/8", problem);
    }

    [Fact]
    public void AnUnmaskedRange_IsRefusedAsAmbiguous()
    {
        // 192.168.1.5/24 could mean the host or the network; netsh would silently pick one. The
        // backend normalizes such text with ipaddress.ip_network(strict=False) before signing, so
        // the agent never sees this from a healthy backend - which is exactly why seeing it is
        // worth refusing rather than quietly masking.
        var problem = PolicyDestinationValidator.DescribeUnsafeAddress("192.168.1.5/24");

        Assert.NotNull(problem);
        Assert.Contains("bits set below its prefix length", problem);
    }

    [Theory]
    [InlineData("010.0.0.1/32")]  // leading zero: octal to some parsers, decimal to others
    [InlineData("10/8")]          // shorthand: 0.0.0.10 to IPAddress.TryParse
    [InlineData("1.2.3/24")]      // shorthand: 1.2.0.3
    public void NonCanonicalIpv4Notation_IsRefused(string value)
    {
        // None of these produce a dangerous rule. They produce a rule whose address is not the text
        // in the audit log, which makes the log useless for proving what was allowed.
        Assert.NotNull(PolicyDestinationValidator.DescribeUnsafeAddress(value));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("*")]
    [InlineData("any")]
    [InlineData("not-an-ip")]
    [InlineData("203.0.113.5-203.0.113.9")]
    [InlineData("203.0.113.5:443")]
    [InlineData("203.0.113.5/33")]
    [InlineData("203.0.113.5/-1")]
    [InlineData("203.0.113.5/")]
    [InlineData("203.0.113.5/x")]
    [InlineData("2001:db8::1/129")]
    public void UnparseableText_IsRefusedRatherThanPassedThroughToNetsh(string value)
    {
        // "*" and "any" matter most here: netsh reads either as a remote-address wildcard, so a
        // range that fails to parse must never reach the rule builder.
        Assert.NotNull(PolicyDestinationValidator.DescribeUnsafeAddress(value));
    }

    [Fact]
    public void SurroundingWhitespace_IsToleratedAndTheReportedAddressIsTrimmed()
    {
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeAddress($" {GoodRange} "));

        var problem = PolicyDestinationValidator.DescribeUnsafeAddress(" 0.0.0.0/0 ");
        Assert.NotNull(problem);

        // The address in the message is the address that would have gone into the rule.
        Assert.Contains("'0.0.0.0/0'", problem);
    }

    // =========================================================================
    // 4. Requirement 7 - IPv6 containment, including transition mechanisms
    // =========================================================================

    [Theory]
    [InlineData("2002:c000:204::/48", "2002::/16")]                            // 6to4
    [InlineData("2001:0:53aa:64c::/64", "2001::/32")]                          // Teredo
    [InlineData("::ffff:8.8.8.8/128", "::ffff:0:0/96")]                        // IPv4-mapped
    public void AnIpv6TransitionRange_IsRefusedSoTrafficCannotLeaveInsideATunnel(
        string value, string forbiddenRange)
    {
        var problem = PolicyDestinationValidator.DescribeUnsafeAddress(value);

        Assert.NotNull(problem);
        Assert.Contains(forbiddenRange, problem);
    }

    [Fact]
    public void OrdinaryGlobalIpv6_IsNotCaughtByTheTransitionRules()
    {
        // 2001:db8::/32 sits next to Teredo's 2001::/32 and must not be confused with it; a check
        // that compared too few bits would refuse the documentation range and every 2001:: network.
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeAddress("2001:db8::/32"));
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeAddress("2003::/32"));
    }

    // =========================================================================
    // 5. TryValidate - what PolicyReceiver actually calls
    // =========================================================================

    [Fact]
    public void TryValidate_AcceptsAWellFormedDestination()
    {
        var ok = PolicyDestinationValidator.TryValidate(0, "vendor", OneGoodRange, out var rejection);

        Assert.True(ok, rejection);
        Assert.Null(rejection);
    }

    [Fact]
    public void TryValidate_RefusesADestinationWithNoRanges()
    {
        // Not a harmless no-op: it produces no rule, so the browser silently cannot reach a
        // destination the policy says is allowed and nothing in the logs explains why.
        var ok = PolicyDestinationValidator.TryValidate(3, "vendor", NoRanges, out var rejection);

        Assert.False(ok);
        Assert.NotNull(rejection);
        Assert.Contains("allowed_destinations[3]", rejection);
        Assert.Contains("vendor", rejection);
        Assert.Contains("no ip_ranges", rejection);
    }

    [Fact]
    public void TryValidate_NamesTheIndexAndTheDestinationSoAnOperatorCanFindTheEntry()
    {
        var ok = PolicyDestinationValidator.TryValidate(
            7, "moodle-primary", GoodThenDefaultRouteThenLoopback, out var rejection);

        Assert.False(ok);
        Assert.NotNull(rejection);
        Assert.Contains("allowed_destinations[7]", rejection);
        Assert.Contains("moodle-primary", rejection);
    }

    [Fact]
    public void TryValidate_StopsAtTheFirstBadRange()
    {
        var ok = PolicyDestinationValidator.TryValidate(
            0, "vendor", GoodThenDefaultRouteThenLoopback, out var rejection);

        Assert.False(ok);
        Assert.NotNull(rejection);
        Assert.Contains("0.0.0.0/0", rejection);

        // One reason, deterministically the first one, so two operators reading the same failure
        // see the same message.
        Assert.DoesNotContain("127.0.0.0/8", rejection);
    }

    [Fact]
    public void TryValidate_ChecksTheNameBeforeTheRanges()
    {
        // The name becomes the purpose segment of the firewall rule name, so it is checked first
        // and the failure names it - even though the ranges are also invalid.
        var ok = PolicyDestinationValidator.TryValidate(
            1, "bad|name", GoodThenDefaultRouteThenLoopback, out var rejection);

        Assert.False(ok);
        Assert.NotNull(rejection);
        Assert.Contains("allowed_destinations[1]", rejection);
        Assert.Contains("not allowed in a firewall rule name", rejection);
        Assert.DoesNotContain("nullify default-deny", rejection);
    }

    [Fact]
    public void TryValidate_RefusesANullName()
    {
        var ok = PolicyDestinationValidator.TryValidate(0, null, OneGoodRange, out var rejection);

        Assert.False(ok);
        Assert.NotNull(rejection);
        Assert.Contains("destination name is empty", rejection);
    }

    // =========================================================================
    // 6. The management address rules, which are deliberately different
    // =========================================================================

    /// <summary>
    /// The management allow rule is the one rule in the set that is not scoped to a program - the
    /// channel belongs to the agent service, not the browser - so any process on the machine could
    /// use it. Its narrowness rests entirely on the address being one host and the port one port.
    /// </summary>
    [Theory]
    [InlineData("203.0.113.0/24")]
    [InlineData("2001:db8::/64")]
    [InlineData("0.0.0.0/0")]
    public void AManagementAddressMustBeExactlyOneHost(string range)
    {
        var problem = PolicyDestinationValidator.DescribeUnsafeManagementAddress(range);

        Assert.NotNull(problem);
        Assert.Contains("is a range, not a single host", problem);
    }

    [Fact]
    public void ASingleHostIsAcceptedAsAManagementAddress_WithOrWithoutAnExplicitPrefix()
    {
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeManagementAddress("203.0.113.5"));
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeManagementAddress("203.0.113.5/32"));
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeManagementAddress("2001:db8::5"));
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeManagementAddress("2001:db8::5/128"));
    }

    /// <summary>
    /// The asymmetry between the two rule sets is intentional and is pinned here so that anyone
    /// tempted to unify them has to read this first. Loopback and private addresses are legitimate
    /// management servers - single-box deployments and the development harness use them - but they
    /// are not destinations: an allow rule to loopback cannot carry exam traffic anywhere.
    /// </summary>
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public void Loopback_IsAValidManagementAddressButNeverAValidDestination(string loopback)
    {
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeManagementAddress(loopback));
        Assert.NotNull(PolicyDestinationValidator.DescribeUnsafeAddress(loopback));
    }

    [Fact]
    public void APrivateAddress_IsAValidManagementAddress()
    {
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeManagementAddress("10.4.1.9"));
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeManagementAddress("192.168.7.20"));
    }

    [Theory]
    [InlineData("0.0.0.0", "unspecified")]
    [InlineData("255.255.255.255", "broadcast")]
    [InlineData("224.0.0.1", "multicast or reserved")]
    [InlineData("239.255.255.250", "multicast or reserved")]
    [InlineData("ff02::1", "multicast or reserved")]
    public void AnUnroutableManagementAddress_IsRefusedForTheRightReason(
        string value, string expectedFragment)
    {
        var problem = PolicyDestinationValidator.DescribeUnsafeManagementAddress(value);

        Assert.NotNull(problem);

        // Asserting the reason keeps the broadcast branch alive: 255.255.255.255 is also caught by
        // the multicast/reserved test that follows it, so a verdict-only assertion would let the
        // more specific check be deleted without any test noticing.
        Assert.Contains(expectedFragment, problem);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("any")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("203.0.113.5:8443")]
    [InlineData("management.example.edu")]
    public void UnparseableManagementText_IsRefused(string value)
    {
        Assert.NotNull(PolicyDestinationValidator.DescribeUnsafeManagementAddress(value));
    }

    // =========================================================================
    // 7. Destination names, which become part of a firewall rule name
    // =========================================================================

    [Fact]
    public void EachForbiddenNameCharacter_IsRefusedIndividually()
    {
        var accepted = new List<string>();

        foreach (var c in ForbiddenNameCharacters)
        {
            var name = $"vendor{c.ToString()}name";
            var problem = PolicyDestinationValidator.DescribeUnsafeName(name);

            if (problem is null)
            {
                accepted.Add($"'{c.ToString()}'");
            }
            else if (!problem.Contains($"contains '{c.ToString()}'", StringComparison.Ordinal))
            {
                accepted.Add($"'{c.ToString()}' (refused, but the reason did not name it: {problem})");
            }
        }

        // Looping every character means removing any single entry from the validator's table fails
        // this test, which a hand-picked example or two would not guarantee.
        Assert.True(
            accepted.Count == 0,
            $"these characters must not survive into a rule name: {string.Join(", ", accepted)}");
    }

    [Fact]
    public void NameLength_IsBoundedAtMaxNameLengthInclusive()
    {
        var atLimit = new string('a', PolicyDestinationValidator.MaxNameLength);
        var overLimit = new string('a', PolicyDestinationValidator.MaxNameLength + 1);

        Assert.Null(PolicyDestinationValidator.DescribeUnsafeName(atLimit));

        var problem = PolicyDestinationValidator.DescribeUnsafeName(overLimit);
        Assert.NotNull(problem);
        Assert.Contains(
            PolicyDestinationValidator.MaxNameLength.ToString(CultureInfo.InvariantCulture),
            problem);
    }

    [Theory]
    [InlineData("ctrl\u0001name")]
    [InlineData("del\u007Fname")]
    [InlineData("tab\tinside")]
    [InlineData("newline\ninside")]
    [InlineData("cr\rinside")]
    public void AnInteriorControlCharacter_IsRefused(string name)
    {
        // Interior, not leading or trailing: Trim() removes the easy cases, and a newline in the
        // middle of a rule name is what would corrupt the netsh output an operator reads.
        var problem = PolicyDestinationValidator.DescribeUnsafeName(name);

        Assert.NotNull(problem);
        Assert.Contains("control characters", problem);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void AnEffectivelyEmptyName_IsRefused(string? name)
    {
        var problem = PolicyDestinationValidator.DescribeUnsafeName(name);

        Assert.NotNull(problem);
        Assert.Contains("empty", problem);
    }

    [Theory]
    [InlineData("vendor")]
    [InlineData("moodle-primary")]
    [InlineData("Moodle Primary")]
    [InlineData("dot.name")]
    [InlineData("unicode-é")]
    [InlineData("  trimmed  ")]
    public void AnOrdinaryName_IsAccepted(string name)
    {
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeName(name));
    }

    // =========================================================================
    // 8. The validator's own literals have to parse under its own parser
    // =========================================================================

    [Fact]
    public void TypeInitialization_ParsesEveryForbiddenRangeLiteralInTheValidator()
    {
        // ForbiddenRange's constructor throws if one of the validator's own CIDR literals does not
        // parse under the validator's own parser - a build-time defect that would otherwise surface
        // at runtime as a TypeInitializationException inside the policy receive loop, on exam day.
        // Touching the type at all forces static initialization, so this call is the whole test.
        // The Python harness asserts the same property against the literals it transliterated.
        Assert.Null(PolicyDestinationValidator.DescribeUnsafeAddress(GoodRange));
    }

    // =========================================================================

    private static string Summarize(List<string> failures, int total, string what)
    {
        if (failures.Count == 0)
        {
            return string.Empty;
        }

        const int shown = 25;
        var header =
            $"{failures.Count.ToString(CultureInfo.InvariantCulture)} of " +
            $"{total.ToString(CultureInfo.InvariantCulture)} {what} disagree with " +
            "backend/backend/services/policy_compiler.py. Regenerate the fixture " +
            "(verify_policy_destination_validator_parity.py --emit-fixture) only after confirming " +
            "the backend is the side that changed:";

        var body = string.Join(Environment.NewLine, failures.Take(shown));
        var more = failures.Count > shown
            ? Environment.NewLine +
              $"  ... and {(failures.Count - shown).ToString(CultureInfo.InvariantCulture)} more"
            : string.Empty;

        return header + Environment.NewLine + body + more;
    }

    /// <summary>Renders control characters visibly so a failure message is readable.</summary>
    private static string Printable(string value)
    {
        var builder = new System.Text.StringBuilder(value.Length);

        foreach (var c in value)
        {
            if (c < 0x20 || c == 0x7F)
            {
                builder.Append("\\u")
                       .Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
            }
            else
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }
}
