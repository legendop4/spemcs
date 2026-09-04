using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Independently re-validates the addresses of an already-signature-verified policy.
/// <para>
/// This is defense in depth, and it is deliberately redundant with
/// <c>backend/backend/services/policy_compiler.py</c>. A valid signature proves a policy came from
/// the management server; it does not prove the management server was right. The endpoint is where
/// the consequence lands: <see cref="EnforcementStateMachine"/> turns every entry of
/// <see cref="PolicyDestination.IpRanges"/> straight into a Windows Firewall outbound allow rule,
/// so a single <c>0.0.0.0/0</c> in a signed policy would re-open the entire internet to the
/// examination browser while every cryptographic and schema check still passed.
/// </para>
/// <para>
/// The agent therefore refuses to build rules it can tell are wrong, rather than trusting that the
/// backend already checked. That matters in three situations a signature cannot distinguish from a
/// legitimate policy: a compromised or misconfigured backend, a backend rolled back to a build
/// predating the compiler-side checks, and a stolen signing key.
/// </para>
/// <para>
/// The rules here are the rules the backend applies, so a policy the backend produced correctly
/// always passes. Rejection means the two sides disagree, which is a condition an operator has to
/// see - hence <see cref="PolicyAcceptanceStatus.PolicyInvalid"/> naming the field and the reason,
/// never a silent drop of the offending range. Dropping it would leave the exam running under an
/// allowlist neither side intended.
/// </para>
/// <para>
/// The address arithmetic below is written against <see cref="IPAddress.GetAddressBytes"/> rather
/// than <c>System.Net.IPNetwork</c> so that this file carries no dependency on a specific BCL
/// version, and so that the containment rule is visible and testable rather than delegated.
/// </para>
/// Kept in sync with policy_compiler.py :: describe_unsafe_network / validate_destination_name.
/// That claim is enforced by <c>Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py</c>,
/// which transliterates the logic below and differential-tests it against the backend over a
/// several-thousand-case corpus, and by <c>AddressValidationFixtures.cs</c>, which drives this
/// class against the same corpus from xunit.
/// <para>
/// Public rather than internal so the test project can reach it: this solution sets no
/// InternalsVisibleTo, and a security check that cannot be unit-tested directly is worse than a
/// slightly wider API surface on an internal-use library.
/// </para>
/// </summary>
public static class PolicyDestinationValidator
{
    /// <summary>
    /// A prefix shorter than this describes a region of the internet, not a destination.
    /// /8 stays permissive enough for a legitimate on-premises 10.0.0.0/8 while rejecting
    /// 0.0.0.0/0 and 128.0.0.0/1.
    /// </summary>
    public const int MinPrefixV4 = 8;

    public const int MinPrefixV6 = 32;

    /// <summary>
    /// Destination names become the <c>purpose</c> segment of the firewall rule name
    /// (<c>SPEMCS-{session}-{purpose}-{hash}</c>), so a name has to be safe to write into one.
    /// </summary>
    public const int MaxNameLength = 64;

    /// <summary>
    /// <c>|</c> is the field delimiter in the firewall rule registry representation; the quote and
    /// slash characters break netsh argument quoting and path parsing.
    /// </summary>
    private static readonly char[] ForbiddenNameChars = { '|', '"', '\'', '`', '\\', '/' };

    /// <summary>Refused as a destination unconditionally, wherever the address came from.</summary>
    private static readonly ForbiddenRange[] ForbiddenV4 =
    {
        new("0.0.0.0/8", "the unspecified/this-network range"),
        new("127.0.0.0/8", "loopback, which cannot leave the machine and is not a destination"),
        new("169.254.0.0/16", "link-local, which includes the cloud instance metadata address 169.254.169.254"),
        new("224.0.0.0/4", "multicast"),
        new("240.0.0.0/4", "reserved"),
        new("255.255.255.255/32", "the broadcast address")
    };

    /// <summary>
    /// The last two entries carry requirement 7 (IPv6 containment): 6to4 and Teredo are address
    /// transition mechanisms, so allowing either range would let IPv6 traffic leave the machine
    /// inside an IPv4 tunnel that the IPv4 rules never inspect.
    /// </summary>
    private static readonly ForbiddenRange[] ForbiddenV6 =
    {
        new("::/128", "the unspecified address"),
        new("::1/128", "loopback, which cannot leave the machine and is not a destination"),
        new("fe80::/10", "link-local"),
        new("ff00::/8", "multicast"),
        new("::ffff:0:0/96", "an IPv4-mapped IPv6 range; express IPv4 destinations as IPv4 so the resulting firewall rule is unambiguous"),
        new("2002::/16", "the 6to4 tunnel range (requirement 7 contains transition mechanisms)"),
        new("2001::/32", "the Teredo tunnel range (requirement 7 contains transition mechanisms)")
    };

    /// <summary>
    /// Validates one entry of <c>allowed_destinations</c>. True when it is safe to build rules from.
    /// </summary>
    /// <param name="index">Position in the array, so the error names the offending entry.</param>
    /// <param name="name">Destination name from the signed payload.</param>
    /// <param name="ipRanges">The <c>ip_ranges</c> entries from the signed payload.</param>
    /// <param name="rejection">Operator-facing reason; null when this returns true.</param>
    public static bool TryValidate(
        int index,
        string? name,
        IReadOnlyList<string> ipRanges,
        out string? rejection)
    {
        var nameProblem = DescribeUnsafeName(name);
        if (nameProblem is not null)
        {
            rejection = $"allowed_destinations[{index}]: {nameProblem}";
            return false;
        }

        // A destination with no ranges produces no rule at all. That is not a harmless no-op: the
        // browser would silently be unable to reach a destination the policy says is allowed, and
        // the exam would fail with nothing in the logs pointing at the cause.
        if (ipRanges.Count == 0)
        {
            rejection = $"allowed_destinations[{index}] ('{name}') carries no ip_ranges, so it " +
                        "would produce no firewall rule and the destination would be unreachable";
            return false;
        }

        for (var i = 0; i < ipRanges.Count; i++)
        {
            var addressProblem = DescribeUnsafeAddress(ipRanges[i]);
            if (addressProblem is not null)
            {
                rejection = $"allowed_destinations[{index}] ('{name}'): {addressProblem}";
                return false;
            }
        }

        rejection = null;
        return true;
    }

    /// <summary>
    /// Returns why <paramref name="value"/> may not become an allow rule, or null if it may.
    /// </summary>
    public static string? DescribeUnsafeAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "an empty address range";
        }

        var trimmed = value.Trim();

        if (!TryParseCidr(trimmed, out var candidate, out var parseError))
        {
            return $"address range '{trimmed}' {parseError}";
        }

        if (candidate.PrefixLength == 0)
        {
            return $"address range '{trimmed}' matches every address, which would nullify default-deny";
        }

        var family = candidate.IsV4 ? "IPv4" : "IPv6";
        var minimum = candidate.IsV4 ? MinPrefixV4 : MinPrefixV6;
        if (candidate.PrefixLength < minimum)
        {
            return $"address range '{trimmed}' is broader than the widest allowed {family} " +
                   $"prefix (/{minimum})";
        }

        var forbidden = candidate.IsV4 ? ForbiddenV4 : ForbiddenV6;
        for (var i = 0; i < forbidden.Length; i++)
        {
            if (Overlaps(candidate, forbidden[i].Range))
            {
                return $"address range '{trimmed}' overlaps {forbidden[i].Cidr}, " +
                       $"which is {forbidden[i].Reason}";
            }
        }

        return null;
    }

    /// <summary>
    /// Returns why <paramref name="value"/> may not be used as a management server address, or
    /// null if it may.
    /// <para>
    /// A different rule set from <see cref="DescribeUnsafeAddress"/>, on purpose. The management
    /// allow rule is not scoped to a program - the channel belongs to the agent service, not the
    /// browser - so it is the one rule in the set that any process on the machine could use. Its
    /// narrowness rests entirely on the address being a single host and the port a single port. A
    /// range or a wildcard here would become an any-program outbound allow, which is wider than
    /// anything a bad destination could produce.
    /// </para>
    /// <para>
    /// Loopback IS permitted, unlike for destinations: single-box deployments and the development
    /// harness legitimately run the management server on 127.0.0.1, and private ranges are normal
    /// for an on-premises one. What is refused is anything that is not one identifiable host.
    /// </para>
    /// </summary>
    public static string? DescribeUnsafeManagementAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "contains an empty ip_addresses entry";
        }

        var trimmed = value.Trim();

        if (!TryParseCidr(trimmed, out var candidate, out var parseError))
        {
            // This is also what rejects "*" and "any", which would otherwise reach netsh as a
            // remote-address wildcard on an unscoped rule.
            return $"ip_addresses entry '{trimmed}' {parseError}";
        }

        if (candidate.PrefixLength != candidate.Bytes.Length * 8)
        {
            return $"ip_addresses entry '{trimmed}' is a range, not a single host; the management " +
                   "allow rule is not program-scoped, so it must name exactly one address";
        }

        if (IsAllBytes(candidate.Bytes, 0x00))
        {
            return $"ip_addresses entry '{trimmed}' is the unspecified address";
        }

        if (candidate.IsV4 && IsAllBytes(candidate.Bytes, 0xFF))
        {
            return $"ip_addresses entry '{trimmed}' is the broadcast address";
        }

        // 224.0.0.0 and above is multicast or reserved for IPv4; ff00::/8 is multicast for IPv6.
        if (candidate.Bytes[0] >= (candidate.IsV4 ? 224 : 0xFF))
        {
            return $"ip_addresses entry '{trimmed}' is a multicast or reserved address";
        }

        return null;
    }

    /// <summary>Returns why <paramref name="name"/> is unusable in a rule name, or null.</summary>
    public static string? DescribeUnsafeName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "destination name is empty";
        }

        var trimmed = name.Trim();

        if (trimmed.Length > MaxNameLength)
        {
            return $"destination name exceeds {MaxNameLength} characters";
        }

        var badIndex = trimmed.IndexOfAny(ForbiddenNameChars);
        if (badIndex >= 0)
        {
            return $"destination name '{trimmed}' contains '{trimmed[badIndex]}', which is not " +
                   "allowed in a firewall rule name";
        }

        for (var i = 0; i < trimmed.Length; i++)
        {
            if (trimmed[i] < 0x20 || trimmed[i] == 0x7F)
            {
                return $"destination name '{trimmed}' contains control characters";
            }
        }

        return null;
    }

    /// <summary>
    /// Parses "a.b.c.d/len", "2001:db8::/len", or a bare address (treated as a single host).
    /// <para>
    /// The backend always emits an explicit prefix, so the bare-address form exists only so that a
    /// legitimate policy is never rejected over notation. A range whose base address has bits set
    /// below the prefix (192.168.1.5/24) IS rejected: such a range is ambiguous about what it
    /// intends to allow, and netsh would silently interpret it one particular way.
    /// </para>
    /// </summary>
    private static bool TryParseCidr(string value, out CidrRange range, out string error)
    {
        range = default;

        var slash = value.IndexOf('/');
        var addressPart = slash < 0 ? value : value.Substring(0, slash);

        if (!IPAddress.TryParse(addressPart, out var address) ||
            (address.AddressFamily != AddressFamily.InterNetwork &&
             address.AddressFamily != AddressFamily.InterNetworkV6))
        {
            error = "is not a valid IP address or CIDR block";
            return false;
        }

        // IPAddress.TryParse has historically accepted shorthand IPv4 forms ("10" -> 0.0.0.10,
        // "1.2.3" -> 1.2.0.3) and, on some runtimes, octal-looking octets. None of those produce a
        // dangerous rule, but they do produce a rule whose address is not the text an operator
        // reads in the audit log. Requiring canonical dotted-quad removes that gap and makes this
        // parser accept exactly what Python's ipaddress module accepts, which is what lets the
        // backend and the agent be described as applying the same rules.
        if (address.AddressFamily == AddressFamily.InterNetwork && !IsCanonicalDottedQuad(addressPart))
        {
            error = "is not a canonical dotted-quad IPv4 address";
            return false;
        }

        var bytes = address.GetAddressBytes();
        var maxPrefix = bytes.Length * 8;
        var prefixLength = maxPrefix;

        if (slash >= 0)
        {
            var prefixPart = value.Substring(slash + 1);
            if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out prefixLength) ||
                prefixLength > maxPrefix)
            {
                error = $"has a prefix length that is not an integer in 0-{maxPrefix}";
                return false;
            }
        }

        if (HasHostBitsSet(bytes, prefixLength))
        {
            error = "has bits set below its prefix length, so what it intends to allow is ambiguous";
            return false;
        }

        range = new CidrRange(bytes, prefixLength, address.AddressFamily == AddressFamily.InterNetwork);
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// True for "a.b.c.d" with four non-empty, all-digit, leading-zero-free octets.
    /// Octet range is not checked here; <see cref="IPAddress.TryParse"/> has already done that.
    /// </summary>
    private static bool IsCanonicalDottedQuad(string text)
    {
        var parts = text.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        foreach (var part in parts)
        {
            // A leading zero is the ambiguous case: some parsers read "010" as octal 8.
            if (part.Length == 0 || part.Length > 3 || (part.Length > 1 && part[0] == '0'))
            {
                return false;
            }

            for (var i = 0; i < part.Length; i++)
            {
                if (part[i] < '0' || part[i] > '9')
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// True when two CIDR blocks share at least one address.
    /// <para>
    /// Two prefix blocks overlap exactly when they agree on the first min(lenA, lenB) bits - the
    /// shorter prefix then contains the whole of the longer one. Asking only whether the candidate
    /// sits INSIDE a forbidden range would be wrong in the other direction: <c>169.252.0.0/14</c>
    /// spans the whole of link-local <c>169.254.0.0/16</c> even though 169.252.0.0 is itself an
    /// ordinary public address, and a one-directional check would let that supernet through.
    /// </para>
    /// </summary>
    private static bool Overlaps(CidrRange a, CidrRange b)
    {
        if (a.Bytes.Length != b.Bytes.Length)
        {
            // Different address families cannot overlap. IPv4-mapped IPv6 is handled as IPv6, by
            // the ::ffff:0:0/96 entry in ForbiddenV6.
            return false;
        }

        return SharesPrefix(a.Bytes, b.Bytes, Math.Min(a.PrefixLength, b.PrefixLength));
    }

    /// <summary>True when the first <paramref name="bits"/> bits of both arrays are equal.</summary>
    private static bool SharesPrefix(byte[] left, byte[] right, int bits)
    {
        var wholeBytes = bits / 8;
        for (var i = 0; i < wholeBytes; i++)
        {
            if (left[i] != right[i])
            {
                return false;
            }
        }

        var remainingBits = bits % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (left[wholeBytes] & mask) == (right[wholeBytes] & mask);
    }

    /// <summary>True when any bit below <paramref name="prefixLength"/> is set.</summary>
    private static bool HasHostBitsSet(byte[] bytes, int prefixLength)
    {
        for (var i = 0; i < bytes.Length; i++)
        {
            var bitsBefore = i * 8;

            if (bitsBefore >= prefixLength)
            {
                if (bytes[i] != 0)
                {
                    return true;
                }

                continue;
            }

            var networkBitsHere = prefixLength - bitsBefore;
            if (networkBitsHere >= 8)
            {
                continue;
            }

            var hostMask = (byte)(0xFF >> networkBitsHere);
            if ((bytes[i] & hostMask) != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAllBytes(byte[] bytes, byte expected)
    {
        for (var i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] != expected)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>A parsed CIDR block: the base address bytes plus its prefix length.</summary>
    private readonly struct CidrRange
    {
        internal CidrRange(byte[] bytes, int prefixLength, bool isV4)
        {
            Bytes = bytes;
            PrefixLength = prefixLength;
            IsV4 = isV4;
        }

        internal byte[] Bytes { get; }

        internal int PrefixLength { get; }

        internal bool IsV4 { get; }
    }

    /// <summary>A forbidden range, parsed once at type initialization.</summary>
    private readonly struct ForbiddenRange
    {
        internal ForbiddenRange(string cidr, string reason)
        {
            Cidr = cidr;
            Reason = reason;

            if (!TryParseCidr(cidr, out var parsed, out var error))
            {
                // A literal in this file is wrong; that is a build-time defect, not a runtime
                // condition, and failing loudly at type initialization is the only safe outcome.
                throw new InvalidOperationException(
                    $"PolicyDestinationValidator has an invalid forbidden range '{cidr}': {error}");
            }

            Range = parsed;
        }

        internal string Cidr { get; }

        internal string Reason { get; }

        internal CidrRange Range { get; }
    }
}
