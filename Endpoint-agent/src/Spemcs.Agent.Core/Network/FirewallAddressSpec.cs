using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Semantic comparison for Windows Firewall address specifications.
/// </summary>
/// <remarks>
/// Windows Defender Firewall does not store an address specification verbatim. Setting
/// <c>INetFwRule.RemoteAddresses</c> and reading it straight back rewrites the value:
/// <list type="bullet">
///   <item><description>IPv4 CIDR becomes a dotted-decimal subnet mask - <c>192.168.250.0/24</c> is
///   returned as <c>192.168.250.0/255.255.255.0</c>.</description></item>
///   <item><description>A bare IPv4 host gains an explicit full mask - <c>127.0.0.1</c> is returned
///   as <c>127.0.0.1/255.255.255.255</c>.</description></item>
///   <item><description>A bare IPv6 host is expanded into a degenerate range - <c>2001:db8::1</c> is
///   returned as <c>2001:db8::1-2001:db8::1</c>.</description></item>
///   <item><description>IPv6 prefixes, address ranges and keywords such as <c>LocalSubnet</c> round
///   trip unchanged.</description></item>
/// </list>
/// So an ordinal comparison of "what we asked for" against "what the firewall holds" reports a
/// mismatch for every IPv4 rule SPEMCS installs, the loopback rule included, even when the rule was
/// written exactly as intended. Verification has to compare the two as address sets.
///
/// This canonicalises rather than reformats: the readback is still surfaced to callers and logs in
/// the firewall's own representation, and only the equality test is made representation-independent.
/// A token that cannot be parsed as an address - including an IPv4 mask whose bits are not
/// contiguous, which is not a prefix at all - is compared literally, so nothing unrecognised is ever
/// silently treated as equivalent to something else.
/// </remarks>
public static class FirewallAddressSpec
{
    private const string AnySpec = "*";

    /// <summary>
    /// Returns true when both specifications denote the same set of addresses, regardless of which
    /// representation each side uses or the order in which the entries appear.
    /// </summary>
    public static bool AreEquivalent(string? expected, string? actual) =>
        string.Equals(Canonicalize(expected), Canonicalize(actual), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reduces an address specification to a canonical, order-independent form. Intended for
    /// comparison and diagnostics only - never write the result back to the firewall.
    /// </summary>
    public static string Canonicalize(string? spec)
    {
        if (string.IsNullOrWhiteSpace(spec))
        {
            return AnySpec;
        }

        var trimmed = spec.Trim();
        if (string.Equals(trimmed, AnySpec, StringComparison.Ordinal) ||
            string.Equals(trimmed, "Any", StringComparison.OrdinalIgnoreCase))
        {
            return AnySpec;
        }

        var tokens = trimmed
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(CanonicalizeToken)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(token => token, StringComparer.Ordinal);

        var joined = string.Join(',', tokens);
        return joined.Length == 0 ? AnySpec : joined;
    }

    private static string CanonicalizeToken(string token)
    {
        if (string.Equals(token, AnySpec, StringComparison.Ordinal) ||
            string.Equals(token, "Any", StringComparison.OrdinalIgnoreCase))
        {
            return AnySpec;
        }

        // Ranges: "a-b". A degenerate range is the host it names, which is how the firewall reports
        // a bare IPv6 address back to us.
        var dash = token.IndexOf('-', StringComparison.Ordinal);
        if (dash > 0)
        {
            if (IPAddress.TryParse(token[..dash], out var low) &&
                IPAddress.TryParse(token[(dash + 1)..], out var high) &&
                low.AddressFamily == high.AddressFamily)
            {
                return low.Equals(high)
                    ? WithPrefix(low, FullPrefix(low))
                    : string.Concat(low.ToString(), "-", high.ToString());
            }

            return token.ToUpperInvariant();
        }

        var slash = token.IndexOf('/', StringComparison.Ordinal);
        if (slash < 0)
        {
            return IPAddress.TryParse(token, out var host)
                ? WithPrefix(host, FullPrefix(host))
                : token.ToUpperInvariant();
        }

        if (!IPAddress.TryParse(token[..slash], out var network))
        {
            return token.ToUpperInvariant();
        }

        var suffix = token[(slash + 1)..];
        var full = FullPrefix(network);

        // "/24" - already a prefix length.
        if (int.TryParse(suffix, NumberStyles.None, CultureInfo.InvariantCulture, out var prefix) &&
            prefix >= 0 && prefix <= full)
        {
            return WithPrefix(network, prefix);
        }

        // "/255.255.255.0" - the form the firewall hands back for IPv4.
        if (network.AddressFamily == AddressFamily.InterNetwork &&
            IPAddress.TryParse(suffix, out var mask) &&
            mask.AddressFamily == AddressFamily.InterNetwork &&
            TryConvertMaskToPrefix(mask, out var derived))
        {
            return WithPrefix(network, derived);
        }

        return token.ToUpperInvariant();
    }

    private static int FullPrefix(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;

    private static string WithPrefix(IPAddress address, int prefix) =>
        string.Concat(address.ToString(), "/", prefix.ToString(CultureInfo.InvariantCulture));

    private static bool TryConvertMaskToPrefix(IPAddress mask, out int prefix)
    {
        prefix = 0;

        var bytes = mask.GetAddressBytes();
        if (bytes.Length != 4)
        {
            return false;
        }

        var value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];

        // A subnet mask is a run of high bits. If the inverted value is not all-low-bits then the
        // mask is non-contiguous (e.g. 255.0.255.0) and denotes no prefix - refuse it rather than
        // inventing one from the population count.
        var inverted = ~value;
        if ((inverted & (inverted + 1)) != 0)
        {
            return false;
        }

        prefix = BitOperations.PopCount(value);
        return true;
    }
}
