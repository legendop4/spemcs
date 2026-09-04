#!/usr/bin/env python3
"""Verifies PolicyDestinationValidator.cs two ways, without a C# compiler.

Part A - structural: brace / paren / bracket balance, with comments, strings, char literals
and verbatim strings removed first.

Part B - parity: the C# address logic is transliterated into Python here, statement for
statement, and then differential-tested against the real backend implementation it claims to
mirror (backend.services.policy_compiler). The C# file says "kept in sync with
policy_compiler.py"; this is what turns that comment into a checked claim.

The property under test is two-directional and both directions matter:

  * anything the BACKEND accepts, the AGENT must accept - otherwise a correctly compiled
    policy is rejected on exam day and the exam fails for no reason;
  * anything the AGENT accepts, the BACKEND must accept - otherwise the agent's
    defense-in-depth layer is weaker than the layer it is backing up, which makes it
    decorative.

One deliberate, documented asymmetry is allowed: the agent refuses a range with bits set
below its prefix ("192.168.1.5/24") while the backend normalizes it away
(ipaddress.ip_network(..., strict=False)). The agent only ever sees the normalized output of
validate_destination_networks, so this can never reject a legitimate policy; a payload that
still carries host bits did not come through the compiler at all. Such cases are counted and
reported separately rather than being silently tolerated.

Why this exists at all: there is no .NET toolchain in the environment this was written in, so
PolicyDestinationValidator.cs could not be compiled, let alone unit-tested. This harness is the
substitute - it verifies the LOGIC by transliteration, and it emits the corpus as a C# fixture so
that the REAL validator can be checked against the identical cases from xunit the moment a
compiler is available. It is not a replacement for `dotnet test`; it is what makes the eventual
`dotnet test` a confirmation rather than a first look.

Usage
-----
    python3 Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py
    python3 ...verify_policy_destination_validator_parity.py --self-check
    python3 ...verify_policy_destination_validator_parity.py --emit-fixture \
        Endpoint-agent/tests/Spemcs.Agent.Tests/AddressValidationFixtures.cs

--self-check mutates this file's own logic 27 ways and requires every mutant to fail the suite,
which is the evidence that a pass here means something. Requires only the standard library plus
an importable `backend` package; no network, no database, no .NET.
"""

import ipaddress
import os
import random
import re
import sys

import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir, os.pardir))
CS_FILE = os.path.join(
    REPO, "Endpoint-agent", "src", "Spemcs.Agent.Core", "Network",
    "PolicyDestinationValidator.cs",
)
sys.path.insert(0, os.path.join(REPO, "backend"))

EMIT_FIXTURE = None
if "--emit-fixture" in sys.argv:
    EMIT_FIXTURE = sys.argv[sys.argv.index("--emit-fixture") + 1]

# ==============================================================================
# --self-check: prove this file is not a test that passes no matter what
# ==============================================================================
# A differential test can be silently vacuous - if the corpus never contains a case that
# distinguishes right from wrong, it passes on a broken validator. Each entry below breaks the
# transliterated logic in one specific way; every one MUST make this script exit non-zero.
#
# Two of them are listed as EQUIVALENT: they delete a branch whose effect another branch already
# covers, so no verdict changes and only the operator-facing message differs. Those are pinned by
# message assertions rather than by verdict, and this list records which they are so a future
# reader does not mistake redundancy for a gap.
MUTATIONS = [
    ("overlap test reduced to one-directional membership",
     "    return shares_prefix(a[0], b[0], min(a[1], b[1]))",
     "    return shares_prefix(a[0], b[0], b[1])"),
    ("minimum IPv4 prefix loosened 8 -> 1", "MIN_PREFIX_V4 = 8", "MIN_PREFIX_V4 = 1"),
    ("minimum IPv6 prefix loosened 32 -> 8", "MIN_PREFIX_V6 = 32", "MIN_PREFIX_V6 = 8"),
    ("link-local narrowed in the IPv4 table",
     '    ("169.254.0.0/16",', '    ("169.254.0.0/32",'),
    ("loopback narrowed in the IPv4 table", '    ("127.0.0.0/8",', '    ("127.0.0.1/32",'),
    ("6to4 narrowed in the IPv6 table", '    ("2002::/16",', '    ("2002::/128",'),
    ("IPv4-mapped IPv6 narrowed", '    ("::ffff:0:0/96",', '    ("::ffff:0:0/128",'),
    ("match-everything guard removed (EQUIVALENT - min-prefix also rejects /0)",
     "    if prefix_length == 0:", "    if prefix_length == -1:"),
    ("host-bit mask off by one",
     "        host_mask = 0xFF >> network_bits_here",
     "        host_mask = 0xFF >> (network_bits_here + 1)"),
    ("host-bit detection disabled",
     "    if has_host_bits_set(data, prefix_length):", "    if False:"),
    ("shares_prefix partial-byte mask dropped",
     "    return (left[whole_bytes] & mask) == (right[whole_bytes] & mask)", "    return True"),
    ("shares_prefix whole-byte loop skipped",
     "    for i in range(whole_bytes):", "    for i in range(0):"),
    ("cross-family short-circuit removed", "    if len(a[0]) != len(b[0]):", "    if False:"),
    ("forbidden name chars narrowed to the pipe",
     "        if ch in FORBIDDEN_NAME_CHARS:", '        if ch in ("|",):'),
    ("name control-character check removed",
     "        if ord(ch) < 0x20 or ord(ch) == 0x7F:", "        if False:"),
    ("name length cap raised", "    if len(trimmed) > MAX_NAME_LENGTH:", "    if len(trimmed) > 4096:"),
    ("management single-host check removed",
     "    if prefix_length != len(data) * 8:", "    if False:"),
    ("management multicast check removed",
     "    if data[0] >= (224 if is_v4 else 0xFF):", "    if False:"),
    ("management unspecified check removed",
     "    if all(b == 0x00 for b in data):", "    if False:"),
    ("management broadcast check removed (EQUIVALENT - multicast/reserved also rejects it)",
     "    if is_v4 and all(b == 0xFF for b in data):", "    if False:"),
    ("empty ip_ranges tolerated", "    if len(ip_ranges) == 0:", "    if False:"),
    ("dotted-quad canonicalisation dropped",
     "    if is_v4 and not is_canonical_dotted_quad(address_part):", "    if False:"),
    ("leading-zero octet allowed",
     '        if len(part) == 0 or len(part) > 3 or (len(part) > 1 and part[0] == "0"):',
     "        if len(part) == 0 or len(part) > 3:"),
    ("four-part IPv4 requirement dropped", "    if len(parts) != 4:", "    if False:"),
    ("prefix length above the family maximum allowed",
     "        if prefix_length > max_prefix:", "        if False:"),
    ("TryValidate skips its address checks", "    for value in ip_ranges:", "    for value in []:"),
    ("TryValidate skips its name check",
     "    problem = cs_describe_unsafe_name(name)", "    problem = None"),
]

if "--self-check" in sys.argv:
    own_source = open(os.path.abspath(__file__), encoding="utf-8").read()
    import tempfile
    survivors = []
    print(f"MUTATION SELF-CHECK - {len(MUTATIONS)} mutants, each must be caught")
    for label, old, new in MUTATIONS:
        if old not in own_source:
            survivors.append(f"{label} (mutation target no longer present in this file)")
            print(f"  STALE       {label}")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            mutant = os.path.join(tmp, "mutant.py")
            with open(mutant, "w", encoding="utf-8") as fh:
                fh.write(own_source.replace(old, new, 1))
            done = subprocess.run([sys.executable, mutant], capture_output=True, text=True)
        if done.returncode == 0:
            survivors.append(label)
            print(f"  NOT CAUGHT  {label}")
        else:
            print(f"  caught      {label}")
    print()
    if survivors:
        print(f"SELF-CHECK FAILED - {len(survivors)} mutant(s) survived; the corpus below does "
              "not distinguish a correct validator from these broken ones:")
        for item in survivors:
            print(f"  - {item}")
        sys.exit(1)
    print("SELF-CHECK PASSED - every mutant was caught")
    sys.exit(0)

from backend.services.policy_compiler import (  # noqa: E402
    _ALWAYS_FORBIDDEN_V4,
    _ALWAYS_FORBIDDEN_V6,
    _FORBIDDEN_NAME_CHARS,
    MAX_DESTINATION_NAME_LENGTH,
    MIN_DESTINATION_PREFIX_V4,
    MIN_DESTINATION_PREFIX_V6,
    DestinationResolutionError,
    describe_unsafe_network,
    validate_destination_name,
)

failures = []
notes = []


def check(condition, message):
    if not condition:
        failures.append(message)
    return bool(condition)


# ==============================================================================
# Part A - structural balance
# ==============================================================================
def strip_cs(src):
    """Removes what must not be counted. Order matters.

    Char literals go FIRST: ForbiddenNameChars contains '"', and if the string regex ran
    first that embedded quote would open a string that swallowed the rest of the file. (That
    exact ordering bug produced a bogus braces_net=-2 on an earlier run.)
    """
    src = re.sub(r"@\"(?:[^\"]|\"\")*\"", '""', src)      # verbatim strings
    src = re.sub(r"'(?:\\.|[^'\\])'", "' '", src)          # char literals
    src = re.sub(r"\"(?:\\.|[^\"\\])*\"", '""', src)       # normal strings
    src = re.sub(r"//[^\n]*", "", src)                      # line comments
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)         # block comments
    return src


with open(CS_FILE, encoding="utf-8") as fh:
    CS_SRC = fh.read()

stripped = strip_cs(CS_SRC)
depth = 0
min_depth = 0
for ch in stripped:
    if ch == "{":
        depth += 1
    elif ch == "}":
        depth -= 1
        min_depth = min(min_depth, depth)

print("=" * 78)
print("PART A - structural")
print("=" * 78)
print(f"  lines            {len(CS_SRC.splitlines())}")
print(f"  braces net       {depth}")
print(f"  braces min depth {min_depth}")
print(f"  parens net       {stripped.count('(') - stripped.count(')')}")
print(f"  brackets net     {stripped.count('[') - stripped.count(']')}")
check(depth == 0, f"brace imbalance: net {depth}")
check(min_depth == 0, f"brace underflow: min depth {min_depth}")
check(stripped.count("(") == stripped.count(")"), "paren imbalance")
check(stripped.count("[") == stripped.count("]"), "bracket imbalance")

# The whole point of the rewrite was to drop a BCL type this sandbox cannot verify. Check the
# comment-stripped source: the doc comment legitimately names IPNetwork to explain its absence.
check(
    "IPNetwork" not in stripped,
    "PolicyDestinationValidator.cs still references IPNetwork in CODE, the unverifiable API "
    "the rewrite was meant to remove",
)
for member in ("IPAddress.TryParse", "GetAddressBytes", "AddressFamily.InterNetwork"):
    check(member in CS_SRC, f"expected {member} in the rewritten validator")

# ==============================================================================
# Part B1 - transliteration of the C# under test
# ==============================================================================
MIN_PREFIX_V4 = 8
MIN_PREFIX_V6 = 32
MAX_NAME_LENGTH = 64
FORBIDDEN_NAME_CHARS = ("|", '"', "'", "`", "\\", "/")

FORBIDDEN_V4 = (
    ("0.0.0.0/8", "the unspecified/this-network range"),
    ("127.0.0.0/8", "loopback, which cannot leave the machine and is not a destination"),
    ("169.254.0.0/16",
     "link-local, which includes the cloud instance metadata address 169.254.169.254"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
    ("255.255.255.255/32", "the broadcast address"),
)
FORBIDDEN_V6 = (
    ("::/128", "the unspecified address"),
    ("::1/128", "loopback, which cannot leave the machine and is not a destination"),
    ("fe80::/10", "link-local"),
    ("ff00::/8", "multicast"),
    ("::ffff:0:0/96",
     "an IPv4-mapped IPv6 range; express IPv4 destinations as IPv4 so the resulting "
     "firewall rule is unambiguous"),
    ("2002::/16", "the 6to4 tunnel range (requirement 7 contains transition mechanisms)"),
    ("2001::/32", "the Teredo tunnel range (requirement 7 contains transition mechanisms)"),
)

CS_WHITESPACE = set(" \t\n\v\f\r\x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
                    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000")


def cs_trim(text):
    """string.Trim(). Narrower than Python's str.strip(), which also strips \\x1c-\\x1f."""
    start, end = 0, len(text)
    while start < end and text[start] in CS_WHITESPACE:
        start += 1
    while end > start and text[end - 1] in CS_WHITESPACE:
        end -= 1
    return text[start:end]


def cs_is_null_or_whitespace(text):
    return text is None or cs_trim(text) == ""


def is_canonical_dotted_quad(text):
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if len(part) == 0 or len(part) > 3 or (len(part) > 1 and part[0] == "0"):
            return False
        for ch in part:
            if ch < "0" or ch > "9":
                return False
    return True


def ip_address_try_parse(text):
    """Models IPAddress.TryParse PERMISSIVELY, on purpose.

    I cannot determine from this sandbox which shorthand and leading-zero forms .NET 8's parser
    accepts (learn.microsoft.com is not reachable and the docs must not be fetched another way).
    Modelling it with Python's strict parser would be the wrong response to that uncertainty: it
    would quietly do IsCanonicalDottedQuad's job, and the harness would then "prove" the C# is
    correct only on the assumption the C# was written to avoid needing.

    So this models the most permissive plausible behaviour - classic inet_aton semantics, where
    "10" is 0.0.0.10, "1.2.3" is 1.2.0.3, and "010" is decimal 10. If the validator is correct
    against THIS parser, it is correct whichever behaviour .NET actually has, because
    IsCanonicalDottedQuad is then the only thing standing between the input and the rule.
    """
    if ":" in text:
        try:
            return ipaddress.IPv6Address(text)
        except ValueError:
            return None

    parts = text.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for part in parts:
        if not part or not part.isdigit() or not part.isascii():
            return None
        values.append(int(part))
    # inet_aton: the final part absorbs all the remaining low-order bytes.
    limits = [255] * (len(values) - 1) + [(1 << (8 * (5 - len(values)))) - 1]
    for value, limit in zip(values, limits):
        if value > limit:
            return None
    packed = 0
    for value, shift in zip(values[:-1], range(24, 0, -8)):
        packed |= value << shift
    packed |= values[-1]
    return ipaddress.IPv4Address(packed)


def has_host_bits_set(data, prefix_length):
    for i in range(len(data)):
        bits_before = i * 8
        if bits_before >= prefix_length:
            if data[i] != 0:
                return True
            continue
        network_bits_here = prefix_length - bits_before
        if network_bits_here >= 8:
            continue
        host_mask = 0xFF >> network_bits_here
        if data[i] & host_mask:
            return True
    return False


def shares_prefix(left, right, bits):
    whole_bytes = bits // 8
    for i in range(whole_bytes):
        if left[i] != right[i]:
            return False
    remaining_bits = bits % 8
    if remaining_bits == 0:
        return True
    mask = (0xFF << (8 - remaining_bits)) & 0xFF
    return (left[whole_bytes] & mask) == (right[whole_bytes] & mask)


def try_parse_cidr(value):
    """Returns (bytes, prefix_length, is_v4) or ('error', message)."""
    slash = value.find("/")
    address_part = value if slash < 0 else value[:slash]

    address = ip_address_try_parse(address_part)
    if address is None:
        return ("error", "is not a valid IP address or CIDR block")

    is_v4 = address.version == 4
    if is_v4 and not is_canonical_dotted_quad(address_part):
        return ("error", "is not a canonical dotted-quad IPv4 address")

    data = address.packed
    max_prefix = len(data) * 8
    prefix_length = max_prefix

    if slash >= 0:
        prefix_part = value[slash + 1:]
        # int.TryParse with NumberStyles.None: digits only, no sign, no space.
        if not prefix_part.isdigit() or not prefix_part.isascii():
            return ("error", f"has a prefix length that is not an integer in 0-{max_prefix}")
        prefix_length = int(prefix_part)
        if prefix_length > max_prefix:
            return ("error", f"has a prefix length that is not an integer in 0-{max_prefix}")

    if has_host_bits_set(data, prefix_length):
        return ("error",
                "has bits set below its prefix length, so what it intends to allow is ambiguous")

    return (data, prefix_length, is_v4)


def overlaps(a, b):
    if len(a[0]) != len(b[0]):
        return False
    return shares_prefix(a[0], b[0], min(a[1], b[1]))


FORBIDDEN_V4_PARSED = [(try_parse_cidr(c), c, r) for c, r in FORBIDDEN_V4]
FORBIDDEN_V6_PARSED = [(try_parse_cidr(c), c, r) for c, r in FORBIDDEN_V6]
for parsed, cidr, _reason in FORBIDDEN_V4_PARSED + FORBIDDEN_V6_PARSED:
    check(parsed[0] != "error",
          f"the C# forbidden-range literal '{cidr}' does not parse under the C# parser: "
          f"{parsed[1] if parsed[0] == 'error' else ''} - the static initializer would throw")


def cs_describe_unsafe_address(value):
    if cs_is_null_or_whitespace(value):
        return "an empty address range"
    trimmed = cs_trim(value)

    parsed = try_parse_cidr(trimmed)
    if parsed[0] == "error":
        return f"address range '{trimmed}' {parsed[1]}"

    _data, prefix_length, is_v4 = parsed
    if prefix_length == 0:
        return f"address range '{trimmed}' matches every address, which would nullify default-deny"

    family = "IPv4" if is_v4 else "IPv6"
    minimum = MIN_PREFIX_V4 if is_v4 else MIN_PREFIX_V6
    if prefix_length < minimum:
        return (f"address range '{trimmed}' is broader than the widest allowed {family} "
                f"prefix (/{minimum})")

    forbidden = FORBIDDEN_V4_PARSED if is_v4 else FORBIDDEN_V6_PARSED
    for fparsed, cidr, reason in forbidden:
        if overlaps(parsed, fparsed):
            return f"address range '{trimmed}' overlaps {cidr}, which is {reason}"

    return None


def cs_describe_unsafe_management_address(value):
    if cs_is_null_or_whitespace(value):
        return "contains an empty ip_addresses entry"
    trimmed = cs_trim(value)

    parsed = try_parse_cidr(trimmed)
    if parsed[0] == "error":
        return f"ip_addresses entry '{trimmed}' {parsed[1]}"

    data, prefix_length, is_v4 = parsed
    if prefix_length != len(data) * 8:
        return (f"ip_addresses entry '{trimmed}' is a range, not a single host; the management "
                "allow rule is not program-scoped, so it must name exactly one address")
    if all(b == 0x00 for b in data):
        return f"ip_addresses entry '{trimmed}' is the unspecified address"
    if is_v4 and all(b == 0xFF for b in data):
        return f"ip_addresses entry '{trimmed}' is the broadcast address"
    if data[0] >= (224 if is_v4 else 0xFF):
        return f"ip_addresses entry '{trimmed}' is a multicast or reserved address"
    return None


def cs_describe_unsafe_name(name):
    if cs_is_null_or_whitespace(name):
        return "destination name is empty"
    trimmed = cs_trim(name)
    if len(trimmed) > MAX_NAME_LENGTH:
        return f"destination name exceeds {MAX_NAME_LENGTH} characters"
    for i, ch in enumerate(trimmed):
        if ch in FORBIDDEN_NAME_CHARS:
            return (f"destination name '{trimmed}' contains '{ch}', which is not allowed in a "
                    "firewall rule name")
    for ch in trimmed:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            return f"destination name '{trimmed}' contains control characters"
    return None


def cs_try_validate(index, name, ip_ranges):
    problem = cs_describe_unsafe_name(name)
    if problem is not None:
        return f"allowed_destinations[{index}]: {problem}"
    if len(ip_ranges) == 0:
        return (f"allowed_destinations[{index}] ('{name}') carries no ip_ranges, so it would "
                "produce no firewall rule and the destination would be unreachable")
    for value in ip_ranges:
        problem = cs_describe_unsafe_address(value)
        if problem is not None:
            return f"allowed_destinations[{index}] ('{name}'): {problem}"
    return None


# ==============================================================================
# Part B2 - the constants must be the same constants
# ==============================================================================
print()
print("=" * 78)
print("PART B - parity with backend/backend/services/policy_compiler.py")
print("=" * 78)

check(MIN_PREFIX_V4 == MIN_DESTINATION_PREFIX_V4,
      f"min v4 prefix drift: C# {MIN_PREFIX_V4} vs backend {MIN_DESTINATION_PREFIX_V4}")
check(MIN_PREFIX_V6 == MIN_DESTINATION_PREFIX_V6,
      f"min v6 prefix drift: C# {MIN_PREFIX_V6} vs backend {MIN_DESTINATION_PREFIX_V6}")
check(MAX_NAME_LENGTH == MAX_DESTINATION_NAME_LENGTH,
      f"name length drift: C# {MAX_NAME_LENGTH} vs backend {MAX_DESTINATION_NAME_LENGTH}")
check(set(FORBIDDEN_NAME_CHARS) == set(_FORBIDDEN_NAME_CHARS),
      f"forbidden name char drift: C# {sorted(FORBIDDEN_NAME_CHARS)} vs backend "
      f"{sorted(_FORBIDDEN_NAME_CHARS)}")
check(tuple(FORBIDDEN_V4) == tuple(_ALWAYS_FORBIDDEN_V4),
      "forbidden IPv4 table drift:\n    C#      " + repr(FORBIDDEN_V4) +
      "\n    backend " + repr(_ALWAYS_FORBIDDEN_V4))
check(tuple(FORBIDDEN_V6) == tuple(_ALWAYS_FORBIDDEN_V6),
      "forbidden IPv6 table drift:\n    C#      " + repr(FORBIDDEN_V6) +
      "\n    backend " + repr(_ALWAYS_FORBIDDEN_V6))
print(f"  constants + forbidden tables compared: {len(FORBIDDEN_V4)} v4, {len(FORBIDDEN_V6)} v6")

# The transliteration is only evidence if it really came from the file. Pin every literal.
for cidr, reason in list(FORBIDDEN_V4) + list(FORBIDDEN_V6):
    check(f'new("{cidr}"' in CS_SRC, f"'{cidr}' is in the transliteration but not in the .cs file")
    check(reason in CS_SRC.replace("\" +\n                       \"", "").replace(
        '" +\n        "', ""),
        f"reason text for {cidr} differs between the transliteration and the .cs file")
check(f"MinPrefixV4 = {MIN_PREFIX_V4}" in CS_SRC, "MinPrefixV4 literal mismatch vs .cs")
check(f"MinPrefixV6 = {MIN_PREFIX_V6}" in CS_SRC, "MinPrefixV6 literal mismatch vs .cs")
check(f"MaxNameLength = {MAX_NAME_LENGTH}" in CS_SRC, "MaxNameLength literal mismatch vs .cs")
print(f"  every transliterated literal located in {os.path.basename(CS_FILE)}")


# ==============================================================================
# Part B3 - differential test of the accept/reject decision
# ==============================================================================
def backend_verdict(text):
    """(accepted, reason, normalized_had_host_bits)."""
    cleaned = text.strip()
    if not cleaned:
        return False, "empty", False
    try:
        if "/" not in cleaned:
            addr = ipaddress.ip_address(cleaned)
            net = ipaddress.ip_network(f"{addr.compressed}/{32 if addr.version == 4 else 128}")
            renormalized = False
        else:
            net = ipaddress.ip_network(cleaned, strict=False)
            renormalized = ipaddress.ip_network(cleaned, strict=False).network_address != \
                ipaddress.ip_address(cleaned.split("/")[0])
    except ValueError as exc:
        return False, f"unparseable: {exc}", False
    reason = describe_unsafe_network(net)
    return reason is None, reason, renormalized


CORPUS = []

# The 20 unsafe / 8 safe corpora already pinned in test_destination_resolution.py.
CORPUS += [
    "0.0.0.0/0", "::/0", "0.0.0.0/8", "0.0.0.1/32", "127.0.0.1/32", "127.0.0.53/32",
    "169.254.0.0/16", "169.254.169.254/32", "169.252.0.0/14", "224.0.0.1/32", "239.255.255.250/32",
    "240.0.0.0/4", "255.255.255.255/32", "128.0.0.0/1", "64.0.0.0/2", "10.0.0.0/7",
    "::1/128", "::/128", "fe80::1/128", "ff02::1/128", "::ffff:127.0.0.1/128",
    "::ffff:8.8.8.8/128", "2002:c000:204::/48", "2001:0:53aa:64c:2c:1234:5678:9abc/128",
    "2001::/32", "fe80::/10", "ff00::/8", "1000::/8", "8000::/1",
]
CORPUS += [
    "203.0.113.5/32", "203.0.113.0/24", "10.20.0.0/24", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.1.0/24", "2001:db8::1/128", "2001:db8::/48", "2606:4700::/32", "8.8.8.8/32",
    "1.1.1.1/32", "104.16.0.0/12",
]
# Notation, tunnelling and boundary forms.
CORPUS += [
    "203.0.113.5", "2001:db8::1", " 203.0.113.5/32 ", "203.0.113.5/33", "203.0.113.5/-1",
    "203.0.113.5/", "203.0.113.5/x", "203.0.113.5//32", "203.0.113.5/032", "192.168.1.5/24",
    "010.0.0.1/32", "10.0.0.01/32", "1.2.3", "10", "0x7f000001", "", "   ", "*", "any",
    "203.0.113.5:443", "203.0.113.5-203.0.113.9", "not-an-ip", "2001:db8::1/129",
    "::ffff:0:0/96", "::ffff:0:0/95", "2002::/15", "2001::/31", "fe80::/9", "ff00::/7",
    "2001:0:1::/48", "2002:1::/32", "126.0.0.0/7", "128.0.0.0/8", "169.255.0.0/16",
    "169.253.0.0/16", "223.255.255.255/32", "224.0.0.0/3", "239.0.0.0/8",
    "0.0.0.0/9", "1.0.0.0/8", "255.0.0.0/8", "255.255.255.254/31",
    "fc00::/7", "fd00::/8", "fdff::/16", "::2/128", "100::/64", "3fff::/20",
]
# Every boundary around every forbidden range: the range itself, each supernet up to the
# minimum prefix, the first and last /32 or /128 inside it, and its immediate neighbours.
for cidr, _ in list(FORBIDDEN_V4) + list(FORBIDDEN_V6):
    net = ipaddress.ip_network(cidr)
    host_len = net.max_prefixlen
    minimum = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
    CORPUS.append(cidr)
    for shorter in range(net.prefixlen - 1, max(minimum, 0) - 1, -1):
        CORPUS.append(str(net.supernet(new_prefix=shorter)))
    CORPUS.append(f"{net.network_address}/{host_len}")
    CORPUS.append(f"{net.broadcast_address}/{host_len}")
    below = int(net.network_address) - 1
    above = int(net.broadcast_address) + 1
    if below >= 0:
        CORPUS.append(f"{ipaddress.ip_address(below)}/{host_len}")
    if above < 2 ** host_len:
        CORPUS.append(f"{ipaddress.ip_address(above)}/{host_len}")
    if net.prefixlen < host_len:
        CORPUS.append(f"{ipaddress.ip_address(below)}/{net.prefixlen}"
                      if below >= 0 else cidr)

# Randomized sweep: masked (canonical) ranges across both families and every prefix length.
rng = random.Random(20260905)
for _ in range(4000):
    if rng.random() < 0.5:
        base = rng.getrandbits(32)
        prefix = rng.randint(0, 32)
        net = ipaddress.ip_network((base, prefix), strict=False)
    else:
        base = rng.getrandbits(128)
        prefix = rng.randint(0, 128)
        net = ipaddress.ip_network((base, prefix), strict=False)
    CORPUS.append(str(net))
# ...and unmasked ones, to exercise the documented host-bits asymmetry.
for _ in range(500):
    base = rng.getrandbits(32) | 1
    CORPUS.append(f"{ipaddress.ip_address(base)}/{rng.randint(1, 31)}")
# Unmasked where the ONLY set host bit is the TOPMOST one, for every prefix length in both
# families. Random "| 1" cases all set the lowest bit, which an off-by-one in the host-bit mask
# still catches; this is the corpus that pins the mask boundary exactly. (Mutation testing found
# that gap: "host_mask = 0xFF >> (network_bits_here + 1)" survived the random corpus.)
for prefix in range(1, 32):
    CORPUS.append(f"{ipaddress.IPv4Address(1 << (32 - prefix - 1))}/{prefix}")
    CORPUS.append(f"{ipaddress.IPv4Address((0xC0000000 >> (prefix - 1)) & 0xFFFFFFFF)}/{prefix}")
for prefix in range(1, 128):
    # IPv4Address/IPv6Address explicitly: ip_address() returns an IPv4Address for any int under
    # 2**32, which would silently turn the high-prefix IPv6 cases into IPv4 text like
    # "0.0.0.1/127" and test nothing.
    CORPUS.append(f"{ipaddress.IPv6Address(1 << (128 - prefix - 1))}/{prefix}")

CORPUS = list(dict.fromkeys(CORPUS))

agree = 0
host_bit_asymmetry = 0
agent_stricter = []
agent_weaker = []
for text in CORPUS:
    agent_reason = cs_describe_unsafe_address(text)
    agent_ok = agent_reason is None
    backend_ok, backend_reason, _ = backend_verdict(text)

    if agent_ok == backend_ok:
        agree += 1
        continue

    if agent_ok and not backend_ok:
        agent_weaker.append((text, backend_reason))
        continue

    # Agent rejects, backend accepts. Allowed only for the documented host-bits case.
    parsed = try_parse_cidr(cs_trim(text))
    if parsed[0] == "error" and "bits set below its prefix length" in parsed[1]:
        host_bit_asymmetry += 1
        continue
    if parsed[0] == "error" and "canonical dotted-quad" in parsed[1]:
        host_bit_asymmetry += 1
        continue
    agent_stricter.append((text, agent_reason))

print(f"  differential corpus            {len(CORPUS)} address strings")
print(f"  identical verdict              {agree}")
print(f"  documented notation asymmetry  {host_bit_asymmetry} "
      f"(agent refuses unnormalized / non-canonical text the backend would rewrite)")
check(not agent_weaker,
      "AGENT ACCEPTS WHAT THE BACKEND REFUSES - the defense-in-depth layer is weaker than "
      "the layer it backs up:\n    " +
      "\n    ".join(f"{t!r}: backend says {r}" for t, r in agent_weaker[:15]))
check(not agent_stricter,
      "AGENT REFUSES WHAT THE BACKEND ACCEPTS for an undocumented reason - a legitimate "
      "policy would be rejected on exam day:\n    " +
      "\n    ".join(f"{t!r}: agent says {r}" for t, r in agent_stricter[:15]))

# The corpus is only meaningful if it actually contains both verdicts.
accepted = sum(1 for t in CORPUS if cs_describe_unsafe_address(t) is None)
print(f"  of those, agent accepts        {accepted}")
print(f"          agent rejects          {len(CORPUS) - accepted}")
check(accepted > 100, f"corpus accepts too few ranges ({accepted}) to be a real test")
check(len(CORPUS) - accepted > 100,
      f"corpus rejects too few ranges ({len(CORPUS) - accepted}) to be a real test")

# ==============================================================================
# Part B3b - notation strictness, asserted rather than merely tolerated
# ==============================================================================
# The differential test above waves through the whole "agent stricter about notation" class, so
# on its own it cannot tell strictness from absence: mutation testing showed that disabling
# host-bit detection entirely, or dropping the dotted-quad check, moved those inputs into the
# agree bucket and nothing fired.
#
# Safety does not actually depend on this strictness. Host bits sit strictly below the
# candidate's own prefix, and Overlaps only ever compares min(candidate, forbidden) <= candidate
# prefix bits, so an unmasked base address can never change an overlap verdict. What the
# strictness buys is that the address in the audit log is the address in the rule. That is a
# claim the .cs file makes, so it gets asserted here.
print()
print("  notation strictness (asserted, not inferred from the differential):")
HOST_BIT_CASES = ["192.168.1.5/24", "10.0.0.64/25", "169.255.0.0/15", "203.0.113.128/24",
                  "2001:db8::1/64", "9.0.0.0/7"]
HOST_BIT_CASES += [f"{ipaddress.IPv4Address(1 << (32 - p - 1))}/{p}" for p in range(1, 32)]
HOST_BIT_CASES += [f"{ipaddress.IPv6Address(1 << (128 - p - 1))}/{p}" for p in range(1, 128)]
host_bit_ok = 0
for text in HOST_BIT_CASES:
    reason = cs_describe_unsafe_address(text) or ""
    if check("bits set below its prefix length" in reason,
             f"{text} has bits set below its prefix but was not reported as ambiguous "
             f"(message was: {reason!r})"):
        host_bit_ok += 1
print(f"    {host_bit_ok}/{len(HOST_BIT_CASES)} unmasked ranges reported as ambiguous "
      "(covers every prefix length in both families)")

NON_CANONICAL = ["010.0.0.1/32", "10.0.0.01/32", "1.2.3", "10", "0x7f000001", "1.2.3.4.5",
                 "1..2.3", "00.1.2.3", "1.2.3.0400"]
non_canon_ok = 0
for text in NON_CANONICAL:
    reason = cs_describe_unsafe_address(text) or ""
    if check("canonical dotted-quad" in reason or "not a valid IP address" in reason,
             f"the non-canonical IPv4 text {text!r} was not rejected "
             f"(message was: {reason!r})"):
        non_canon_ok += 1
print(f"    {non_canon_ok}/{len(NON_CANONICAL)} non-canonical IPv4 forms rejected "
      "(leading zeros, shorthand, hex)")

# And the converse: canonical forms must NOT be caught by that check.
for text in ["0.0.0.0/8", "10.0.0.0/8", "203.0.113.5", "255.255.255.255/32", "9.9.9.9/32"]:
    reason = cs_describe_unsafe_address(text) or ""
    check("canonical dotted-quad" not in reason and "bits set below" not in reason,
          f"the canonical form {text!r} was wrongly rejected as malformed: {reason!r}")
print("    canonical dotted-quad forms unaffected by either check")

# Overlaps' cross-family short-circuit is unreachable through DescribeUnsafeAddress, which picks
# the forbidden table by family before calling it - mutation testing confirmed that removing the
# guard changes no verdict. It is still load-bearing insurance: in C#, SharesPrefix on a 4-byte
# array with a bit count taken from a 16-byte prefix is an IndexOutOfRangeException, i.e. a crash
# in the WebSocket receive loop rather than a rejected policy. Exercise it directly.
v4 = try_parse_cidr("203.0.113.0/24")
v6 = try_parse_cidr("2001:db8::/32")
check(overlaps(v4, v6) is False and overlaps(v6, v4) is False,
      "cross-family Overlaps did not return false")
for a, b in (("0.0.0.0/8", "::/128"), ("255.255.255.255/32", "ff00::/8"),
             ("127.0.0.0/8", "::ffff:0:0/96")):
    pa, pb = try_parse_cidr(a), try_parse_cidr(b)
    check(overlaps(pa, pb) is False and overlaps(pb, pa) is False,
          f"cross-family Overlaps({a}, {b}) did not return false")
print("    cross-family Overlaps returns false in both directions (guards an index-out-of-range)")

notes.append(
    "Host-bit and dotted-quad strictness are agent-only; the backend normalizes such text via "
    "ipaddress.ip_network(strict=False). This cannot reject a legitimate policy because the "
    "agent only ever sees the normalized output of validate_destination_networks."
)

# ==============================================================================
# Part B4 - the specific cases requirement 3 exists for
# ==============================================================================
print()
print("  requirement-3 cases, explicitly:")
MUST_REJECT = {
    "0.0.0.0/0": "the original injection vector",
    "::/0": "the IPv6 form of it",
    "128.0.0.0/1": "half the internet, without matching everything",
    "169.252.0.0/14": "a public supernet that spans link-local - membership check would miss it",
    "169.254.169.254/32": "cloud instance metadata",
    "127.0.0.53/32": "the systemd-resolved stub, a DNS bypass",
    "::ffff:8.8.8.8/128": "an IPv4 destination smuggled in as IPv6",
    "2002:c000:204::/48": "6to4 tunnelling",
    "2001:0:53aa:64c:2c:1234:5678:9abc/128": "Teredo tunnelling",
    "10.0.0.0/7": "a /7 that reaches outside RFC 1918",
    "255.255.255.255/32": "broadcast",
    "239.255.255.250/32": "SSDP multicast",
}
for cidr, why in MUST_REJECT.items():
    reason = cs_describe_unsafe_address(cidr)
    ok = check(reason is not None, f"agent ACCEPTS {cidr} ({why}) - requirement 3 is not met")
    print(f"    {'reject' if ok else 'ACCEPT!':>7}  {cidr:<42} {why}")

MUST_ACCEPT = ["203.0.113.0/24", "10.20.0.0/24", "2001:db8::/48", "8.8.8.8/32", "2606:4700::/32"]
for cidr in MUST_ACCEPT:
    reason = cs_describe_unsafe_address(cidr)
    ok = check(reason is None, f"agent REFUSES the legitimate range {cidr}: {reason}")
    print(f"    {'accept' if ok else 'REFUSE!':>7}  {cidr:<42} a normal vendor destination")

# /0 is rejected twice over: the explicit prefixlen==0 guard AND the minimum-prefix rule. That
# redundancy is deliberate, but it means the verdict alone cannot tell whether the dedicated
# guard is still there - mutation testing confirmed removing it changes nothing observable. Pin
# the MESSAGE instead, because "matches every address, which would nullify default-deny" is the
# operator-facing explanation for the single case requirement 3 exists to prevent.
for cidr in ("0.0.0.0/0", "::/0"):
    reason = cs_describe_unsafe_address(cidr) or ""
    check("nullify default-deny" in reason,
          f"{cidr} is rejected, but not by the dedicated match-everything guard "
          f"(message was: {reason!r})")
print(f"    {'reason':>7}  {'0.0.0.0/0 and ::/0':<42} "
      "reported as nullifying default-deny, not merely as too broad")

# ==============================================================================
# Part B5 - management address rules (the one unscoped rule)
# ==============================================================================
print()
print("  management_server.ip_addresses (unscoped rule - must be one host):")
# The expected-reason labels are asserted, not just "rejected somehow". Several of these rules
# overlap - 255.255.255.255 is caught by the multicast/reserved test as well as the broadcast one -
# and mutation testing showed that checking only the verdict lets the more specific branch be
# deleted unnoticed. The specific branch exists for its message, so the message is the assertion.
MGMT_REASONS = {
    "range": "is a range, not a single host",
    "unparseable": "is not a valid IP address or CIDR block",
    "empty": "contains an empty ip_addresses entry",
    "unspecified": "is the unspecified address",
    "broadcast": "is the broadcast address",
    "multicast": "is a multicast or reserved address",
}
MGMT_CASES = [
    ("203.0.113.5", None, "a normal management host"),
    ("203.0.113.5/32", None, "explicit /32 is still one host"),
    ("127.0.0.1", None, "loopback IS allowed here - single-box and dev deployments"),
    ("10.4.1.9", None, "private IS allowed here - on-premises deployments"),
    ("2001:db8::5", None, "IPv6 single host"),
    ("::1", None, "IPv6 loopback"),
    ("203.0.113.0/24", "range", "a range would become an any-program allow for 256 hosts"),
    ("0.0.0.0/0", "range", "the whole internet, any program"),
    ("2001:db8::/64", "range", "IPv6 range"),
    ("*", "unparseable", "netsh would read this as a remote-address wildcard"),
    ("any", "unparseable", "same, spelled out"),
    ("", "empty", "empty entry"),
    ("0.0.0.0", "unspecified", "unspecified address"),
    ("255.255.255.255", "broadcast", "broadcast"),
    ("239.255.255.250", "multicast", "multicast"),
    ("224.0.0.1", "multicast", "multicast base"),
    ("ff02::1", "multicast", "IPv6 multicast"),
    ("203.0.113.5:8443", "unparseable", "host:port is not an address"),
]
for value, expect, why in MGMT_CASES:
    reason = cs_describe_unsafe_management_address(value)
    if expect is None:
        ok = check(reason is None, f"management address {value!r} refused ({why}): {reason}")
        print(f"    {'allow' if ok else 'REFUSE!':>7}  {value!r:<20} {why}")
    else:
        ok = check(reason is not None and MGMT_REASONS[expect] in reason,
                   f"management address {value!r} ({why}) should be refused as {expect!r} "
                   f"({MGMT_REASONS[expect]!r}), got: {reason!r}")
        print(f"    {'refuse' if ok else 'WRONG!':>7}  {value!r:<20} {expect + ' - ' + why}")

# A single host must never be refused, whatever it is - that would break deployments.
for _ in range(2000):
    octets = [rng.randint(1, 223), rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255)]
    if octets[0] in (0,):
        continue
    text = ".".join(str(o) for o in octets)
    if text == "255.255.255.255":
        continue
    check(cs_describe_unsafe_management_address(text) is None,
          f"management address {text} (a unicast single host) was refused")

# ==============================================================================
# Part B6 - destination names, differentially
# ==============================================================================
print()
NAME_CORPUS = [
    "vendor", "moodle-primary", "Moodle Primary", "a" * 64, "a" * 65, "", "   ", "\t",
    "pipe|name", 'quote"name', "apos'name", "back`tick", "back\\slash", "for/ward",
    "ctrl\x01name", "del\x7fname", "  trimmed  ", "unicode-\u00e9", "dot.name",
    "SPEMCS-x-y-z", "name with spaces", "tab\tinside", "newline\ninside",
]
name_agree = 0
name_diff = []
for name in NAME_CORPUS:
    agent_reason = cs_describe_unsafe_name(name)
    try:
        validate_destination_name(name)
        backend_ok = True
    except DestinationResolutionError:
        backend_ok = False
    if (agent_reason is None) == backend_ok:
        name_agree += 1
    else:
        name_diff.append((name, agent_reason, backend_ok))
print(f"  name corpus                    {len(NAME_CORPUS)} names")
print(f"  identical verdict              {name_agree}")
for name, agent_reason, backend_ok in name_diff:
    # Python's str.strip() also strips \x1c-\x1f, C#'s Trim() does not. Only a divergence for
    # names the compiler would have trimmed before signing, so it cannot reach the agent.
    print(f"    divergence {name!r}: agent={agent_reason!r} backend_ok={backend_ok}")
check(not name_diff, f"destination name verdict differs from the backend on {len(name_diff)} names")

# TryValidate composition
check(cs_try_validate(0, "vendor", ["203.0.113.0/24"]) is None, "a valid destination was rejected")
check("carries no ip_ranges" in (cs_try_validate(2, "vendor", []) or ""),
      "a destination with no ip_ranges was accepted; it would produce no rule at all")
check("allowed_destinations[3]" in (cs_try_validate(3, "vendor", ["0.0.0.0/0"]) or ""),
      "the rejection message does not name the offending index")
check("allowed_destinations[1]" in (cs_try_validate(1, "bad|name", ["203.0.113.0/24"]) or ""),
      "an unsafe destination name was accepted")
check(cs_try_validate(0, "vendor", ["203.0.113.0/24", "0.0.0.0/0"]) is not None,
      "one bad range among good ones was not caught")

# ==============================================================================
print()
print("=" * 78)
if failures:
    print(f"FAILED - {len(failures)} problem(s)")
    for i, message in enumerate(failures, 1):
        print(f"\n{i}. {message}")
    sys.exit(1)
print("PASSED - structural balance clean; agent and backend agree on every case in the corpus")
for note in notes:
    print(f"  note: {note}")
print("  run with --self-check to re-prove the corpus can actually fail")


# ==============================================================================
# --emit-fixture: hand the same corpus to xunit
# ==============================================================================
def cs_literal(text):
    out = ['"']
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def emit_fixture(path):
    """Writes the corpus as C# so the real validator faces the identical cases.

    Deliberately NOT all 4534 differential inputs: the curated boundary cases plus a
    deterministic sample keep the generated file reviewable, and the exhaustive sweep stays on
    the Python side where it costs nothing. Every case that distinguishes a correct validator
    from one of the 27 mutants is in the curated set.
    """
    curated = []
    for cidr in MUST_REJECT:
        curated.append(cidr)
    curated.extend(MUST_ACCEPT)
    for cidr, _reason in list(FORBIDDEN_V4) + list(FORBIDDEN_V6):
        net = ipaddress.ip_network(cidr)
        minimum = MIN_PREFIX_V4 if net.version == 4 else MIN_PREFIX_V6
        curated.append(cidr)
        for shorter in range(net.prefixlen - 1, minimum - 1, -1):
            curated.append(str(net.supernet(new_prefix=shorter)))
        curated.append(f"{net.network_address}/{net.max_prefixlen}")
        curated.append(f"{net.broadcast_address}/{net.max_prefixlen}")
        below = int(net.network_address) - 1
        above = int(net.broadcast_address) + 1
        cls = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
        if below >= 0:
            curated.append(f"{cls(below)}/{net.max_prefixlen}")
        if above < 2 ** net.max_prefixlen:
            curated.append(f"{cls(above)}/{net.max_prefixlen}")
    curated.extend(HOST_BIT_CASES)
    curated.extend(NON_CANONICAL)
    curated.extend([
        "203.0.113.5", "2001:db8::1", " 203.0.113.5/32 ", "203.0.113.5/33", "203.0.113.5/-1",
        "203.0.113.5/", "203.0.113.5/x", "203.0.113.5//32", "203.0.113.5/032", "", "   ",
        "*", "any", "203.0.113.5:443", "203.0.113.5-203.0.113.9", "not-an-ip",
        "2001:db8::1/129", "::ffff:0:0/95", "2002::/15", "2001::/31", "fe80::/9", "ff00::/7",
        "fc00::/7", "fd00::/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24",
    ])
    sample = ipaddress
    rng2 = random.Random(20260905)
    for _ in range(200):
        curated.append(str(ipaddress.ip_network((rng2.getrandbits(32), rng2.randint(0, 32)),
                                                strict=False)))
    for _ in range(200):
        curated.append(str(ipaddress.ip_network((rng2.getrandbits(128), rng2.randint(0, 128)),
                                                strict=False)))
    curated = list(dict.fromkeys(curated))

    dest_rows = [(text, cs_describe_unsafe_address(text) is None) for text in curated]
    mgmt_rows = [(value, cs_describe_unsafe_management_address(value) is None)
                 for value, _e, _w in MGMT_CASES]
    name_rows = [(name, cs_describe_unsafe_name(name) is None) for name in NAME_CORPUS]
    reason_rows = [
        ("0.0.0.0/0", "nullify default-deny"),
        ("::/0", "nullify default-deny"),
        ("169.252.0.0/14", "169.254.0.0/16"),
        ("169.254.169.254/32", "169.254.0.0/16"),
        ("127.0.0.53/32", "127.0.0.0/8"),
        ("::ffff:8.8.8.8/128", "::ffff:0:0/96"),
        ("2002:c000:204::/48", "2002::/16"),
        ("2001:0:53aa:64c:2c:1234:5678:9abc/128", "2001::/32"),
        ("128.0.0.0/1", "widest allowed IPv4 prefix"),
        ("1000::/8", "widest allowed IPv6 prefix"),
        ("192.168.1.5/24", "bits set below its prefix length"),
        ("010.0.0.1/32", "canonical dotted-quad"),
        ("239.255.255.250/32", "224.0.0.0/4"),
        # Reported as "reserved", not "the broadcast address": 255.255.255.255 lies inside
        # 240.0.0.0/4, which comes first in the table. The backend's table is ordered the same
        # way and reports the same reason, so the dedicated broadcast entry is unreachable for
        # destinations on BOTH sides - it earns its place only in the management-address rules,
        # where there is no enclosing reserved range to catch it.
        ("255.255.255.255/32", "240.0.0.0/4"),
    ]
    for cidr, fragment in reason_rows:
        actual = cs_describe_unsafe_address(cidr) or ""
        assert fragment in actual, (
            f"fixture reason row is wrong: {cidr} -> {actual!r} does not contain {fragment!r}"
        )

    denied = sum(1 for _t, allowed in dest_rows if not allowed)
    lines = [
        "// GENERATED FILE - do not edit by hand.",
        "//",
        "// Regenerate with:",
        "//   python3 Endpoint-agent/tests/parity/verify_policy_destination_validator_parity.py \\",
        "//       --emit-fixture Endpoint-agent/tests/Spemcs.Agent.Tests/AddressValidationFixtures.cs",
        "//",
        "// The expected verdicts below are produced by a transliteration of",
        "// PolicyDestinationValidator.cs that has been differential-tested against",
        "// backend/backend/services/policy_compiler.py over several thousand inputs, and whose own",
        "// corpus is mutation-tested (--self-check). So these are not this validator's current",
        "// behaviour recorded as gospel: they are the BACKEND's behaviour, which is what the agent",
        "// is required to agree with.",
        "",
        "namespace Spemcs.Agent.Tests;",
        "",
        "/// <summary>Address, name and management-address cases shared with the Python parity harness.</summary>",
        "internal static class AddressValidationFixtures",
        "{",
        f"    /// <summary>Destination ip_ranges entries. {denied} of {len(dest_rows)} must be refused.</summary>",
        "    public static readonly (string Value, bool Allowed)[] DestinationAddresses =",
        "    {",
    ]
    for text, allowed in dest_rows:
        lines.append(f"        ({cs_literal(text)}, {'true' if allowed else 'false'}),")
    lines += [
        "    };",
        "",
        "    /// <summary>management_server.ip_addresses entries - the one rule that is not program-scoped.</summary>",
        "    public static readonly (string Value, bool Allowed)[] ManagementAddresses =",
        "    {",
    ]
    for text, allowed in mgmt_rows:
        lines.append(f"        ({cs_literal(text)}, {'true' if allowed else 'false'}),")
    lines += [
        "    };",
        "",
        "    /// <summary>Destination names, which become the purpose segment of a firewall rule name.</summary>",
        "    public static readonly (string Value, bool Allowed)[] DestinationNames =",
        "    {",
    ]
    for text, allowed in name_rows:
        lines.append(f"        ({cs_literal(text)}, {'true' if allowed else 'false'}),")
    lines += [
        "    };",
        "",
        "    /// <summary>Cases where the REASON matters, not just the verdict - several rules overlap,",
        "    /// and a message assertion is what keeps the more specific branch from being deleted unnoticed.</summary>",
        "    public static readonly (string Value, string ReasonFragment)[] RejectionReasons =",
        "    {",
    ]
    for text, fragment in reason_rows:
        lines.append(f"        ({cs_literal(text)}, {cs_literal(fragment)}),")
    lines += ["    };", "}", ""]

    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines))
    print()
    print(f"  fixture written: {os.path.relpath(path, REPO)}")
    print(f"    {len(dest_rows)} destination addresses ({denied} refused), "
          f"{len(mgmt_rows)} management addresses, {len(name_rows)} names, "
          f"{len(reason_rows)} reason assertions")


if EMIT_FIXTURE:
    emit_fixture(os.path.abspath(EMIT_FIXTURE))

sys.exit(0)
