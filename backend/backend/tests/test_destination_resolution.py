"""Trusted destination resolution and address-safety tests (requirement 3).

The defect these tests exist to prevent: `POST /api/policies/compile/{exam_id}` used to copy
`resolved_destinations[].ip_ranges` from the request body straight into the payload it signed.
The endpoint agent turns every entry of `allowed_destinations` directly into a Windows Firewall
allow rule scoped to the examination browser, and performed no address checking of its own. So a
single request containing `0.0.0.0/0` yielded a correctly signed, schema-valid policy that
re-opened the entire internet for the browser under exam conditions - defeating the default-deny
posture that the rest of the system exists to establish, while looking legitimate to every
downstream check.

Two independent properties are therefore asserted here:

* **Provenance** - addresses may only come from server-side vendor profile data or from this
  server's own trusted DNS resolution. A caller may name domains; never addresses.
* **Safety** - loopback, link-local (including the cloud metadata address), multicast, reserved,
  IPv4-mapped IPv6, 6to4/Teredo tunnel ranges, and over-broad prefixes are refused no matter
  which of those sources they arrive from, because a poisoned DNS answer is just as dangerous as
  a hostile request body.

This module deliberately imports nothing from fastapi, pydantic or sqlalchemy so that the
security-critical logic is testable without a database or a web stack.
"""

import ipaddress
import socket
import struct
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from backend.services.destination_resolver import (
    DnsConfigurationError,
    DnsResolutionError,
    ResolutionLimits,
    StaticDnsResolver,
    TrustedDestinationResolver,
    TrustedDnsResolver,
    build_destination_resolver,
    build_resolver_from_settings,
)
from backend.services.destination_resolver import (
    _encode_name,
    _parse_response,
)
from backend.services.policy_compiler import (
    AddressPolicy,
    DestinationLimitExceededError,
    DestinationResolutionError,
    EmptyAllowlistError,
    PolicyCompilationError,
    UnsafeDestinationAddressError,
    UntrustedDestinationError,
    compile_exam_policy,
    describe_unsafe_network,
    validate_destination_name,
    validate_destination_networks,
)

FIXED_NOW = datetime(2026, 9, 5, 4, 12, 0, tzinfo=timezone.utc)
MGMT = {"ip_addresses": ["203.0.113.5"], "port": 8443}
VENDOR_ID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"


def _clock():
    return FIXED_NOW


@pytest.fixture
def resolver():
    """A resolver over a fixed domain map - no network, fully deterministic."""
    return TrustedDestinationResolver(
        StaticDnsResolver(
            {
                "lms.univ.edu": ["198.51.100.7", "198.51.100.8", "2606:4700::7"],
                "cdn.univ.edu": ["203.0.113.9"],
                "metadata.univ.edu": ["169.254.169.254"],
                "loopback.univ.edu": ["127.0.0.1"],
                "mixed.univ.edu": ["127.0.0.1", "203.0.113.10"],
                "empty.univ.edu": [],
                "wide.univ.edu": [f"203.0.113.{n}" for n in range(1, 40)],
            }
        ),
        clock=_clock,
    )


def _profile(**overrides):
    profile = {
        "vendor_id": VENDOR_ID,
        "vendor_name": "Pearson VUE",
        "required_domains": ["lms.univ.edu"],
        "approved_ip_ranges": ["10.1.0.0/24"],
        "required_tcp_ports": [443],
        "required_udp_ports": [],
    }
    profile.update(overrides)
    return profile


def _compile(**overrides):
    kwargs = dict(
        exam_id=uuid.uuid4(),
        version=1,
        vendor_profile=_profile(),
        management_server=MGMT,
        not_before=FIXED_NOW,
        expires_at=FIXED_NOW + timedelta(hours=3),
        approved_browser="chrome",
        key_id="spemcs-test-key",
    )
    kwargs.update(overrides)
    return compile_exam_policy(**kwargs)


# ==============================================================================
# 1. Address safety: the ranges that must never reach an allowlist
# ==============================================================================
@pytest.mark.parametrize(
    "cidr",
    [
        "0.0.0.0/0",             # the entire IPv4 internet
        "::/0",                  # the entire IPv6 internet
        "128.0.0.0/1",           # half the internet
        "10.0.0.0/7",            # broader than the widest allowed IPv4 prefix
        "::/16",                 # broader than the widest allowed IPv6 prefix
        "0.0.0.0/8",             # this-network / unspecified
        "127.0.0.1/32",          # loopback
        "127.0.0.53/32",         # the systemd stub resolver - the old test's own value
        "::1/128",               # IPv6 loopback
        "169.254.0.0/16",        # link-local
        "169.254.169.254/32",    # cloud instance metadata
        "169.252.0.0/14",        # a supernet that *covers* link-local while starting outside it
        "224.0.0.1/32",          # multicast
        "240.0.0.0/4",           # reserved
        "255.255.255.255/32",    # broadcast
        "fe80::1/128",           # IPv6 link-local
        "ff02::1/128",           # IPv6 multicast
        "::ffff:127.0.0.1/128",  # IPv4-mapped IPv6
        "2002:c000:204::/48",    # 6to4 tunnel range
        "2001:0:53aa::/48",      # Teredo tunnel range
    ],
)
def test_unsafe_ranges_are_refused(cidr):
    reason = describe_unsafe_network(ipaddress.ip_network(cidr))
    assert reason, f"{cidr} must be refused"
    with pytest.raises(UnsafeDestinationAddressError) as exc:
        validate_destination_networks([cidr])
    # The error has to be actionable: it names the range (in normalized form, which is what an
    # operator will see in the compiled policy) and the reason.
    assert str(ipaddress.ip_network(cidr)) in str(exc.value)
    assert "cannot be allowed because" in str(exc.value)


@pytest.mark.parametrize(
    "cidr",
    [
        "198.51.100.7/32",
        "203.0.113.0/24",
        "8.8.8.8/32",
        "10.1.0.0/24",      # RFC 1918, permitted by default for on-premises deployments
        "172.16.5.0/24",
        "192.168.1.0/24",
        "2606:4700::7/128",
        "2606:4700::/32",
    ],
)
def test_safe_ranges_are_accepted(cidr):
    assert describe_unsafe_network(ipaddress.ip_network(cidr)) is None
    assert validate_destination_networks([cidr]) == [cidr]


def test_private_ranges_can_be_refused_by_configuration():
    strict = AddressPolicy(allow_private=False)
    assert describe_unsafe_network(ipaddress.ip_network("10.1.0.0/24"), strict)
    assert describe_unsafe_network(ipaddress.ip_network("fc00::1/128"), strict)
    # Public destinations are unaffected.
    assert describe_unsafe_network(ipaddress.ip_network("203.0.113.0/24"), strict) is None


def test_loopback_is_refused_even_though_the_agent_allows_loopback_rules():
    """The endpoint does add loopback allow rules, but never from the policy allowlist.

    Those rules are built unconditionally by the agent for agent IPC and the DNS stub. A
    loopback address arriving as a *destination* means something is wrong - it cannot leave the
    machine, so it is never a real exam destination, and accepting it would let a policy silently
    widen the deliberately unscoped loopback surface.
    """
    assert describe_unsafe_network(ipaddress.ip_network("127.0.0.0/8"))
    assert describe_unsafe_network(ipaddress.ip_network("::1/128"))


# ==============================================================================
# 2. Provenance: a caller may name domains, never addresses
# ==============================================================================
@pytest.mark.parametrize("field", ["ip_ranges", "ips", "addresses", "resolved_ips", "resolution"])
def test_caller_supplied_addresses_are_rejected_by_the_compiler(field):
    with pytest.raises(UntrustedDestinationError) as exc:
        _compile(resolved_destinations=[{"name": "Injected", field: ["0.0.0.0/0"]}])
    assert field in str(exc.value)


@pytest.mark.parametrize(
    "ranges",
    [
        ["0.0.0.0/0"],
        ["::/0"],
        ["203.0.113.99/32"],     # a plausible-looking single host is just as forbidden
        ["127.0.0.53/32"],
        ["169.254.169.254/32"],
    ],
)
def test_the_original_injection_vector_is_closed(ranges):
    """The exact shape of the old request body must now fail, whatever address it carries.

    Parametrised over both a wide-open range and an innocuous-looking single host: the rule is
    about *provenance*, not about how dangerous the individual address looks. A reviewer who only
    blocked `/0` would leave the vector open.
    """
    with pytest.raises(UntrustedDestinationError):
        _compile(
            resolved_destinations=[
                {"name": "Local Resolver", "ip_ranges": ranges, "tcp_ports": [53], "udp_ports": [53]}
            ]
        )


def test_caller_supplied_addresses_are_rejected_by_the_resolver_too(resolver):
    """Both layers reject independently, so neither is load-bearing on its own."""
    with pytest.raises(UntrustedDestinationError):
        resolver.resolve_requested_destinations([{"name": "X", "ip_ranges": ["0.0.0.0/0"]}])


def test_unknown_destination_fields_are_rejected():
    """An unknown key is a failed injection attempt or a client bug; either way, not ignorable.

    `applicationPath` is the specific field worth naming: the endpoint scopes allow rules to the
    approved browser's executable, and a caller that could set it would aim it at curl.exe.
    """
    with pytest.raises(PolicyCompilationError) as exc:
        _compile(
            resolved_destinations=[
                {"name": "X", "domains": ["cdn.univ.edu"], "applicationPath": "C:/curl.exe"}
            ]
        )
    assert "applicationPath" in str(exc.value)


def test_a_destination_with_no_domains_is_rejected(resolver):
    with pytest.raises(DestinationResolutionError):
        resolver.resolve_requested_destinations([{"name": "X", "tcp_ports": [443]}])


def test_vendor_profile_addresses_are_still_safety_checked():
    """Server-side data is trusted for provenance but not for correctness.

    An operator can mistype a vendor profile, and a compromised admin account can edit one. The
    address-safety gate applies to the profile exactly as it does to a request body.
    """
    with pytest.raises(UnsafeDestinationAddressError):
        _compile(vendor_profile=_profile(required_domains=[], approved_ip_ranges=["0.0.0.0/0"]))


# ==============================================================================
# 3. Resolution: domains become addresses, and the association is recorded
# ==============================================================================
def test_resolution_produces_normalized_host_cidrs(resolver):
    assert resolver.resolve_domain("cdn.univ.edu") == ["203.0.113.9/32"]
    # IPv4 sorts before IPv6, and bare addresses become /32 and /128.
    assert resolver.resolve_domain("lms.univ.edu") == [
        "198.51.100.7/32",
        "198.51.100.8/32",
        "2606:4700::7/128",
    ]


def test_both_ip_families_survive_into_the_allowlist(resolver):
    dest = resolver.build_allowlist(vendor_profile=_profile())[0]
    versions = {ipaddress.ip_network(c).version for c in dest["ip_ranges"]}
    assert versions == {4, 6}, "an IPv6-only destination must not be silently dropped"


def test_static_and_resolved_addresses_are_merged_and_deduplicated(resolver):
    dest = resolver.build_allowlist(
        vendor_profile=_profile(
            required_domains=["lms.univ.edu", "cdn.univ.edu"],
            approved_ip_ranges=["10.1.0.0/24", "203.0.113.9/32"],  # overlaps a resolved address
        )
    )[0]
    assert dest["ip_ranges"] == [
        "10.1.0.0/24",
        "198.51.100.7/32",
        "198.51.100.8/32",
        "203.0.113.9/32",
        "2606:4700::7/128",
    ]
    assert len(dest["ip_ranges"]) == len(set(dest["ip_ranges"]))


def test_resolution_provenance_is_recorded_inside_the_destination(resolver):
    dest = resolver.build_allowlist(
        vendor_profile=_profile(required_domains=["lms.univ.edu", "cdn.univ.edu"])
    )[0]
    resolution = dest["resolution"]

    assert resolution["resolved_at"] == "2026-09-05T04:12:00Z"
    assert resolution["static_ranges"] == ["10.1.0.0/24"]
    assert resolution["domain_map"]["cdn.univ.edu"] == ["203.0.113.9/32"]
    assert resolution["domain_map"]["lms.univ.edu"] == [
        "198.51.100.7/32",
        "198.51.100.8/32",
        "2606:4700::7/128",
    ]
    # Every resolved address is attributable to a domain or to the static ranges: an address with
    # no recorded origin would make the signed policy unauditable.
    attributed = set(resolution["static_ranges"])
    for ips in resolution["domain_map"].values():
        attributed.update(ips)
    assert set(dest["ip_ranges"]) == attributed


def test_provenance_survives_compilation(resolver):
    """The provenance block must reach the signed bytes.

    It is nested inside the destination rather than added at the envelope top level because the
    agent enforces a strict whitelist of top-level fields and rejects unknown ones, while
    ignoring unknown keys inside a destination.
    """
    allowed = resolver.build_allowlist(vendor_profile=_profile())
    payload = _compile(allowed_destinations=allowed)
    assert payload["allowed_destinations"][0]["resolution"]["source"] == "static-map+static"
    # The envelope itself must not have grown a field.
    assert "resolution" not in payload


def test_a_static_only_destination_needs_no_resolver():
    """A deployment that pins explicit ranges must work with no DNS configuration at all."""
    dest = TrustedDestinationResolver(None).resolve_vendor_profile(
        {"vendor_id": VENDOR_ID, "vendor_name": "Static", "approved_ip_ranges": ["203.0.113.0/24"]}
    )
    assert dest["ip_ranges"] == ["203.0.113.0/24"]
    assert dest["resolution"]["source"] == "static"
    assert dest["resolution"]["domain_map"] == {}


def test_resolver_output_is_order_independent(resolver):
    a = resolver.build_allowlist(
        vendor_profile=_profile(
            required_domains=["lms.univ.edu", "cdn.univ.edu"],
            approved_ip_ranges=["10.1.0.0/24", "203.0.113.0/24"],
        )
    )
    b = resolver.build_allowlist(
        vendor_profile=_profile(
            required_domains=["cdn.univ.edu", "lms.univ.edu"],
            approved_ip_ranges=["203.0.113.0/24", "10.1.0.0/24"],
        )
    )
    assert a == b, "resolution must be deterministic; signatures depend on byte-identical output"


# ==============================================================================
# 4. Poisoned answers
# ==============================================================================
def test_a_poisoned_answer_cannot_enter_the_allowlist(resolver):
    """DNS is an input, not an authority. An answer of 169.254.169.254 is refused."""
    with pytest.raises(DnsResolutionError) as exc:
        resolver.resolve_domain("metadata.univ.edu")
    assert "169.254.169.254" in str(exc.value)


def test_a_loopback_answer_is_refused(resolver):
    with pytest.raises(DnsResolutionError):
        resolver.resolve_domain("loopback.univ.edu")


def test_unsafe_answers_are_dropped_when_safe_ones_remain(resolver):
    """One bad record among good ones is normal; only an all-bad answer is a configuration error.

    A service that also publishes an internal address is common, and failing the whole exam
    because of it would be a worse failure than ignoring the record. The distinction is that
    nothing unsafe ever reaches the allowlist either way.
    """
    assert resolver.resolve_domain("mixed.univ.edu") == ["203.0.113.10/32"]


# ==============================================================================
# 5. Deterministic failure, never a silently empty allowlist
# ==============================================================================
def test_an_unresolvable_domain_fails_loudly(resolver):
    with pytest.raises(DnsResolutionError) as exc:
        resolver.resolve_domain("absent.univ.edu")
    assert "absent.univ.edu" in str(exc.value)


def test_an_empty_answer_fails_loudly(resolver):
    with pytest.raises(DnsResolutionError):
        resolver.resolve_domain("empty.univ.edu")


def test_a_domain_with_no_resolver_configured_fails_loudly():
    """The failure names the domain and the setting to change.

    The alternative - dropping the domain and compiling an allowlist without it - produces a
    policy that passes every signature and schema check and then blocks the examination at exam
    time with nothing pointing at the cause.
    """
    with pytest.raises(DnsConfigurationError) as exc:
        TrustedDestinationResolver(None).resolve_domain("lms.univ.edu")
    message = str(exc.value)
    assert "lms.univ.edu" in message
    assert "TRUSTED_DNS_SERVERS" in message


def test_a_domain_only_profile_cannot_compile_to_an_empty_allowlist():
    """Without resolution, a domain-only profile must fail rather than compile to nothing."""
    with pytest.raises(EmptyAllowlistError) as exc:
        _compile(vendor_profile=_profile(required_domains=["lms.univ.edu"], approved_ip_ranges=[]))
    assert "lms.univ.edu" in str(exc.value)


def test_a_destination_with_no_addresses_is_rejected():
    """The endpoint builds rules from ip_ranges only, so an empty list means "no rule at all"."""
    with pytest.raises(EmptyAllowlistError):
        _compile(
            allowed_destinations=[
                {"name": "Ghost", "domains": ["lms.univ.edu"], "ip_ranges": [], "tcp_ports": [443]}
            ]
        )


def test_a_policy_with_no_destinations_at_all_is_rejected():
    with pytest.raises(EmptyAllowlistError):
        _compile(vendor_profile=None)


def test_an_exam_with_no_vendor_profile_is_rejected_by_the_resolver(resolver):
    with pytest.raises(EmptyAllowlistError):
        resolver.build_allowlist(vendor_profile=None)


# ==============================================================================
# 6. Expansion limits
# ==============================================================================
def test_a_domain_resolving_to_too_many_addresses_is_refused(resolver):
    """A CDN front door cannot be expressed as a firewall allowlist; say so instead of trying.

    Truncating would produce a policy that looks complete and then fails unpredictably, on some
    candidates' machines and not others, depending on which records their exam happened to get.
    """
    with pytest.raises(DestinationLimitExceededError) as exc:
        resolver.resolve_domain("wide.univ.edu")
    assert "39" in str(exc.value)


def test_the_per_policy_address_cap_is_enforced(resolver):
    tight = TrustedDestinationResolver(
        StaticDnsResolver({"lms.univ.edu": ["198.51.100.7", "198.51.100.8"]}),
        limits=ResolutionLimits(max_addresses_per_policy=2),
        clock=_clock,
    )
    with pytest.raises(DestinationLimitExceededError):
        tight.build_allowlist(
            vendor_profile=_profile(required_domains=["lms.univ.edu"], approved_ip_ranges=["10.1.0.0/24"])
        )


def test_the_destination_count_cap_is_enforced(resolver):
    tight = TrustedDestinationResolver(
        StaticDnsResolver({"cdn.univ.edu": ["203.0.113.9"]}),
        limits=ResolutionLimits(max_destinations=1),
        clock=_clock,
    )
    with pytest.raises(DestinationLimitExceededError):
        tight.build_allowlist(
            vendor_profile={"vendor_id": VENDOR_ID, "vendor_name": "V", "approved_ip_ranges": ["10.1.0.0/24"]},
            requested_destinations=[{"name": "Extra", "domains": ["cdn.univ.edu"]}],
        )


# ==============================================================================
# 7. Destination names become firewall rule names
# ==============================================================================
@pytest.mark.parametrize(
    "name",
    [
        "A|B",            # the field delimiter in the firewall rule registry representation
        'A"B',
        "A'B",
        "A\\B",
        "A/B",
        "A\nB",           # log and rule-name injection
        "A\tB",
        "\x7fB",
        "   ",
        "",
        "x" * 65,
    ],
)
def test_unsafe_destination_names_are_refused(name):
    with pytest.raises(DestinationResolutionError):
        validate_destination_name(name)


def test_destination_names_are_trimmed():
    assert validate_destination_name("  Pearson VUE  ") == "Pearson VUE"


def test_duplicate_destination_names_are_refused(resolver):
    """The name is the rule's `purpose` segment on the endpoint and must identify it uniquely."""
    allowed = resolver.build_allowlist(vendor_profile=_profile())
    with pytest.raises(PolicyCompilationError) as exc:
        _compile(allowed_destinations=[allowed[0], dict(allowed[0])])
    assert "Duplicate destination name" in str(exc.value)


def test_duplicate_names_are_refused_case_insensitively(resolver):
    with pytest.raises(DestinationResolutionError):
        resolver.build_allowlist(
            vendor_profile={"vendor_id": VENDOR_ID, "vendor_name": "Vendor", "approved_ip_ranges": ["10.1.0.0/24"]},
            requested_destinations=[{"name": "vendor", "domains": ["cdn.univ.edu"]}],
        )


# ==============================================================================
# 8. The compiler re-validates, so the resolver is not the only gate
# ==============================================================================
def test_the_compiler_refuses_unsafe_addresses_it_did_not_resolve_itself():
    """A future caller that assembles an allowlist by some other route must not bypass safety."""
    with pytest.raises(UnsafeDestinationAddressError):
        _compile(
            allowed_destinations=[
                {"name": "Handmade", "domains": [], "ip_ranges": ["0.0.0.0/0"], "tcp_ports": [443]}
            ]
        )


def test_key_id_has_no_default():
    """A placeholder key id would compile policies that verify against nothing."""
    with pytest.raises(TypeError):
        compile_exam_policy(
            exam_id=uuid.uuid4(),
            version=1,
            vendor_profile=_profile(required_domains=[]),
            management_server=MGMT,
            not_before=FIXED_NOW,
            expires_at=FIXED_NOW + timedelta(hours=1),
            approved_browser="chrome",
        )


def test_blank_key_id_is_refused():
    with pytest.raises(PolicyCompilationError):
        _compile(vendor_profile=_profile(required_domains=[]), key_id="   ")


def test_the_two_destination_inputs_are_mutually_exclusive(resolver):
    allowed = resolver.build_allowlist(vendor_profile=_profile())
    with pytest.raises(PolicyCompilationError):
        _compile(
            allowed_destinations=allowed,
            resolved_destinations=[{"name": "Extra", "domains": ["cdn.univ.edu"]}],
        )


@pytest.mark.parametrize(
    "resolution",
    [
        {"source": "attacker-controlled", "resolved_at": "2026-09-05T04:12:00Z"},
        {"source": "trusted-dns", "resolved_at": "not-a-timestamp"},
        {"source": "", "resolved_at": "2026-09-05T04:12:00Z"},
        {"resolved_at": "2026-09-05T04:12:00Z"},
        "not-an-object",
    ],
)
def test_malformed_provenance_is_refused(resolution):
    """Provenance is signed, so a fabricated block is a reason to refuse to sign."""
    with pytest.raises(PolicyCompilationError):
        _compile(
            allowed_destinations=[
                {
                    "name": "Handmade",
                    "domains": [],
                    "ip_ranges": ["203.0.113.0/24"],
                    "tcp_ports": [443],
                    "resolution": resolution,
                }
            ]
        )


def test_the_signed_envelope_still_has_exactly_eleven_fields(resolver):
    """The agent rejects unknown top-level fields, so the envelope must not have grown one."""
    payload = _compile(allowed_destinations=resolver.build_allowlist(vendor_profile=_profile()))
    assert sorted(payload.keys()) == [
        "allowed_destinations",
        "approved_browser",
        "exam_id",
        "expires_at",
        "key_id",
        "management_server",
        "not_before",
        "policy_id",
        "schema_version",
        "vendor_profile_id",
        "version",
    ]


# ==============================================================================
# 9. The DNS client itself
# ==============================================================================
def _dns_response(txn_id, question, qtype, answers, flags=0x8180, qdcount=1, echo=None):
    """Builds a DNS response message. `echo` overrides the question section verbatim."""
    body = (echo if echo is not None else question) + struct.pack("!HH", qtype, 1)
    out = struct.pack("!HHHHHH", txn_id, flags, qdcount, len(answers), 0, 0) + body
    for owner, rtype, rdata in answers:
        out += _encode_name(owner) + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    return out


class _FakeSocket:
    """Stands in for a UDP/TCP socket, echoing whatever answer the test configures.

    Using the real `_query` path means the transaction id, the DNS-0x20 case pattern and the
    question echo are all produced and checked by production code, not by the test.
    """

    def __init__(self, answers, *, flags=0x8180, echo_question=True, corrupt_txn=False, stream=False):
        self._answers = answers
        self._flags = flags
        self._echo_question = echo_question
        self._corrupt_txn = corrupt_txn
        self._stream = stream
        self._pending = b""
        self.sent = []
        self.closed = False

    def settimeout(self, _t):
        pass

    def connect(self, _addr):
        pass

    def send(self, data):
        if self._stream:
            data = data[2:]  # strip the TCP length prefix
        self.sent.append(data)
        txn_id, _flags, _qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        question = data[12:-4]
        qtype = struct.unpack("!H", data[-4:-2])[0]
        response = _dns_response(
            # Flipping every bit guarantees a mismatch; a fixed wrong value would collide with
            # the real (random) id once in 65536 runs and make this test flaky.
            txn_id ^ 0xFFFF if self._corrupt_txn else txn_id,
            question,
            qtype,
            [a for a in self._answers if a[1] in (qtype, 5)],
            flags=self._flags,
            # A different name, not a differently-cased one: DNS-0x20 occasionally produces an
            # all-lowercase query, so echoing the lowercase form would sometimes match.
            echo=None if self._echo_question else _encode_name("attacker.example"),
        )
        self._pending = (struct.pack("!H", len(response)) + response) if self._stream else response
        return len(data)

    def recv(self, size):
        chunk, self._pending = self._pending[:size], self._pending[size:]
        return chunk

    def close(self):
        self.closed = True


def _trusted(answers, **kwargs):
    sockets = []

    def factory(family, kind):
        sock = _FakeSocket(answers, stream=(kind == socket.SOCK_STREAM), **kwargs)
        sockets.append(sock)
        return sock

    return TrustedDnsResolver(["203.0.113.53"], attempts=1, socket_factory=factory), sockets


def test_the_dns_client_reads_a_and_aaaa_records():
    dns, sockets = _trusted(
        [
            ("lms.univ.edu", 1, ipaddress.IPv4Address("198.51.100.7").packed),
            ("lms.univ.edu", 28, ipaddress.IPv6Address("2606:4700::7").packed),
        ]
    )
    assert sorted(dns.resolve("lms.univ.edu")) == ["198.51.100.7", "2606:4700::7"]
    assert all(s.closed for s in sockets), "every socket must be closed even on the happy path"


def test_the_query_uses_dns_0x20_case_randomization():
    """Case randomization plus a byte-exact echo check raises the bar for off-path spoofing.

    An attacker who guesses the 16-bit transaction id must also reproduce the case pattern of the
    query name. Over many attempts at least one label must differ from the lowercase form.
    """
    seen_mixed = False
    for _ in range(24):
        dns, sockets = _trusted([("lms.univ.edu", 1, ipaddress.IPv4Address("198.51.100.7").packed)])
        dns.resolve("lms.univ.edu")
        question = sockets[0].sent[0][12:-4]
        if question != _encode_name("lms.univ.edu"):
            seen_mixed = True
            break
    assert seen_mixed, "queries are always lowercase; DNS-0x20 is not in effect"


def test_a_response_with_the_wrong_transaction_id_is_discarded():
    dns, _ = _trusted(
        [("lms.univ.edu", 1, ipaddress.IPv4Address("198.51.100.7").packed)], corrupt_txn=True
    )
    with pytest.raises(DnsResolutionError) as exc:
        dns.resolve("lms.univ.edu")
    assert "transaction id" in str(exc.value)


def test_a_response_that_does_not_echo_the_question_is_discarded():
    dns, _ = _trusted(
        [("lms.univ.edu", 1, ipaddress.IPv4Address("198.51.100.7").packed)], echo_question=False
    )
    with pytest.raises(DnsResolutionError) as exc:
        dns.resolve("lms.univ.edu")
    assert "does not echo the question" in str(exc.value)


@pytest.mark.parametrize(
    "flags,fragment",
    [
        (0x8183, "NXDOMAIN"),
        (0x8182, "SERVFAIL"),
        (0x8185, "REFUSED"),
        (0x0100, "not a response"),
    ],
)
def test_dns_error_responses_are_distinguished(flags, fragment):
    """Each failure mode reads differently, because they call for different operator action."""
    dns, _ = _trusted([], flags=flags)
    with pytest.raises(DnsResolutionError) as exc:
        dns.resolve("lms.univ.edu")
    assert fragment in str(exc.value)


def test_a_truncated_response_is_retried_over_tcp():
    """TC=1 must trigger the TCP path, not be treated as an empty answer.

    An empty answer would surface as "domain does not resolve" for any destination whose record
    set does not fit in a UDP datagram.
    """
    answers = [("lms.univ.edu", 1, ipaddress.IPv4Address("198.51.100.7").packed)]
    sockets = []
    state = {"first": True}

    def factory(family, kind):
        stream = kind == socket.SOCK_STREAM
        # The first (UDP) exchange sets TC=1; the TCP retry answers normally.
        flags = 0x8380 if (state["first"] and not stream) else 0x8180
        if not stream:
            state["first"] = False
        sock = _FakeSocket(answers, flags=flags, stream=stream)
        sockets.append(sock)
        return sock

    dns = TrustedDnsResolver(["203.0.113.53"], attempts=1, socket_factory=factory)
    assert dns.resolve("lms.univ.edu") == ["198.51.100.7"]
    assert any(s._stream for s in sockets), "the TCP fallback was never attempted"


def test_records_for_an_unrelated_owner_are_ignored():
    """An extra record smuggled into the answer section must not widen the allowlist."""
    question = _encode_name("lms.univ.edu", randomize_case=True)
    data = _dns_response(
        0x1234,
        question,
        1,
        [
            ("lms.univ.edu", 1, ipaddress.IPv4Address("198.51.100.7").packed),
            ("evil.example", 1, ipaddress.IPv4Address("203.0.113.66").packed),
        ],
    )
    addresses, _ = _parse_response(
        data, txn_id=0x1234, question=question, qtype=1, domain="lms.univ.edu"
    )
    assert addresses == ["198.51.100.7"]


def test_a_cname_chain_is_followed():
    question = _encode_name("lms.univ.edu", randomize_case=True)
    data = _dns_response(
        0x1234,
        question,
        1,
        [
            ("lms.univ.edu", 5, _encode_name("edge.cdn.example")),
            ("edge.cdn.example", 1, ipaddress.IPv4Address("203.0.113.9").packed),
        ],
    )
    addresses, _ = _parse_response(
        data, txn_id=0x1234, question=question, qtype=1, domain="lms.univ.edu"
    )
    assert addresses == ["203.0.113.9"]


def test_a_compression_pointer_loop_is_rejected():
    """A malformed response must fail, not hang: this is reachable from the network."""
    question = _encode_name("lms.univ.edu", randomize_case=True)
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    body = question + struct.pack("!HH", 1, 1)
    self_pointer = bytes([0xC0, len(header) + len(body)])
    with pytest.raises(DnsResolutionError) as exc:
        _parse_response(
            header + body + self_pointer,
            txn_id=0x1234,
            question=question,
            qtype=1,
            domain="lms.univ.edu",
        )
    assert "pointer" in str(exc.value)


@pytest.mark.parametrize("rdlength,rtype", [(2, 1), (5, 1), (4, 28), (17, 28)])
def test_a_record_of_the_wrong_length_is_rejected(rdlength, rtype):
    question = _encode_name("lms.univ.edu", randomize_case=True)
    data = _dns_response(0x1234, question, rtype, [("lms.univ.edu", rtype, b"\x01" * rdlength)])
    with pytest.raises(DnsResolutionError):
        _parse_response(
            data, txn_id=0x1234, question=question, qtype=rtype, domain="lms.univ.edu"
        )


def test_multiple_questions_are_rejected():
    question = _encode_name("lms.univ.edu", randomize_case=True)
    data = _dns_response(0x1234, question, 1, [], qdcount=2)
    with pytest.raises(DnsResolutionError) as exc:
        _parse_response(
            data, txn_id=0x1234, question=question, qtype=1, domain="lms.univ.edu"
        )
    assert "questions" in str(exc.value)


def test_dns_servers_must_be_addresses_not_names():
    """Resolving the resolver would be circular, and would move trust to another resolver."""
    with pytest.raises(DnsConfigurationError) as exc:
        TrustedDnsResolver(["dns.example.com"])
    assert "dns.example.com" in str(exc.value)


def test_a_resolver_with_no_servers_is_refused():
    with pytest.raises(DnsConfigurationError):
        TrustedDnsResolver([])


# ==============================================================================
# 10. Configuration
# ==============================================================================
class _Settings:
    def __init__(self, **kwargs):
        self.TRUSTED_DNS_SERVERS = ""
        self.POLICY_DNS_ALLOW_SYSTEM_RESOLVER = False
        self.POLICY_DNS_TIMEOUT_SECONDS = 3.0
        self.POLICY_DNS_ATTEMPTS = 2
        self.POLICY_MAX_ADDRESSES_PER_DOMAIN = 32
        self.POLICY_MAX_ADDRESSES_PER_POLICY = 256
        self.POLICY_ALLOW_PRIVATE_DESTINATIONS = True
        self.__dict__.update(kwargs)


def test_configured_servers_build_a_trusted_resolver():
    built = build_resolver_from_settings(_Settings(TRUSTED_DNS_SERVERS="203.0.113.53, 198.51.100.53"))
    assert isinstance(built, TrustedDnsResolver)
    assert built.servers == ["203.0.113.53", "198.51.100.53"]
    assert built.source_label == "trusted-dns"


def test_no_dns_configuration_yields_no_resolver_rather_than_the_system_one():
    """Fail closed. Falling back to the host resolver silently would move the trust boundary."""
    assert build_resolver_from_settings(_Settings()) is None


def test_the_system_resolver_is_opt_in():
    built = build_resolver_from_settings(_Settings(POLICY_DNS_ALLOW_SYSTEM_RESOLVER=True))
    assert built is not None
    assert built.source_label == "system-resolver"


def test_trusted_servers_take_precedence_over_the_system_resolver():
    built = build_resolver_from_settings(
        _Settings(TRUSTED_DNS_SERVERS="203.0.113.53", POLICY_DNS_ALLOW_SYSTEM_RESOLVER=True)
    )
    assert isinstance(built, TrustedDnsResolver)


def test_the_private_destination_setting_reaches_the_address_policy():
    built = build_destination_resolver(_Settings(POLICY_ALLOW_PRIVATE_DESTINATIONS=False))
    with pytest.raises(UnsafeDestinationAddressError):
        built.resolve_vendor_profile(
            {"vendor_id": VENDOR_ID, "vendor_name": "V", "approved_ip_ranges": ["10.1.0.0/24"]}
        )
