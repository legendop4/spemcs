"""Trusted destination resolution for SPEMCS exam network policies.

Requirement 3 of the network-lockdown contract: every destination in a signed policy must be a
*trusted*, validated, normalized IP/CIDR range, and the backend must never blindly trust resolved
IPs supplied by a client.

Before this module existed, `POST /api/policies/compile/{exam_id}` accepted a
`resolved_destinations` list straight from the request body and copied its `ip_ranges` into the
signed payload. Since the endpoint agent turns every entry of `allowed_destinations` directly into
a Windows Firewall allow rule with no further address checking, one request containing
`{"ip_ranges": ["0.0.0.0/0"]}` produced a correctly signed policy that re-opened the entire
internet for the examination browser - defeating the default-deny posture the rest of the system
exists to establish.

Two things are therefore separated here:

* **Where addresses come from.** Only two sources are trusted: IP ranges stored server-side on the
  vendor profile, and A/AAAA records this module resolves itself. A caller may name *domains*; it
  may never name addresses.
* **Which addresses are acceptable.** Loopback, link-local (including the cloud metadata address),
  multicast, unspecified, IPv4-mapped IPv6, 6to4/Teredo tunnel ranges and over-broad prefixes are
  rejected wherever they come from - including from DNS, because a poisoned or hostile answer of
  `169.254.169.254` or `::ffff:127.0.0.1` is exactly what an allowlist must not absorb.

The resolution result is recorded *inside* each destination object as a `resolution` sub-object, so
the domain-to-address association travels inside the signed bytes and stays auditable after the
fact. It is deliberately nested rather than added at the top level: the agent's policy parser
enforces a strict whitelist of top-level envelope fields and would reject a new one, while unknown
keys inside a destination are ignored by its property-based reader.

This module performs I/O and is therefore kept out of `policy_compiler`, which stays pure and
deterministic. The service layer resolves first, then compiles.
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

from .policy_compiler import (
    DEFAULT_ADDRESS_POLICY,
    AddressPolicy,
    DestinationLimitExceededError,
    DestinationResolutionError,
    EmptyAllowlistError,
    UnsafeDestinationAddressError,
    UntrustedDestinationError,
    describe_unsafe_network,
    normalize_ports,
    validate_and_normalize_domain,
    validate_destination_name,
    validate_destination_networks,
)


# ==============================================================================
# Errors
# ==============================================================================
# The address-safety errors (UnsafeDestinationAddressError, UntrustedDestinationError,
# EmptyAllowlistError, DestinationLimitExceededError) live in policy_compiler alongside the pure
# validation logic they belong to, and are re-exported here so callers only need one import.
# Both they and the DNS errors below subclass PolicyCompilationError, so the compile route's
# existing "PolicyCompilationError -> HTTP 400" mapping reports them as the configuration
# problems they are rather than as an opaque 500.
class DnsConfigurationError(DestinationResolutionError):
    """No usable, trusted DNS configuration exists, so no domain can be resolved."""


class DnsResolutionError(DestinationResolutionError):
    """A domain could not be resolved to any usable address."""


# ==============================================================================
# Resolution limits
# ==============================================================================
@dataclass(frozen=True)
class ResolutionLimits:
    """Bounds on how much an allowlist may expand.

    Every address becomes one or two firewall rules on the endpoint, so an unbounded answer (a
    hostile or misconfigured DNS server returning hundreds of records) would translate into an
    unbounded rule set, a slow activation, and a rollback with far more state to undo. Exceeding
    a bound is a hard error, not a silent truncation: truncating would produce a policy that
    looks complete and fails unpredictably at exam time.
    """

    max_addresses_per_domain: int = 32
    max_addresses_per_policy: int = 256
    max_domains_per_destination: int = 64
    max_destinations: int = 32


# ==============================================================================
# DNS
# ==============================================================================
_DNS_TYPE_A = 1
_DNS_TYPE_AAAA = 28
_DNS_TYPE_CNAME = 5
_DNS_CLASS_IN = 1
_DNS_PORT = 53
_MAX_CNAME_CHAIN = 8
_MAX_NAME_LENGTH = 255

_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DnsResolver(Protocol):
    """Resolves a domain to bare IP address strings.

    Implementations must return only addresses they actually obtained; returning an empty list
    means "no answer", which callers treat as a hard failure rather than an empty allowlist.
    """

    source_label: str

    def resolve(self, domain: str) -> List[str]:  # pragma: no cover - protocol definition
        ...


def _encode_name(name: str, *, randomize_case: bool = False) -> bytes:
    """Encodes a domain as DNS wire-format labels.

    `randomize_case` implements DNS-0x20: the query name is sent with randomly flipped letter
    case and the response's question section is required to match byte-for-byte. DNS label
    comparison is case-insensitive, so a legitimate server echoes the question verbatim, while an
    off-path attacker guessing the transaction id must also guess the case pattern.
    """
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise DnsResolutionError(f"Invalid DNS label in '{name}'")
        if randomize_case:
            raw = bytes(
                (b ^ 0x20) if (0x41 <= (b & ~0x20) <= 0x5A and secrets.randbits(1)) else b
                for b in raw
            )
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > _MAX_NAME_LENGTH:
        raise DnsResolutionError(f"Encoded domain '{name}' exceeds {_MAX_NAME_LENGTH} bytes")
    return bytes(out)


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Reads a possibly-compressed DNS name, returning (lowercased name, offset after the name).

    Compression pointers are followed at most once per visited offset: a response crafted with a
    pointer loop would otherwise spin here forever.
    """
    labels: List[str] = []
    visited = set()
    cursor = offset
    after: Optional[int] = None
    total = 0

    while True:
        if cursor >= len(data):
            raise DnsResolutionError("Truncated DNS name")
        length = data[cursor]

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise DnsResolutionError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if after is None:
                after = cursor + 2
            if pointer in visited or pointer >= len(data):
                raise DnsResolutionError("Invalid or looping DNS compression pointer")
            visited.add(pointer)
            cursor = pointer
            continue

        if length & 0xC0:
            raise DnsResolutionError("Unsupported DNS label type")

        cursor += 1
        if length == 0:
            break

        if cursor + length > len(data):
            raise DnsResolutionError("Truncated DNS label")
        total += length + 1
        if total > _MAX_NAME_LENGTH:
            raise DnsResolutionError("DNS name exceeds maximum length")
        labels.append(data[cursor : cursor + length].decode("ascii", errors="replace").lower())
        cursor += length

    return ".".join(labels), (after if after is not None else cursor)


def _parse_response(
    data: bytes,
    *,
    txn_id: int,
    question: bytes,
    qtype: int,
    domain: str,
) -> Tuple[List[str], bool]:
    """Validates a DNS response and extracts its addresses.

    Returns (addresses, truncated). Everything that does not match the question this resolver
    asked is discarded: an answer section may legitimately contain a CNAME chain, but a record
    for an unrelated owner name is either irrelevant or an attempt to smuggle an extra address
    into the allowlist.
    """
    if len(data) < 12:
        raise DnsResolutionError(f"DNS response for '{domain}' is too short to be a message")

    resp_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])

    if resp_id != txn_id:
        raise DnsResolutionError(
            f"DNS response for '{domain}' has transaction id {resp_id}, expected {txn_id}; "
            "discarding as unsolicited"
        )
    if not flags & 0x8000:
        raise DnsResolutionError(f"DNS response for '{domain}' is not a response (QR=0)")
    if (flags >> 11) & 0x0F:
        raise DnsResolutionError(f"DNS response for '{domain}' has an unexpected opcode")

    truncated = bool((flags >> 9) & 0x01)
    rcode = flags & 0x0F

    if qdcount != 1:
        raise DnsResolutionError(
            f"DNS response for '{domain}' contains {qdcount} questions, expected exactly 1"
        )

    expected_question = question + struct.pack("!HH", qtype, _DNS_CLASS_IN)
    if data[12 : 12 + len(expected_question)] != expected_question:
        # Byte-exact, which also enforces the DNS-0x20 case pattern.
        raise DnsResolutionError(
            f"DNS response for '{domain}' does not echo the question that was asked; "
            "discarding as unsolicited or spoofed"
        )

    if rcode != 0:
        name = _RCODE_NAMES.get(rcode, f"RCODE{rcode}")
        if truncated:
            return [], True
        raise DnsResolutionError(f"DNS server answered {name} for '{domain}'")

    cursor = 12 + len(expected_question)
    accepted = {domain.lower().rstrip(".")}
    addresses: List[str] = []
    cname_links = 0

    for _ in range(ancount):
        owner, cursor = _read_name(data, cursor)
        if cursor + 10 > len(data):
            raise DnsResolutionError(f"Truncated DNS record in response for '{domain}'")
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", data[cursor : cursor + 10])
        cursor += 10
        if cursor + rdlength > len(data):
            raise DnsResolutionError(f"Truncated DNS record data in response for '{domain}'")
        rdata = data[cursor : cursor + rdlength]
        cursor += rdlength

        if rclass != _DNS_CLASS_IN or owner not in accepted:
            continue

        if rtype == _DNS_TYPE_CNAME:
            cname_links += 1
            if cname_links > _MAX_CNAME_CHAIN:
                raise DnsResolutionError(
                    f"CNAME chain for '{domain}' exceeds {_MAX_CNAME_CHAIN} links"
                )
            target, _ = _read_name(data, cursor - rdlength)
            accepted.add(target)
            continue

        if rtype == _DNS_TYPE_A and qtype == _DNS_TYPE_A:
            if rdlength != 4:
                raise DnsResolutionError(f"A record for '{domain}' has {rdlength} bytes, expected 4")
            addresses.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == _DNS_TYPE_AAAA and qtype == _DNS_TYPE_AAAA:
            if rdlength != 16:
                raise DnsResolutionError(
                    f"AAAA record for '{domain}' has {rdlength} bytes, expected 16"
                )
            addresses.append(str(ipaddress.IPv6Address(rdata)))

    return addresses, truncated


class TrustedDnsResolver:
    """Queries an explicitly configured set of DNS servers for A and AAAA records.

    The servers are configured as IP addresses rather than discovered from the host's resolver
    settings. That is the whole point of the word "trusted" in requirement 3: a backend that
    inherits whatever nameserver DHCP handed it has no basis for treating the answers as
    authoritative input to a security allowlist.

    This is a deliberately small resolver, not a general-purpose DNS library: it asks one
    question, validates that the reply answers exactly that question, and reads A/AAAA records.
    Transaction ids come from `secrets`, the socket is connected so the kernel drops packets from
    other peers, the question section must be echoed byte-for-byte (DNS-0x20), and a truncated
    reply is retried over TCP.
    """

    source_label = "trusted-dns"

    def __init__(
        self,
        servers: Sequence[str],
        *,
        timeout_seconds: float = 3.0,
        attempts: int = 2,
        socket_factory: Optional[Callable[[int, int], Any]] = None,
    ):
        if not servers:
            raise DnsConfigurationError(
                "TrustedDnsResolver requires at least one DNS server address"
            )
        validated: List[str] = []
        for server in servers:
            try:
                validated.append(str(ipaddress.ip_address(str(server).strip())))
            except ValueError as exc:
                raise DnsConfigurationError(
                    f"Trusted DNS server '{server}' is not a valid IP address: {exc}. "
                    "Servers must be addresses, not names - resolving the resolver would be "
                    "circular."
                ) from exc
        self._servers = validated
        self._timeout = max(0.1, float(timeout_seconds))
        self._attempts = max(1, int(attempts))
        self._socket_factory = socket_factory or socket.socket

    @property
    def servers(self) -> List[str]:
        return list(self._servers)

    def resolve(self, domain: str) -> List[str]:
        addresses: List[str] = []
        failures: List[str] = []

        for qtype in (_DNS_TYPE_A, _DNS_TYPE_AAAA):
            try:
                addresses.extend(self._query_all_servers(domain, qtype))
            except DnsResolutionError as exc:
                # A missing AAAA is normal for an IPv4-only service, and vice versa. Only a
                # domain with neither is a failure, which is decided by the caller once both
                # queries have been attempted.
                failures.append(str(exc))

        if not addresses:
            detail = "; ".join(failures) if failures else "the servers returned no A or AAAA records"
            raise DnsResolutionError(f"Could not resolve '{domain}': {detail}")

        return addresses

    def _query_all_servers(self, domain: str, qtype: int) -> List[str]:
        errors: List[str] = []
        for server in self._servers:
            for attempt in range(self._attempts):
                try:
                    return self._query(server, domain, qtype)
                except DnsResolutionError as exc:
                    errors.append(f"{server} (attempt {attempt + 1}): {exc}")
                except OSError as exc:
                    errors.append(f"{server} (attempt {attempt + 1}): {exc}")
        raise DnsResolutionError(
            f"No trusted DNS server answered the {'A' if qtype == _DNS_TYPE_A else 'AAAA'} "
            f"query for '{domain}': " + "; ".join(errors)
        )

    def _query(self, server: str, domain: str, qtype: int) -> List[str]:
        txn_id = secrets.randbelow(0x10000)
        question = _encode_name(domain, randomize_case=True)
        header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)  # RD=1
        message = header + question + struct.pack("!HH", qtype, _DNS_CLASS_IN)

        data = self._exchange_udp(server, message)
        addresses, truncated = _parse_response(
            data, txn_id=txn_id, question=question, qtype=qtype, domain=domain
        )
        if truncated:
            data = self._exchange_tcp(server, message)
            addresses, _ = _parse_response(
                data, txn_id=txn_id, question=question, qtype=qtype, domain=domain
            )
        return addresses

    def _exchange_udp(self, server: str, message: bytes) -> bytes:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = self._socket_factory(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self._timeout)
            # connect() on a datagram socket makes the kernel discard datagrams from any other
            # peer, removing the trivial off-path spoofing window.
            sock.connect((server, _DNS_PORT))
            sock.send(message)
            return sock.recv(4096)
        finally:
            try:
                sock.close()
            except OSError:  # pragma: no cover - close failures are not actionable here
                pass

    def _exchange_tcp(self, server: str, message: bytes) -> bytes:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = self._socket_factory(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self._timeout)
            sock.connect((server, _DNS_PORT))
            sock.send(struct.pack("!H", len(message)) + message)
            prefix = self._recv_exactly(sock, 2)
            (length,) = struct.unpack("!H", prefix)
            return self._recv_exactly(sock, length)
        finally:
            try:
                sock.close()
            except OSError:  # pragma: no cover
                pass

    @staticmethod
    def _recv_exactly(sock: Any, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            chunk = sock.recv(count - len(chunks))
            if not chunk:
                raise DnsResolutionError("DNS server closed the TCP connection early")
            chunks += chunk
        return bytes(chunks)


class SystemDnsResolver:
    """Resolves through the host's own resolver via getaddrinfo.

    Only used when a deployment explicitly opts in. It is weaker than TrustedDnsResolver by
    construction - the answers come from whatever nameserver the backend host happens to be
    configured with - so it exists for development and for deployments that deliberately delegate
    trust to a hardened host resolver.
    """

    source_label = "system-resolver"

    def resolve(self, domain: str) -> List[str]:
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise DnsResolutionError(f"Could not resolve '{domain}' via the system resolver: {exc}")

        addresses = [info[4][0] for info in infos if info[4] and info[4][0]]
        # getaddrinfo may append a scope id to link-local IPv6 results ("fe80::1%eth0"), which is
        # meaningless in a firewall rule and is rejected as link-local anyway.
        addresses = [addr.split("%")[0] for addr in addresses]
        if not addresses:
            raise DnsResolutionError(f"The system resolver returned no addresses for '{domain}'")
        return addresses


class StaticDnsResolver:
    """A fixed domain-to-address mapping. For tests and for air-gapped deployments.

    Also the mechanism that makes the pipeline testable without touching the network: the
    resolution, validation, association and failure logic is exercised against known answers.
    """

    source_label = "static-map"

    def __init__(self, mapping: Mapping[str, Sequence[str]]):
        self._mapping = {
            validate_and_normalize_domain(domain): list(addresses)
            for domain, addresses in mapping.items()
        }

    def resolve(self, domain: str) -> List[str]:
        key = validate_and_normalize_domain(domain)
        if key not in self._mapping:
            raise DnsResolutionError(f"No static mapping configured for '{key}'")
        addresses = self._mapping[key]
        if not addresses:
            raise DnsResolutionError(f"Static mapping for '{key}' is empty")
        return list(addresses)


# ==============================================================================
# Destination resolution
# ==============================================================================
def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TrustedDestinationResolver:
    """Turns exam configuration into the `allowed_destinations` list of a signed policy.

    The output of `build_allowlist` is what `policy_compiler.compile_exam_policy` receives; every
    address in it has been obtained from a trusted source and checked against the address policy.
    """

    def __init__(
        self,
        resolver: Optional[DnsResolver] = None,
        *,
        address_policy: Optional[AddressPolicy] = None,
        limits: Optional[ResolutionLimits] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ):
        self._resolver = resolver
        self._address_policy = address_policy or DEFAULT_ADDRESS_POLICY
        self._limits = limits or ResolutionLimits()
        self._clock = clock or _utc_now

    # -- domain resolution -------------------------------------------------
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolves one domain to a sorted list of safe, normalized host CIDRs.

        Unsafe answers are dropped individually and reported only if nothing safe remains,
        because a single bad record among several good ones is a normal occurrence (a service
        that also publishes an internal address, for instance) whereas a domain that resolves
        *only* to unusable addresses is a configuration error the operator has to see.
        """
        normalized_domain = validate_and_normalize_domain(domain)

        if self._resolver is None:
            raise DnsConfigurationError(
                f"Destination domain '{normalized_domain}' requires DNS resolution, but no "
                "trusted resolver is configured. Set TRUSTED_DNS_SERVERS, or give the vendor "
                "profile explicit approved_ip_ranges. Refusing to compile a policy whose "
                "allowlist would silently omit this destination."
            )

        raw = self._resolver.resolve(normalized_domain)
        if not raw:
            raise DnsResolutionError(
                f"Resolver returned no addresses for '{normalized_domain}'"
            )

        safe: List[str] = []
        rejected: List[str] = []
        seen = set()
        for address in raw:
            try:
                network = ipaddress.ip_network(str(address).strip(), strict=False)
            except ValueError as exc:
                rejected.append(f"{address} (not a valid address: {exc})")
                continue
            if network.num_addresses != 1:
                # A resolver answer is a host address; anything else is not something we asked for.
                rejected.append(f"{address} (a range, not a host address)")
                continue
            reason = describe_unsafe_network(network, self._address_policy)
            if reason is not None:
                rejected.append(f"{address} ({reason})")
                continue
            cidr = f"{network.network_address.compressed}/{network.prefixlen}"
            if cidr not in seen:
                seen.add(cidr)
                safe.append(cidr)

        if not safe:
            raise DnsResolutionError(
                f"Every address returned for '{normalized_domain}' was rejected: "
                + "; ".join(rejected)
            )

        if len(safe) > self._limits.max_addresses_per_domain:
            raise DestinationLimitExceededError(
                f"'{normalized_domain}' resolved to {len(safe)} addresses, more than the "
                f"{self._limits.max_addresses_per_domain} allowed for one domain. This usually "
                "means the domain is a large CDN front door that cannot be expressed as a "
                "firewall allowlist; pin explicit approved_ip_ranges instead."
            )

        return sorted(safe, key=_network_sort_key)

    # -- destinations ------------------------------------------------------
    def resolve_destination(
        self,
        *,
        name: str,
        domains: Sequence[str],
        static_ip_ranges: Sequence[str],
        tcp_ports: Sequence[int],
        udp_ports: Sequence[int],
    ) -> Dict[str, Any]:
        """Builds one destination object with its resolution provenance attached."""
        clean_name = validate_destination_name(name)

        normalized_domains = sorted({validate_and_normalize_domain(d) for d in domains})
        if len(normalized_domains) > self._limits.max_domains_per_destination:
            raise DestinationLimitExceededError(
                f"Destination '{clean_name}' names {len(normalized_domains)} domains, more than "
                f"the {self._limits.max_domains_per_destination} allowed"
            )

        static = validate_destination_networks(
            static_ip_ranges,
            policy=self._address_policy,
            context=f"destination '{clean_name}'",
        )

        domain_map: Dict[str, List[str]] = {}
        resolved: List[str] = []
        for domain in normalized_domains:
            addresses = self.resolve_domain(domain)
            domain_map[domain] = addresses
            resolved.extend(addresses)

        combined = sorted(set(static) | set(resolved), key=_network_sort_key)

        if not combined:
            raise EmptyAllowlistError(
                f"Destination '{clean_name}' has no reachable address: it declares neither "
                "approved IP ranges nor any domain that resolves. A destination with no "
                "addresses produces no firewall rule at all, so the examination browser would "
                "silently be unable to reach it."
            )

        if normalized_domains and static:
            source = f"{self._source_label()}+static"
        elif normalized_domains:
            source = self._source_label()
        else:
            source = "static"

        return {
            "name": clean_name,
            "domains": normalized_domains,
            "ip_ranges": combined,
            "tcp_ports": normalize_ports(list(tcp_ports)),
            "udp_ports": normalize_ports(list(udp_ports)),
            # Provenance travels inside the signed bytes: which domain produced which address,
            # which addresses were configured statically, where the answers came from, and when.
            # Without this, an audit of a signed policy cannot tell a resolved address from an
            # operator-typed one.
            "resolution": {
                "source": source,
                "resolved_at": self._clock().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "domain_map": {domain: list(ips) for domain, ips in sorted(domain_map.items())},
                "static_ranges": static,
            },
        }

    def resolve_vendor_profile(self, vendor_profile: Any) -> Optional[Dict[str, Any]]:
        """Builds the vendor destination from a VendorProfile row or an equivalent dict."""
        if vendor_profile is None:
            return None

        if hasattr(vendor_profile, "vendor_id"):
            name = getattr(vendor_profile, "vendor_name", None) or "Vendor LMS"
            domains = getattr(vendor_profile, "required_domains", None) or []
            ips = getattr(vendor_profile, "approved_ip_ranges", None) or []
            tcp = getattr(vendor_profile, "required_tcp_ports", None) or []
            udp = getattr(vendor_profile, "required_udp_ports", None) or []
        elif isinstance(vendor_profile, dict):
            name = vendor_profile.get("vendor_name") or "Vendor LMS"
            domains = vendor_profile.get("required_domains") or []
            ips = vendor_profile.get("approved_ip_ranges") or []
            tcp = vendor_profile.get("required_tcp_ports") or []
            udp = vendor_profile.get("required_udp_ports") or []
        else:
            raise DestinationResolutionError(
                f"Unsupported vendor_profile type: {type(vendor_profile).__name__}"
            )

        return self.resolve_destination(
            name=name,
            domains=domains,
            static_ip_ranges=ips,
            tcp_ports=tcp,
            udp_ports=udp,
        )

    def resolve_requested_destinations(
        self, requested: Optional[Sequence[Mapping[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Resolves caller-supplied *additional* destinations - names and domains only.

        Any attempt to supply `ip_ranges` is refused rather than ignored. Silently dropping them
        would leave the caller believing an address was allowed when it was not, and would make
        the difference between "trusted" and "requested" invisible in the response.
        """
        if not requested:
            return []
        if not isinstance(requested, (list, tuple)):
            raise DestinationResolutionError(
                "resolved_destinations must be a list of destination objects"
            )

        out: List[Dict[str, Any]] = []
        for index, entry in enumerate(requested):
            if not isinstance(entry, Mapping):
                raise DestinationResolutionError(
                    f"Destination at index {index} must be an object"
                )

            forbidden = sorted(
                key
                for key in ("ip_ranges", "ips", "addresses", "resolved_ips", "resolution")
                if entry.get(key)
            )
            if forbidden:
                raise UntrustedDestinationError(
                    f"Destination at index {index} supplies {forbidden}. Addresses in a signed "
                    "policy must come from the vendor profile or from the server's own trusted "
                    "DNS resolution - a caller-supplied address would let whoever can reach this "
                    "endpoint widen the examination allowlist to any host. Send 'domains' "
                    "instead, or add the range to the vendor profile."
                )

            unknown = sorted(
                set(entry.keys()) - {"name", "domains", "tcp_ports", "udp_ports"}
            )
            if unknown:
                raise DestinationResolutionError(
                    f"Destination at index {index} contains unsupported fields {unknown}. "
                    "Allowed fields: name, domains, tcp_ports, udp_ports."
                )

            domains = entry.get("domains") or []
            if not domains:
                raise DestinationResolutionError(
                    f"Destination at index {index} names no domains. Without domains there is "
                    "nothing for the server to resolve, and addresses may not be supplied "
                    "directly."
                )

            out.append(
                self.resolve_destination(
                    name=entry.get("name") or f"Destination-{index + 1}",
                    domains=domains,
                    static_ip_ranges=[],
                    tcp_ports=entry.get("tcp_ports") or [],
                    udp_ports=entry.get("udp_ports") or [],
                )
            )
        return out

    def build_allowlist(
        self,
        *,
        vendor_profile: Any = None,
        requested_destinations: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Produces the complete, trusted `allowed_destinations` list for a policy."""
        destinations: List[Dict[str, Any]] = []

        vendor_destination = self.resolve_vendor_profile(vendor_profile)
        if vendor_destination is not None:
            destinations.append(vendor_destination)

        destinations.extend(self.resolve_requested_destinations(requested_destinations))

        if not destinations:
            raise EmptyAllowlistError(
                "The exam has no vendor profile and no additional destinations, so its policy "
                "would allow nothing beyond the management channel. Assign a vendor profile "
                "before compiling a policy."
            )

        if len(destinations) > self._limits.max_destinations:
            raise DestinationLimitExceededError(
                f"{len(destinations)} destinations exceeds the maximum of "
                f"{self._limits.max_destinations}"
            )

        seen_names = {}
        total_addresses = 0
        for destination in destinations:
            key = destination["name"].casefold()
            if key in seen_names:
                raise DestinationResolutionError(
                    f"Duplicate destination name '{destination['name']}'. Names identify the "
                    "purpose of each firewall rule on the endpoint and must be distinct."
                )
            seen_names[key] = True
            total_addresses += len(destination["ip_ranges"])

        if total_addresses > self._limits.max_addresses_per_policy:
            raise DestinationLimitExceededError(
                f"The allowlist resolves to {total_addresses} addresses, more than the "
                f"{self._limits.max_addresses_per_policy} a single policy may carry. Narrow the "
                "vendor profile: every address becomes a firewall rule that has to be applied "
                "and later rolled back."
            )

        return destinations

    # -- helpers -----------------------------------------------------------
    def _source_label(self) -> str:
        return getattr(self._resolver, "source_label", "unknown-resolver")

    def with_address_policy(self, policy: AddressPolicy) -> "TrustedDestinationResolver":
        return TrustedDestinationResolver(
            self._resolver, address_policy=policy, limits=self._limits, clock=self._clock
        )


def _network_sort_key(cidr: str) -> Tuple[int, int, int]:
    """Deterministic ordering: IPv4 before IPv6, then by address, then by prefix length."""
    network = ipaddress.ip_network(cidr)
    return (network.version, int(network.network_address), network.prefixlen)


# ==============================================================================
# Configuration
# ==============================================================================
def build_resolver_from_settings(settings: Any = None) -> Optional[DnsResolver]:
    """Builds the configured DNS resolver, or None when domain resolution is unavailable.

    Returning None rather than raising keeps a deployment that pins explicit
    `approved_ip_ranges` working without any DNS configuration at all. The failure only
    surfaces - loudly, naming the domain - if a destination actually needs resolving.

    `settings` is passed in (or imported lazily) so that importing this module does not require
    the application configuration, and so tests can supply their own.
    """
    if settings is None:
        from backend.app.config import settings as app_settings  # local import: see docstring

        settings = app_settings

    raw = getattr(settings, "TRUSTED_DNS_SERVERS", "") or ""
    servers = [part.strip() for part in str(raw).replace(";", ",").split(",") if part.strip()]

    if servers:
        return TrustedDnsResolver(
            servers,
            timeout_seconds=float(getattr(settings, "POLICY_DNS_TIMEOUT_SECONDS", 3.0)),
            attempts=int(getattr(settings, "POLICY_DNS_ATTEMPTS", 2)),
        )

    if getattr(settings, "POLICY_DNS_ALLOW_SYSTEM_RESOLVER", False):
        return SystemDnsResolver()

    return None


def build_destination_resolver(settings: Any = None) -> TrustedDestinationResolver:
    """Builds the destination resolver a policy compilation should use."""
    if settings is None:
        from backend.app.config import settings as app_settings

        settings = app_settings

    return TrustedDestinationResolver(
        build_resolver_from_settings(settings),
        address_policy=AddressPolicy(
            allow_private=bool(getattr(settings, "POLICY_ALLOW_PRIVATE_DESTINATIONS", True)),
        ),
        limits=ResolutionLimits(
            max_addresses_per_domain=int(
                getattr(settings, "POLICY_MAX_ADDRESSES_PER_DOMAIN", 32)
            ),
            max_addresses_per_policy=int(
                getattr(settings, "POLICY_MAX_ADDRESSES_PER_POLICY", 256)
            ),
        ),
    )


__all__ = [
    "AddressPolicy",
    "DestinationLimitExceededError",
    "DestinationResolutionError",
    "DnsConfigurationError",
    "DnsResolutionError",
    "DnsResolver",
    "EmptyAllowlistError",
    "ResolutionLimits",
    "StaticDnsResolver",
    "SystemDnsResolver",
    "TrustedDestinationResolver",
    "TrustedDnsResolver",
    "UnsafeDestinationAddressError",
    "UntrustedDestinationError",
    "build_destination_resolver",
    "build_resolver_from_settings",
    "describe_unsafe_network",
    "validate_destination_name",
    "validate_destination_networks",
]
