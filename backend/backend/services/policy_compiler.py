"""SPEMCS Policy Compiler & Validation Engine.

Provides:
- Domain validation & normalization (RFC 1035 / RFC 1123)
- IPv4 / IPv6 IP and CIDR validation and normalization (RFC 4632 / RFC 4291)
- Port & protocol validation and deterministic deduplication
- Separate management control-plane destination representation
- Pure, deterministic policy compilation ready for M2 RSA-PSS signing
"""

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from .canonical_json import canonicalize_to_bytes

# ==============================================================================
# Domain Name Validation Regex (RFC 1123 compliant FQDN)
# - Labels: 1-63 chars, letters/digits/hyphens, cannot start or end with hyphen
# - Must not contain URI schemes, slashes, ports, queries, or whitespace
# ==============================================================================
DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


class PolicyCompilationError(Exception):
    """Base exception for all policy compilation failures."""
    pass


class InvalidDomainError(PolicyCompilationError):
    """Domain name is malformed, contains URI fragments, or invalid characters."""
    pass


class InvalidNetworkAddressError(PolicyCompilationError):
    """IP address or CIDR range is malformed or unparseable."""
    pass


class InvalidPortError(PolicyCompilationError):
    """Port number is outside the valid range (1-65535) or malformed."""
    pass


class InvalidValidityWindowError(PolicyCompilationError):
    """Policy timestamp validity window is inverted or invalid."""
    pass


class MissingConfigurationError(PolicyCompilationError):
    """Required configuration or profile fields are missing or empty."""
    pass


class InvalidApprovedBrowserError(PolicyCompilationError):
    """The exam's approved browser is missing or is not a family the endpoint can scope rules to."""
    pass


# Browser families the endpoint agent can positively identify and scope firewall rules to.
# Duplicated from policy_signer.SUPPORTED_APPROVED_BROWSERS deliberately: policy_compiler is
# a pure module with no crypto dependency, and a mismatch between the two sets is caught by
# test_policy_browser_scoping's parity test rather than by an import cycle.
#
# Firefox is excluded on purpose - see the longer note in policy_signer.py. In short: the
# endpoint classifier hard-denies firefox.exe, so a Firefox exam could never be both
# network-allowed and monitor-clean.
SUPPORTED_APPROVED_BROWSERS = frozenset({"chrome", "edge"})


def validate_and_normalize_approved_browser(value: Any) -> str:
    """Validates the exam's approved browser family and returns its canonical lowercase form.

    Rejects (rather than defaults) unknown values: the approved browser is the executable
    identity that every vendor/exam firewall allow rule is scoped to on the endpoint, so an
    unrecognised value must surface as a configuration error at compile time instead of
    producing a policy that the endpoint can only fail closed on.
    """
    if not isinstance(value, str):
        raise InvalidApprovedBrowserError(
            f"approved_browser must be a string, got {type(value).__name__}"
        )
    normalized = value.strip().lower()
    if not normalized:
        raise InvalidApprovedBrowserError("approved_browser must not be empty")
    if normalized not in SUPPORTED_APPROVED_BROWSERS:
        raise InvalidApprovedBrowserError(
            f"Unsupported approved_browser '{value}'. "
            f"Supported: {sorted(SUPPORTED_APPROVED_BROWSERS)}"
        )
    return normalized


# ==============================================================================
# Domain Validation & Normalization
# ==============================================================================
def validate_and_normalize_domain(domain_str: str) -> str:
    """Validates and normalizes an FQDN.
    
    Rules:
    - Strips leading/trailing whitespace and trailing dot.
    - Converts to lowercase.
    - Rejects URI schemes (http://, https://), slashes (/), query strings (?),
      fragment identifiers (#), and port specifications (:).
    - Validates total length <= 253 characters and each label <= 63 characters.
    - Ensures each label conforms to letters, digits, hyphens (no leading/trailing hyphen).
    """
    if not isinstance(domain_str, str):
        raise InvalidDomainError(f"Domain must be a string, got {type(domain_str).__name__}")
    
    cleaned = domain_str.strip().lower()
    if not cleaned:
        raise InvalidDomainError("Domain cannot be empty")

    # Reject URLs, schemes, paths, query, ports
    if "://" in cleaned:
        raise InvalidDomainError(f"Domain '{domain_str}' must not contain a URL scheme (e.g. 'http://')")
    if "/" in cleaned or "\\" in cleaned:
        raise InvalidDomainError(f"Domain '{domain_str}' must not contain path components ('/')")
    if "?" in cleaned or "#" in cleaned:
        raise InvalidDomainError(f"Domain '{domain_str}' must not contain query parameters or fragments ('?', '#')")
    if ":" in cleaned:
        raise InvalidDomainError(f"Domain '{domain_str}' must not contain port specifications (':')")

    # Strip trailing dot if present (e.g. 'example.com.' -> 'example.com')
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]

    if len(cleaned) > 253:
        raise InvalidDomainError(f"Domain '{domain_str}' exceeds maximum length of 253 characters")

    labels = cleaned.split(".")
    if len(labels) < 2:
        raise InvalidDomainError(f"Domain '{domain_str}' must have at least two labels (e.g. 'exam.univ.edu')")

    for label in labels:
        if not label:
            raise InvalidDomainError(f"Domain '{domain_str}' contains empty label")
        if len(label) > 63:
            raise InvalidDomainError(f"Domain label '{label}' exceeds maximum length of 63 characters")
        if not DOMAIN_LABEL_REGEX.match(label):
            raise InvalidDomainError(f"Domain label '{label}' contains invalid characters or leading/trailing hyphens")

    # TLD must not be purely numeric
    if labels[-1].isdigit():
        raise InvalidDomainError(f"Top-level domain '{labels[-1]}' must not be purely numeric")

    return cleaned


def normalize_domain_list(domains: List[str]) -> List[str]:
    """Validates, deduplicates, and deterministically sorts a list of domains."""
    if not isinstance(domains, (list, tuple)):
        raise InvalidDomainError(f"Domains must be a list, got {type(domains).__name__}")
    
    normalized_set = set()
    for d in domains:
        normalized_set.add(validate_and_normalize_domain(d))
    
    return sorted(list(normalized_set))


# ==============================================================================
# IP / CIDR Validation & Normalization (IPv4 & IPv6)
# ==============================================================================
def validate_and_normalize_ip_network(network_str: str) -> Tuple[str, str]:
    """Validates an IP address or CIDR network range.
    
    Returns:
        Tuple of (normalized_cidr_string, ip_version_string: "IPv4" | "IPv6")
    
    Rules:
    - Accepts both single host IPs ("192.168.1.1", "2001:db8::1") and CIDRs ("10.0.0.0/24").
    - If no prefix is specified, appends /32 for IPv4 or /128 for IPv6.
    - Normalizes canonical representation (e.g. zero-compression in IPv6).
    """
    if not isinstance(network_str, str):
        raise InvalidNetworkAddressError(f"Network address must be a string, got {type(network_str).__name__}")
    
    cleaned = network_str.strip()
    if not cleaned:
        raise InvalidNetworkAddressError("Network address cannot be empty")

    try:
        # Check if single IP without mask
        if "/" not in cleaned:
            ip_obj = ipaddress.ip_address(cleaned)
            version_str = f"IPv{ip_obj.version}"
            prefix = 32 if ip_obj.version == 4 else 128
            normalized_cidr = f"{ip_obj.compressed}/{prefix}"
            return normalized_cidr, version_str
        else:
            net_obj = ipaddress.ip_network(cleaned, strict=False)
            version_str = f"IPv{net_obj.version}"
            normalized_cidr = f"{net_obj.network_address.compressed}/{net_obj.prefixlen}"
            return normalized_cidr, version_str
    except ValueError as exc:
        raise InvalidNetworkAddressError(f"Invalid IP address or CIDR range '{network_str}': {exc}")


def normalize_ip_network_list(ip_ranges: List[str]) -> List[str]:
    """Validates, deduplicates, and deterministically sorts a list of IP ranges/CIDRs.
    
    Sorting rule: IPv4 ranges first sorted by network address/prefix, then IPv6 ranges.
    """
    if not isinstance(ip_ranges, (list, tuple)):
        raise InvalidNetworkAddressError(f"IP ranges must be a list, got {type(ip_ranges).__name__}")

    normalized_v4 = []
    normalized_v6 = []

    seen = set()
    for r in ip_ranges:
        cidr_str, version = validate_and_normalize_ip_network(r)
        if cidr_str in seen:
            continue
        seen.add(cidr_str)
        net_obj = ipaddress.ip_network(cidr_str)
        if version == "IPv4":
            normalized_v4.append((net_obj, cidr_str))
        else:
            normalized_v6.append((net_obj, cidr_str))

    # Deterministic sorting by network address integer then prefix
    normalized_v4.sort(key=lambda item: (int(item[0].network_address), item[0].prefixlen))
    normalized_v6.sort(key=lambda item: (int(item[0].network_address), item[0].prefixlen))

    return [item[1] for item in normalized_v4] + [item[1] for item in normalized_v6]


# ==============================================================================
# Destination Address Safety (requirement 3)
# ==============================================================================
# `validate_and_normalize_ip_network` answers "is this a well-formed range?". That is not the
# same question as "may this range appear in an examination allowlist?", and conflating the two
# is what allowed a compiled policy to contain `0.0.0.0/0`: a perfectly well-formed range whose
# presence in a signed policy re-opens the entire internet for the examination browser, because
# the endpoint agent turns every allowed_destinations entry straight into a firewall allow rule.
#
# Everything below is pure and deterministic, so it lives here rather than in
# destination_resolver (which performs DNS I/O and imports these).

# A prefix shorter than this is a region of the internet, not a destination. /8 is permissive
# enough for a legitimate on-premises 10.0.0.0/8 while still rejecting 0.0.0.0/0 and 128.0.0.0/1.
MIN_DESTINATION_PREFIX_V4 = 8
MIN_DESTINATION_PREFIX_V6 = 32

# Refused unconditionally, wherever the address came from - a vendor profile, a DNS answer, or a
# request body.
_ALWAYS_FORBIDDEN_V4: Tuple[Tuple[str, str], ...] = (
    ("0.0.0.0/8", "the unspecified/this-network range"),
    ("127.0.0.0/8", "loopback, which cannot leave the machine and is not a destination"),
    (
        "169.254.0.0/16",
        "link-local, which includes the cloud instance metadata address 169.254.169.254",
    ),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
    ("255.255.255.255/32", "the broadcast address"),
)

_ALWAYS_FORBIDDEN_V6: Tuple[Tuple[str, str], ...] = (
    ("::/128", "the unspecified address"),
    ("::1/128", "loopback, which cannot leave the machine and is not a destination"),
    ("fe80::/10", "link-local"),
    ("ff00::/8", "multicast"),
    (
        "::ffff:0:0/96",
        "an IPv4-mapped IPv6 range; express IPv4 destinations as IPv4 so the resulting firewall "
        "rule is unambiguous",
    ),
    ("2002::/16", "the 6to4 tunnel range (requirement 7 contains transition mechanisms)"),
    ("2001::/32", "the Teredo tunnel range (requirement 7 contains transition mechanisms)"),
)

# Refused only when a deployment opts out. On-premises examination servers on RFC 1918 space are
# common and legitimate, so private ranges are permitted by default.
_PRIVATE_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
_PRIVATE_V6 = ("fc00::/7",)

# Destination names become the `purpose` segment of the endpoint's firewall rule name
# (`SPEMCS-{session}-{purpose}-{hash}`), so they must be safe to write into a rule name.
MAX_DESTINATION_NAME_LENGTH = 64
# `|` is the field delimiter in the firewall rule registry representation; the quote and slash
# characters break netsh argument quoting and path parsing.
_FORBIDDEN_NAME_CHARS = frozenset('|"\'`\\/')


class DestinationResolutionError(PolicyCompilationError):
    """Base for every failure turning exam configuration into trusted destination addresses."""


class UnsafeDestinationAddressError(DestinationResolutionError):
    """An address or range is not acceptable in an examination allowlist."""


class UntrustedDestinationError(DestinationResolutionError):
    """A caller supplied resolved addresses. Addresses may only come from trusted sources."""


class EmptyAllowlistError(DestinationResolutionError):
    """A destination, or the policy as a whole, resolved to no reachable address."""


class DestinationLimitExceededError(DestinationResolutionError):
    """Resolution produced more destinations or addresses than a policy may carry."""


class AddressPolicy:
    """Which address ranges may appear in an examination allowlist."""

    __slots__ = ("allow_private", "min_prefix_v4", "min_prefix_v6")

    def __init__(
        self,
        allow_private: bool = True,
        min_prefix_v4: int = MIN_DESTINATION_PREFIX_V4,
        min_prefix_v6: int = MIN_DESTINATION_PREFIX_V6,
    ):
        self.allow_private = bool(allow_private)
        self.min_prefix_v4 = int(min_prefix_v4)
        self.min_prefix_v6 = int(min_prefix_v6)

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return (
            f"AddressPolicy(allow_private={self.allow_private}, "
            f"min_prefix_v4={self.min_prefix_v4}, min_prefix_v6={self.min_prefix_v6})"
        )


DEFAULT_ADDRESS_POLICY = AddressPolicy()


def describe_unsafe_network(network: Any, policy: Optional[AddressPolicy] = None) -> Optional[str]:
    """Returns why `network` may not appear in an allowlist, or None if it is acceptable.

    Overlap is tested rather than membership of the network address alone. A supernet can cover
    forbidden space while starting outside it - `169.252.0.0/14` spans the whole of link-local
    `169.254.0.0/16` even though its own network address is an ordinary public one - so checking
    only the first address of a range would let such a supernet through.
    """
    effective = policy or DEFAULT_ADDRESS_POLICY

    if network.prefixlen == 0:
        return "it matches every address, which would nullify default-deny"

    if network.version == 4:
        minimum, forbidden, private = effective.min_prefix_v4, _ALWAYS_FORBIDDEN_V4, _PRIVATE_V4
    else:
        minimum, forbidden, private = effective.min_prefix_v6, _ALWAYS_FORBIDDEN_V6, _PRIVATE_V6

    if network.prefixlen < minimum:
        return (
            f"/{network.prefixlen} is broader than the widest allowed IPv{network.version} "
            f"prefix (/{minimum})"
        )

    for cidr, reason in forbidden:
        if network.overlaps(ipaddress.ip_network(cidr)):
            return f"it overlaps {cidr}, which is {reason}"

    if not effective.allow_private:
        for cidr in private:
            if network.overlaps(ipaddress.ip_network(cidr)):
                return (
                    f"it overlaps the private range {cidr} and this deployment does not permit "
                    "private destinations"
                )

    return None


def validate_destination_networks(
    cidrs: List[str],
    policy: Optional[AddressPolicy] = None,
    context: str = "destination",
) -> List[str]:
    """Normalizes, deduplicates, sorts and safety-checks a list of IP/CIDR strings.

    Errors name both the offending range and the reason, so an operator can fix the vendor
    profile without reading the code.
    """
    normalized = normalize_ip_network_list(list(cidrs))
    for cidr in normalized:
        reason = describe_unsafe_network(ipaddress.ip_network(cidr), policy)
        if reason is not None:
            raise UnsafeDestinationAddressError(
                f"{context}: address range '{cidr}' cannot be allowed because {reason}."
            )
    return normalized


def validate_destination_name(name: Any) -> str:
    """Validates a destination name and returns its trimmed form."""
    if not isinstance(name, str):
        raise DestinationResolutionError(
            f"Destination name must be a string, got {type(name).__name__}"
        )
    cleaned = name.strip()
    if not cleaned:
        raise DestinationResolutionError("Destination name must not be empty")
    if len(cleaned) > MAX_DESTINATION_NAME_LENGTH:
        raise DestinationResolutionError(
            f"Destination name '{cleaned[:32]}...' exceeds "
            f"{MAX_DESTINATION_NAME_LENGTH} characters"
        )
    bad = sorted(_FORBIDDEN_NAME_CHARS.intersection(cleaned))
    if bad:
        raise DestinationResolutionError(
            f"Destination name '{cleaned}' contains characters that are not allowed in a "
            f"firewall rule name: {bad}"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
        raise DestinationResolutionError(
            f"Destination name {cleaned!r} contains control characters"
        )
    return cleaned



# ==============================================================================
# Port & Protocol Validation
# ==============================================================================
def validate_port(port: Any) -> int:
    """Validates an individual network port number (1-65535)."""
    if isinstance(port, bool) or not isinstance(port, int):
        raise InvalidPortError(f"Port must be an integer, got {type(port).__name__} ({port!r})")
    if port < 1 or port > 65535:
        raise InvalidPortError(f"Port {port} is out of valid range (1-65535)")
    return port


def normalize_ports(ports: List[int]) -> List[int]:
    """Validates, deduplicates, and sorts a list of port numbers ascending."""
    if not isinstance(ports, (list, tuple)):
        raise InvalidPortError(f"Ports must be a list, got {type(ports).__name__}")
    validated_set = {validate_port(p) for p in ports}
    return sorted(list(validated_set))


# ==============================================================================
# Management Server Validation
# ==============================================================================
def validate_management_server(management_server: Dict[str, Any]) -> Dict[str, Any]:
    """Validates management server configuration.
    
    Requires:
    - ip_addresses: non-empty list of valid IP addresses or CIDRs
    - port: valid integer port (1-65535)
    """
    if not isinstance(management_server, dict):
        raise MissingConfigurationError(f"management_server must be a dictionary, got {type(management_server).__name__}")
    
    if "ip_addresses" not in management_server or "port" not in management_server:
        raise MissingConfigurationError("management_server must contain 'ip_addresses' and 'port'")

    raw_ips = management_server["ip_addresses"]
    if not isinstance(raw_ips, (list, tuple)) or len(raw_ips) == 0:
        raise MissingConfigurationError("management_server 'ip_addresses' must be a non-empty list")

    normalized_ips = []
    seen = set()
    for ip_entry in raw_ips:
        if not isinstance(ip_entry, str):
            raise InvalidNetworkAddressError(f"Management IP must be string, got {type(ip_entry).__name__}")
        try:
            # Can be bare IP or CIDR
            if "/" in ip_entry:
                net = ipaddress.ip_network(ip_entry.strip(), strict=False)
                normalized = f"{net.network_address.compressed}/{net.prefixlen}"
            else:
                ip_obj = ipaddress.ip_address(ip_entry.strip())
                normalized = ip_obj.compressed
            if normalized not in seen:
                seen.add(normalized)
                normalized_ips.append(normalized)
        except ValueError as exc:
            raise InvalidNetworkAddressError(f"Invalid management IP '{ip_entry}': {exc}")

    normalized_ips.sort()
    port = validate_port(management_server["port"])

    return {
        "ip_addresses": normalized_ips,
        "port": port,
    }


# ==============================================================================
# Validity Window Validation
# ==============================================================================
def validate_validity_window(
    not_before: Union[datetime, str],
    expires_at: Union[datetime, str],
) -> Tuple[str, str]:
    """Validates and formats the policy validity window as ISO-8601 UTC strings.
    
    Enforces:
    - Timestamps are parseable
    - expires_at is strictly greater than not_before
    - Serializes consistently with trailing 'Z'
    """
    def _to_utc(ts: Union[datetime, str]) -> datetime:
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc)
        elif isinstance(ts, str):
            s = ts.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception as exc:
                raise InvalidValidityWindowError(f"Invalid timestamp format '{ts}': {exc}")
        raise InvalidValidityWindowError(f"Timestamp must be datetime or ISO string, got {type(ts).__name__}")

    nb_dt = _to_utc(not_before)
    exp_dt = _to_utc(expires_at)

    if exp_dt <= nb_dt:
        raise InvalidValidityWindowError(
            f"Invalid validity window: expires_at ({exp_dt.isoformat()}) must be strictly after not_before ({nb_dt.isoformat()})"
        )

    nb_str = nb_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    exp_str = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return nb_str, exp_str


# ==============================================================================
# Policy Compiler Engine
# ==============================================================================
def compile_exam_policy(
    exam_id: Union[str, uuid.UUID],
    version: int,
    vendor_profile: Optional[Any],
    management_server: Dict[str, Any],
    not_before: Union[datetime, str],
    expires_at: Union[datetime, str],
    approved_browser: str,
    key_id: str,
    policy_id: Optional[Union[str, uuid.UUID]] = None,
    allowed_destinations: Optional[List[Dict[str, Any]]] = None,
    resolved_destinations: Optional[List[Dict[str, Any]]] = None,
    address_policy: Optional[AddressPolicy] = None,
    schema_version: str = "1.1",
) -> Dict[str, Any]:
    """Compiles an examination configuration and vendor profile into a deterministic,
    M2-ready canonical policy envelope.

    Pure & Deterministic:
    - Input ordering of destinations, IPs, ports, and domains does not affect output.
    - All collections are deduplicated and deterministically sorted.
    - Output conforms strictly to M2 MANDATORY_PAYLOAD_FIELDS.
    - Excludes transient state or local database IDs (created_at, db PKs).

    `approved_browser` is REQUIRED with no default. It is part of the signed envelope because the
    endpoint scopes each vendor/exam allow rule to that browser's executable; a default here
    would silently produce rules for the wrong program.

    `key_id` is likewise REQUIRED with no default. It names the key whose signature the endpoint
    will demand, and a placeholder default would compile policies that verify against nothing.

    Destinations reach this function by one of two routes:

    * `allowed_destinations` - the complete, already-resolved allowlist produced by
      `destination_resolver.TrustedDestinationResolver.build_allowlist()`. This is the production
      route: domain-to-address resolution needs DNS I/O, which does not belong in a pure
      compiler. Entries are still re-validated here, because this function is the last gate
      before the bytes are signed.
    * `vendor_profile` alone - the compiler builds a single destination from the profile's
      server-side `approved_ip_ranges`. This route cannot resolve domains, so a profile that
      declares only domains fails with EmptyAllowlistError rather than compiling an allowlist
      that would silently block the exam.

    `resolved_destinations` accepts *names and domains only*. Any caller-supplied addresses are
    rejected: they were the vector by which a request body could put `0.0.0.0/0` into a validly
    signed policy. Resolve them through the destination resolver and pass
    `allowed_destinations` instead.
    """
    # 1. Validate Identifiers
    try:
        exam_uuid_str = str(uuid.UUID(str(exam_id)))
    except Exception as exc:
        raise PolicyCompilationError(f"Invalid exam_id '{exam_id}': {exc}")

    pol_id_str = str(uuid.UUID(str(policy_id))) if policy_id else str(uuid.uuid4())

    if not isinstance(version, int) or version < 1:
        raise PolicyCompilationError(f"Policy version must be a positive integer >= 1, got {version!r}")

    if not isinstance(key_id, str) or not key_id.strip():
        raise PolicyCompilationError("key_id is required and must be a non-empty string")

    # 2. Validate Validity Window
    nb_str, exp_str = validate_validity_window(not_before, expires_at)

    # 2b. Validate approved browser (endpoint firewall-rule scoping identity)
    norm_browser = validate_and_normalize_approved_browser(approved_browser)

    # 3. Validate Management Server
    norm_management = validate_management_server(management_server)

    # 4. Resolve the vendor profile id, which is signed independently of the destination list.
    vendor_profile_id_str = None
    if vendor_profile is not None:
        if hasattr(vendor_profile, "vendor_id"):
            vendor_profile_id_str = str(vendor_profile.vendor_id)
        elif isinstance(vendor_profile, dict):
            vendor_profile_id_str = (
                str(vendor_profile.get("vendor_id")) if vendor_profile.get("vendor_id") else None
            )
        else:
            raise PolicyCompilationError(
                f"Unsupported vendor_profile type: {type(vendor_profile).__name__}"
            )

    # 5. Reject caller-supplied addresses before they can reach the signed payload.
    _reject_untrusted_destination_addresses(resolved_destinations)

    # 6. Assemble the destination list.
    if allowed_destinations is not None:
        candidates = list(allowed_destinations)
        if resolved_destinations:
            # The resolver already folded these in; accepting both would double-count and make
            # the provenance recorded in each destination's `resolution` block a lie.
            raise PolicyCompilationError(
                "Pass either allowed_destinations (already resolved) or resolved_destinations "
                "(names and domains to resolve), not both."
            )
    else:
        candidates = _destinations_from_vendor_profile(vendor_profile)
        candidates.extend(resolved_destinations or [])

    all_destinations = _validate_destination_list(candidates, address_policy)

    # 7. Construct Final Canonical Payload (Strictly conforming to M2 envelope)
    compiled_payload = {
        "schema_version": str(schema_version),
        "key_id": key_id.strip(),
        "exam_id": exam_uuid_str,
        "policy_id": pol_id_str,
        "version": int(version),
        "vendor_profile_id": vendor_profile_id_str,
        "approved_browser": norm_browser,
        "allowed_destinations": all_destinations,
        "management_server": norm_management,
        "not_before": nb_str,
        "expires_at": exp_str,
    }

    return compiled_payload


# Field names a caller might use to smuggle addresses into a policy. Checked by name rather than
# by rejecting all unknown keys so the error can say precisely what was wrong and why.
_CALLER_FORBIDDEN_ADDRESS_FIELDS = ("ip_ranges", "ips", "addresses", "resolved_ips", "resolution")
_CALLER_ALLOWED_DESTINATION_FIELDS = frozenset({"name", "domains", "tcp_ports", "udp_ports"})


def _reject_untrusted_destination_addresses(
    resolved_destinations: Optional[List[Dict[str, Any]]],
) -> None:
    """Refuses caller-supplied destination addresses, loudly.

    Silently dropping them would be worse than failing: the caller would believe a destination
    was allowed when it was not, and the difference between a trusted address and a requested one
    would be invisible in the compiled policy.
    """
    if not resolved_destinations:
        return
    if not isinstance(resolved_destinations, (list, tuple)):
        raise PolicyCompilationError("resolved_destinations must be a list of destination dicts")

    for idx, dest in enumerate(resolved_destinations):
        if not isinstance(dest, dict):
            raise PolicyCompilationError(f"Destination at index {idx} must be a dictionary")

        supplied = sorted(k for k in _CALLER_FORBIDDEN_ADDRESS_FIELDS if dest.get(k))
        if supplied:
            raise UntrustedDestinationError(
                f"Destination at index {idx} supplies {supplied}. Addresses in a signed policy "
                "must come from the vendor profile or from the server's own trusted DNS "
                "resolution; a caller-supplied address would let whoever can reach this endpoint "
                "widen the examination allowlist to any host, including 0.0.0.0/0. Send 'domains' "
                "instead, or add the range to the vendor profile."
            )

        unknown = sorted(set(dest.keys()) - _CALLER_ALLOWED_DESTINATION_FIELDS)
        if unknown:
            raise PolicyCompilationError(
                f"Destination at index {idx} contains unsupported fields {unknown}. "
                f"Allowed fields: {sorted(_CALLER_ALLOWED_DESTINATION_FIELDS)}."
            )


def _destinations_from_vendor_profile(vendor_profile: Optional[Any]) -> List[Dict[str, Any]]:
    """Builds the vendor destination from server-side profile data (no DNS resolution)."""
    if vendor_profile is None:
        return []

    if hasattr(vendor_profile, "vendor_id"):
        name = getattr(vendor_profile, "vendor_name", "Vendor LMS")
        domains = getattr(vendor_profile, "required_domains", []) or []
        ips = getattr(vendor_profile, "approved_ip_ranges", []) or []
        tcp = getattr(vendor_profile, "required_tcp_ports", []) or []
        udp = getattr(vendor_profile, "required_udp_ports", []) or []
    else:
        name = vendor_profile.get("vendor_name", "Vendor LMS")
        domains = vendor_profile.get("required_domains", []) or []
        ips = vendor_profile.get("approved_ip_ranges", []) or []
        tcp = vendor_profile.get("required_tcp_ports", []) or []
        udp = vendor_profile.get("required_udp_ports", []) or []

    return [
        {
            "name": name,
            "domains": domains,
            "ip_ranges": ips,
            "tcp_ports": tcp,
            "udp_ports": udp,
        }
    ]


def _validate_destination_list(
    candidates: List[Dict[str, Any]],
    address_policy: Optional[AddressPolicy],
) -> List[Dict[str, Any]]:
    """Normalizes and safety-checks every destination, then orders them deterministically.

    This is the last gate before signing, so it re-checks destinations that the resolver already
    checked. That duplication is deliberate: a future caller that assembles an allowlist by some
    other route must not be able to bypass address safety just by not going through the resolver.
    """
    if not isinstance(candidates, (list, tuple)):
        raise PolicyCompilationError("Destinations must be provided as a list")

    validated: List[Dict[str, Any]] = []
    seen_names: Dict[str, int] = {}

    for idx, dest in enumerate(candidates):
        if not isinstance(dest, dict):
            raise PolicyCompilationError(f"Destination at index {idx} must be a dictionary")

        name = validate_destination_name(dest.get("name"))
        key = name.casefold()
        if key in seen_names:
            raise PolicyCompilationError(
                f"Duplicate destination name '{name}' (indexes {seen_names[key]} and {idx}). "
                "The name identifies the purpose of each firewall rule on the endpoint and must "
                "be distinct."
            )
        seen_names[key] = idx

        ip_ranges = validate_destination_networks(
            dest.get("ip_ranges") or [], address_policy, context=f"destination '{name}'"
        )
        domains = normalize_domain_list(dest.get("domains") or [])

        if not ip_ranges:
            # The endpoint builds rules from ip_ranges only; a destination without addresses
            # produces no rule at all, so the browser silently cannot reach it.
            detail = (
                f"its domains {domains} were never resolved to addresses"
                if domains
                else "it declares no approved IP ranges and no domains"
            )
            raise EmptyAllowlistError(
                f"Destination '{name}' has no reachable address: {detail}. Resolve the "
                "destination through the trusted destination resolver, or add explicit "
                "approved_ip_ranges to the vendor profile. Compiling this policy would produce "
                "an allowlist that blocks the examination without saying so."
            )

        entry: Dict[str, Any] = {
            "name": name,
            "domains": domains,
            "ip_ranges": ip_ranges,
            "tcp_ports": normalize_ports(dest.get("tcp_ports") or []),
            "udp_ports": normalize_ports(dest.get("udp_ports") or []),
        }

        # Preserve resolution provenance when the resolver supplied it. It is nested inside the
        # destination rather than added at the envelope top level on purpose: the endpoint's
        # policy parser enforces a strict whitelist of top-level fields and rejects unknown ones,
        # while ignoring unknown keys inside a destination.
        resolution = dest.get("resolution")
        if resolution is not None:
            entry["resolution"] = _validate_resolution_metadata(resolution, name)

        validated.append(entry)

    if not validated:
        raise EmptyAllowlistError(
            "The compiled policy would contain no allowed destination at all, leaving the "
            "examination browser with nothing reachable once default-deny engages. Assign a "
            "vendor profile with approved IP ranges or resolvable domains before compiling."
        )

    validated.sort(key=lambda d: (d["name"], d["ip_ranges"][0] if d["ip_ranges"] else ""))
    return validated


_RESOLUTION_SOURCES = frozenset({"static", "trusted-dns", "system-resolver", "static-map"})


def _validate_resolution_metadata(resolution: Any, destination_name: str) -> Dict[str, Any]:
    """Validates the resolver's provenance block and returns it in canonical form.

    It is signed alongside the addresses, so it has to be as well-formed as the rest of the
    payload; and because it is the audit record of where each address came from, a malformed or
    fabricated block is a reason to refuse to sign rather than something to drop.
    """
    if not isinstance(resolution, dict):
        raise PolicyCompilationError(
            f"Destination '{destination_name}': resolution metadata must be an object"
        )

    source = resolution.get("source")
    if not isinstance(source, str) or not source:
        raise PolicyCompilationError(
            f"Destination '{destination_name}': resolution.source must be a non-empty string"
        )
    for part in source.split("+"):
        if part not in _RESOLUTION_SOURCES:
            raise PolicyCompilationError(
                f"Destination '{destination_name}': unknown resolution source '{part}'. "
                f"Known sources: {sorted(_RESOLUTION_SOURCES)}."
            )

    resolved_at = resolution.get("resolved_at")
    if not isinstance(resolved_at, str) or not resolved_at:
        raise PolicyCompilationError(
            f"Destination '{destination_name}': resolution.resolved_at must be an ISO-8601 string"
        )
    try:
        parsed = resolved_at[:-1] + "+00:00" if resolved_at.endswith("Z") else resolved_at
        datetime.fromisoformat(parsed)
    except Exception as exc:
        raise PolicyCompilationError(
            f"Destination '{destination_name}': resolution.resolved_at '{resolved_at}' is not a "
            f"parseable timestamp: {exc}"
        )

    raw_map = resolution.get("domain_map") or {}
    if not isinstance(raw_map, dict):
        raise PolicyCompilationError(
            f"Destination '{destination_name}': resolution.domain_map must be an object"
        )
    domain_map = {
        validate_and_normalize_domain(domain): normalize_ip_network_list(list(ips or []))
        for domain, ips in raw_map.items()
    }

    static_ranges = normalize_ip_network_list(list(resolution.get("static_ranges") or []))

    return {
        "source": source,
        "resolved_at": resolved_at,
        "domain_map": {d: domain_map[d] for d in sorted(domain_map)},
        "static_ranges": static_ranges,
    }
