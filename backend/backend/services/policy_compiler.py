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
    policy_id: Optional[Union[str, uuid.UUID]] = None,
    resolved_destinations: Optional[List[Dict[str, Any]]] = None,
    key_id: str = "dev-key-1",
    schema_version: str = "1.0",
) -> Dict[str, Any]:
    """Compiles an examination configuration and vendor profile into a deterministic,
    M2-ready canonical policy envelope.
    
    Pure & Deterministic:
    - Input ordering of destinations, IPs, ports, and domains does not affect output.
    - All collections are deduplicated and deterministically sorted.
    - Output conforms strictly to M2 MANDATORY_PAYLOAD_FIELDS.
    - Excludes transient state or local database IDs (created_at, db PKs).
    """
    # 1. Validate Identifiers
    try:
        exam_uuid_str = str(uuid.UUID(str(exam_id)))
    except Exception as exc:
        raise PolicyCompilationError(f"Invalid exam_id '{exam_id}': {exc}")

    pol_id_str = str(uuid.UUID(str(policy_id))) if policy_id else str(uuid.uuid4())

    if not isinstance(version, int) or version < 1:
        raise PolicyCompilationError(f"Policy version must be a positive integer >= 1, got {version!r}")

    # 2. Validate Validity Window
    nb_str, exp_str = validate_validity_window(not_before, expires_at)

    # 3. Validate Management Server
    norm_management = validate_management_server(management_server)

    # 4. Process Vendor Profile Destinations
    vendor_profile_id_str = None
    vendor_destinations: List[Dict[str, Any]] = []

    if vendor_profile is not None:
        # Support either SQLAlchemy model instance or dict
        if hasattr(vendor_profile, "vendor_id"):
            vendor_profile_id_str = str(vendor_profile.vendor_id)
            v_name = getattr(vendor_profile, "vendor_name", "Vendor LMS")
            v_domains = getattr(vendor_profile, "required_domains", []) or []
            v_ips = getattr(vendor_profile, "approved_ip_ranges", []) or []
            v_tcp = getattr(vendor_profile, "required_tcp_ports", []) or []
            v_udp = getattr(vendor_profile, "required_udp_ports", []) or []
        elif isinstance(vendor_profile, dict):
            vendor_profile_id_str = str(vendor_profile.get("vendor_id")) if vendor_profile.get("vendor_id") else None
            v_name = vendor_profile.get("vendor_name", "Vendor LMS")
            v_domains = vendor_profile.get("required_domains", []) or []
            v_ips = vendor_profile.get("approved_ip_ranges", []) or []
            v_tcp = vendor_profile.get("required_tcp_ports", []) or []
            v_udp = vendor_profile.get("required_udp_ports", []) or []
        else:
            raise PolicyCompilationError(f"Unsupported vendor_profile type: {type(vendor_profile).__name__}")

        norm_domains = normalize_domain_list(v_domains)
        norm_ips = normalize_ip_network_list(v_ips)
        norm_tcp = normalize_ports(v_tcp)
        norm_udp = normalize_ports(v_udp)

        # A destination structure includes both approved IP ranges and domain requirements metadata
        vendor_dest = {
            "name": str(v_name),
            "domains": norm_domains,
            "ip_ranges": norm_ips,
            "tcp_ports": norm_tcp,
            "udp_ports": norm_udp,
        }
        vendor_destinations.append(vendor_dest)

    # 5. Process Additional / Resolved Destinations (e.g. campus DNS, external pre-resolved LMS)
    extra_destinations: List[Dict[str, Any]] = []
    if resolved_destinations:
        if not isinstance(resolved_destinations, (list, tuple)):
            raise PolicyCompilationError("resolved_destinations must be a list of destination dicts")
        for idx, dest in enumerate(resolved_destinations):
            if not isinstance(dest, dict):
                raise PolicyCompilationError(f"Destination at index {idx} must be a dictionary")
            d_name = str(dest.get("name", f"Destination-{idx+1}"))
            d_domains = normalize_domain_list(dest.get("domains", []) or [])
            d_ips = normalize_ip_network_list(dest.get("ip_ranges", []) or [])
            d_tcp = normalize_ports(dest.get("tcp_ports", []) or [])
            d_udp = normalize_ports(dest.get("udp_ports", []) or [])
            extra_destinations.append({
                "name": d_name,
                "domains": d_domains,
                "ip_ranges": d_ips,
                "tcp_ports": d_tcp,
                "udp_ports": d_udp,
            })

    # 6. Combine and Sort Destinations Deterministically
    all_destinations = vendor_destinations + extra_destinations
    # Sort deterministically by name, then primary IP range if names match
    all_destinations.sort(key=lambda d: (d["name"], d["ip_ranges"][0] if d["ip_ranges"] else ""))

    # 7. Construct Final Canonical Payload (Strictly conforming to M2 envelope)
    compiled_payload = {
        "schema_version": str(schema_version),
        "key_id": str(key_id),
        "exam_id": exam_uuid_str,
        "policy_id": pol_id_str,
        "version": int(version),
        "vendor_profile_id": vendor_profile_id_str,
        "allowed_destinations": all_destinations,
        "management_server": norm_management,
        "not_before": nb_str,
        "expires_at": exp_str,
    }

    return compiled_payload
