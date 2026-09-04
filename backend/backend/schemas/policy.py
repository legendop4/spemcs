"""SPEMCS Policy Pydantic Schemas.

Defines request and response validation models for:
- VendorProfile CRUD
- NetworkPolicy compilation and inspection
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from backend.services.policy_compiler import (
    normalize_domain_list,
    normalize_ip_network_list,
    normalize_ports,
)


class VendorProfileBase(BaseModel):
    vendor_name: str
    description: Optional[str] = None
    required_domains: List[str] = []
    approved_ip_ranges: List[str] = []
    required_tcp_ports: List[int] = [80, 443]
    required_udp_ports: List[int] = []

    model_config = ConfigDict(from_attributes=True)


class VendorProfileCreate(VendorProfileBase):
    @field_validator("vendor_name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("vendor_name cannot be empty")
        return s

    @field_validator("required_domains")
    @classmethod
    def validate_domains(cls, v: List[str]) -> List[str]:
        return normalize_domain_list(v)

    @field_validator("approved_ip_ranges")
    @classmethod
    def validate_ips(cls, v: List[str]) -> List[str]:
        return normalize_ip_network_list(v)

    @field_validator("required_tcp_ports")
    @classmethod
    def validate_tcp(cls, v: List[int]) -> List[int]:
        return normalize_ports(v)

    @field_validator("required_udp_ports")
    @classmethod
    def validate_udp(cls, v: List[int]) -> List[int]:
        return normalize_ports(v)


class VendorProfileUpdate(BaseModel):
    vendor_name: Optional[str] = None
    description: Optional[str] = None
    required_domains: Optional[List[str]] = None
    approved_ip_ranges: Optional[List[str]] = None
    required_tcp_ports: Optional[List[int]] = None
    required_udp_ports: Optional[List[int]] = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("vendor_name")
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            s = v.strip()
            if not s:
                raise ValueError("vendor_name cannot be empty")
            return s
        return v

    @field_validator("required_domains")
    @classmethod
    def validate_domains(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            return normalize_domain_list(v)
        return v

    @field_validator("approved_ip_ranges")
    @classmethod
    def validate_ips(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            return normalize_ip_network_list(v)
        return v

    @field_validator("required_tcp_ports")
    @classmethod
    def validate_tcp(cls, v: Optional[List[int]]) -> Optional[List[int]]:
        if v is not None:
            return normalize_ports(v)
        return v

    @field_validator("required_udp_ports")
    @classmethod
    def validate_udp(cls, v: Optional[List[int]]) -> Optional[List[int]]:
        if v is not None:
            return normalize_ports(v)
        return v


class VendorProfileRead(VendorProfileBase):
    vendor_id: UUID
    created_at: datetime


class PolicyCompileRequest(BaseModel):
    vendor_profile_id: Optional[UUID] = None
    version: int = 1
    management_server: Optional[Dict[str, Any]] = None
    not_before: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    resolved_destinations: Optional[List[Dict[str, Any]]] = None

    model_config = ConfigDict(from_attributes=True)

    # NOTE: `approved_browser` is deliberately NOT accepted here. It is the executable
    # identity that endpoint firewall allow rules are scoped to, so it is read from trusted
    # server-side exam configuration (Exam.approved_browser) rather than from the request
    # body. Accepting it from a caller would let whoever can reach this endpoint change
    # which program the exam allowlist applies to without changing the exam itself.


class NetworkPolicyRead(BaseModel):
    policy_id: UUID
    exam_id: UUID
    version: int
    vendor_profile_id: Optional[UUID] = None
    approved_browser: str
    allowed_destinations: List[Dict[str, Any]]
    management_server: Dict[str, Any]
    not_before: datetime
    expires_at: datetime
    key_id: str
    schema_version: str
    signature: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Signing key lifecycle
# ==============================================================================
# Every model here carries PUBLIC key material only. There is deliberately no field that could
# hold a private key or a passphrase, so no response model in this module is capable of leaking
# one even if a future handler passes it the wrong object.


class SigningKeyRead(BaseModel):
    """One signing key as published to endpoint agents and operators."""

    key_id: str
    public_key_pem: str
    # "active" (signs new policies), "retired" (still verifies older policies), or "revoked"
    # (must be rejected outright).
    state: str
    created_at: Optional[str] = None
    retired_at: Optional[str] = None
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None


class SigningKeyringRead(BaseModel):
    """The full set of keys an agent needs in order to make correct decisions.

    Agents get the whole set rather than just the active key because three different answers
    have to be distinguishable: a retired key still verifies policies signed before the last
    rotation, a revoked key must be refused even though its signature is cryptographically
    valid, and an id absent from this list is merely unknown - which is not the same decision.
    """

    active_key_id: str
    keys: List[SigningKeyRead]
    revoked_key_ids: List[str] = []
    # True when the active key lives only in the backend's memory and will not survive a
    # restart. Agents and operators should treat this as a misconfigured deployment.
    ephemeral: bool = False


class SigningKeyRevokeRequest(BaseModel):
    """A revocation is permanent and is audit evidence, so the reason is mandatory."""

    reason: str

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, v: str) -> str:
        s = (v or "").strip()
        if not s:
            raise ValueError("A revocation reason is required")
        return s


class SigningKeyRotateRequest(BaseModel):
    reason: Optional[str] = None
