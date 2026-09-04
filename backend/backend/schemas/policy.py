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


class NetworkPolicyRead(BaseModel):
    policy_id: UUID
    exam_id: UUID
    version: int
    vendor_profile_id: Optional[UUID] = None
    allowed_destinations: List[Dict[str, Any]]
    management_server: Dict[str, Any]
    not_before: datetime
    expires_at: datetime
    signature: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
