"""SPEMCS Network Policy models.
Defines VendorProfile, NetworkPolicy, and DevicePolicyState for University Exam Network Policy Enforcement.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from .base import Base


class VendorProfile(Base):
    """Third-party examination vendor network requirements template (e.g. Moodle, Canvas)."""
    __tablename__ = "vendor_profiles"

    vendor_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vendor_name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    required_domains = Column(JSONB, nullable=False, default=list)       # e.g. ["moodle.univ.edu", "cdn.univ.edu"]
    approved_ip_ranges = Column(JSONB, nullable=False, default=list)     # e.g. ["192.168.10.0/24"]
    required_tcp_ports = Column(JSONB, nullable=False, default=lambda: [80, 443])
    required_udp_ports = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    exams = relationship("Exam", back_populates="vendor_profile")
    network_policies = relationship("NetworkPolicy", back_populates="vendor_profile")


class NetworkPolicy(Base):
    """Immutable, versioned policy compiled for an active examination session.

    Every column below (except created_at) is part of the RSA-PSS signed canonical payload.
    Distribution re-derives the exact signed bytes from these columns, so any signed field
    that is NOT persisted here cannot be reproduced and the stored signature would no longer
    verify. That is why `approved_browser`, `key_id`, and `schema_version` are columns rather
    than being re-supplied as constants at distribution time.
    """
    __tablename__ = "network_policies"

    policy_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.exam_id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, default=1, nullable=False)
    vendor_profile_id = Column(UUID(as_uuid=True), ForeignKey("vendor_profiles.vendor_id"), nullable=True)
    # Signed browser identity: the endpoint scopes vendor/exam firewall allow rules to this
    # browser family's executable. Must be one of policy_signer.SUPPORTED_APPROVED_BROWSERS.
    approved_browser = Column(String(20), nullable=False)
    allowed_destinations = Column(JSONB, nullable=False, default=list)   # list of {name, ip_ranges, tcp_ports, udp_ports}
    management_server = Column(JSONB, nullable=False, default=dict)      # {ip_addresses: [...], port: 8000}
    not_before = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    # Identity of the signing key that produced `signature`. Persisted so key rotation does
    # not invalidate previously issued policies and so distribution never hardcodes a key id.
    key_id = Column(String(64), nullable=False)
    schema_version = Column(String(10), nullable=False)
    signature = Column(Text, nullable=True)                              # Base64 RSA-PSS digital signature
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    exam = relationship("Exam", back_populates="network_policies")
    vendor_profile = relationship("VendorProfile", back_populates="network_policies")
    device_states = relationship("DevicePolicyState", back_populates="policy", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("exam_id", "version", name="uq_exam_policy_version"),
        Index("ix_network_policies_exam_id", "exam_id"),
    )


class DevicePolicyState(Base):
    """Tracks per-device network enforcement lifecycle state."""
    __tablename__ = "device_policy_states"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.exam_id", ondelete="CASCADE"), nullable=False)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("network_policies.policy_id"), nullable=False)
    status = Column(String(30), default="PENDING", nullable=False)       # PENDING, APPLYING, APPLIED, FAILED, ROLLED_BACK
    rules_installed = Column(Integer, default=0, nullable=False)
    last_error = Column(String(255), nullable=True)
    applied_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    exam = relationship("Exam", back_populates="device_policy_states")
    device = relationship("Device", back_populates="policy_states")
    policy = relationship("NetworkPolicy", back_populates="device_states")

    __table_args__ = (
        UniqueConstraint("exam_id", "device_id", name="uq_device_policy_state"),
        Index("ix_device_policy_states_device_id", "device_id"),
        Index("ix_device_policy_states_status", "status"),
    )
