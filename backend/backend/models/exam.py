"""Exam -> created/configured by admin. ExamDevice -> which devices are selected for an exam."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, String, Text, Boolean, DateTime, ForeignKey, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base


class ExamStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    STOPPED = "stopped"
    COMPLETED = "stopped"


class ApprovedBrowser(str, enum.Enum):
    CHROME = "chrome"
    FIREFOX = "firefox"
    EDGE = "edge"


class ExamDeviceStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    MONITORING = "monitoring"


class Exam(Base):
    __tablename__ = "exams"

    exam_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    exam_name = Column(String(150), nullable=False)
    section = Column(String(150), nullable=True)
    exam_link = Column(Text, nullable=True)  # allowed URL for the exam
    approved_browser = Column(String(20), nullable=False)
    status = Column(String(20), default=ExamStatus.PENDING.value, nullable=False)
    network_enforcement = Column(Boolean, default=False, nullable=False)
    vendor_profile_id = Column(UUID(as_uuid=True), ForeignKey("vendor_profiles.vendor_id"), nullable=True)
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # relationships
    device_links = relationship("ExamDevice", back_populates="exam", cascade="all, delete-orphan")
    sessions = relationship("ExamSession", back_populates="exam")
    alerts = relationship("Alert", back_populates="exam")
    reports = relationship("Report", back_populates="exam")
    vendor_profile = relationship("VendorProfile", back_populates="exams")
    network_policies = relationship("NetworkPolicy", back_populates="exam", cascade="all, delete-orphan")
    device_policy_states = relationship("DevicePolicyState", back_populates="exam", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_exams_exam_name", "exam_name"),
        Index("ix_exams_status", "status"),
    )


class ExamDevice(Base):
    """Join table: which devices are selected/participating in a given exam."""

    __tablename__ = "exam_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.exam_id"), nullable=False)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.device_id"), nullable=False)
    status = Column(String(20), default=ExamDeviceStatus.PENDING.value, nullable=False)

    exam = relationship("Exam", back_populates="device_links")
    device = relationship("Device", back_populates="exam_links")

    __table_args__ = (
        UniqueConstraint("exam_id", "device_id", name="uq_exam_device"),
        Index("ix_exam_devices_exam_id", "exam_id"),
    )
