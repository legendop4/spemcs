"""Device -> Agent registration. device_id is the permanent identity;
hardware_uuid is the immutable hardware identifier from WMI;
device_name is the human-readable label (Building:Lab:PC format)."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base


class DeviceStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"


class Device(Base):
    __tablename__ = "devices"

    device_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hardware_uuid = Column(String(100), unique=True, nullable=True, index=True)
    device_name = Column(String(100), nullable=False)  # e.g. "TechTower:Lab-03:PC-012"
    building_name = Column(String(50), nullable=True)
    lab_name = Column(String(50), nullable=True)
    pc_number = Column(String(10), nullable=True)
    registered_ip = Column(String(50), nullable=True)
    status = Column(String(20), default=DeviceStatus.OFFLINE.value, nullable=False)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # relationships
    exam_links = relationship("ExamDevice", back_populates="device")
    sessions = relationship("ExamSession", back_populates="device")
    lab_links = relationship("LabDevice", back_populates="device")
    alerts = relationship("Alert", back_populates="device")
    events = relationship("Event", back_populates="device")
    policy_states = relationship("DevicePolicyState", back_populates="device")

    __table_args__ = (
        Index("ix_devices_device_name", "device_name"),
        Index("ix_devices_building_lab", "building_name", "lab_name"),
    )
