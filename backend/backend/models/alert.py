"""Alert -> one per event, surfaced to the Admin Portal over WebSocket."""

import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base


class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.event_id"), nullable=False, unique=True)
    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.exam_id"), nullable=False)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.device_id"), nullable=False)

    # Deduplication: agent-generated event ID to prevent duplicate alerts
    agent_event_id = Column(String(100), unique=True, nullable=True, index=True)

    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    message = Column(String, nullable=False)
    status = Column(String(20), nullable=False, default="open")  # open, acknowledged, resolved

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    event = relationship("Event", back_populates="alert")
    exam = relationship("Exam", back_populates="alerts")
    device = relationship("Device", back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_exam_id", "exam_id"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_device_id", "device_id"),
    )
