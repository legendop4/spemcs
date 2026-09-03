"""ExamSession -> one student's attempt on one device, for one exam.
This is the entity Events and Alerts hang off of."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base


class SessionStatus(str, enum.Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"


class ExamSession(Base):
    __tablename__ = "exam_sessions"

    session_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.exam_id"), nullable=False)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.device_id"), nullable=False)
    student_roll_number = Column(String(50), nullable=False)
    status = Column(String(20), default=SessionStatus.ACTIVE.value, nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ended_at = Column(DateTime, nullable=True)

    exam = relationship("Exam", back_populates="sessions")
    device = relationship("Device", back_populates="sessions")
    events = relationship("Event", back_populates="session")

    __table_args__ = (
        Index("ix_exam_sessions_session_id", "session_id"),
        Index("ix_exam_sessions_exam_id", "exam_id"),
        Index("ix_exam_sessions_device_id", "device_id"),
    )
