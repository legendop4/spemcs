"""Report -> generated once an exam's status moves to STOPPED.
Frontend only displays this; it never reconstructs a report itself."""

import uuid
from datetime import datetime

from sqlalchemy import Column, Integer, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from .base import Base


class Report(Base):
    __tablename__ = "reports"

    report_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    exam_id = Column(UUID(as_uuid=True), ForeignKey("exams.exam_id"), nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # structured content - exam summary, per-student violation summary,
    # violation-type breakdown, event timeline (see earlier SPEMCS spec, sec.24)
    summary = Column(JSONB, nullable=True)
    report_data = Column(JSONB, nullable=True)

    alert_count = Column(Integer, default=0, nullable=False)
    event_count = Column(Integer, default=0, nullable=False)

    exam = relationship("Exam", back_populates="reports")
