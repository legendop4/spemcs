from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AlertBase(BaseModel):
    event_id: Optional[UUID] = None
    exam_id: Optional[UUID] = None
    device_id: Optional[UUID] = None
    severity: str
    message: str
    status: str = "open"
    agent_event_id: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AlertCreate(AlertBase):
    alert_id: Optional[UUID] = None


class AlertUpdate(BaseModel):
    severity: Optional[str] = None
    message: Optional[str] = None
    status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AlertRead(AlertBase):
    alert_id: UUID


class AlertReadDetailed(AlertRead):
    """Alert with joined device, exam, and suspicious process info for dashboard display."""
    device_name: Optional[str] = None
    exam_name: Optional[str] = None
    student_roll_number: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    executable_path: Optional[str] = None
    event_type: Optional[str] = None
    reason: Optional[str] = None
    classification: Optional[str] = None
    ip_address: Optional[str] = None
