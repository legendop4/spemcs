from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class EventBase(BaseModel):
    session_id: Optional[UUID] = None
    device_id: UUID
    device_name: str
    ip_address: Optional[str] = None
    student_roll_number: Optional[str] = None
    event_type: str
    timestamp: datetime
    process_name: Optional[str] = None
    pid: Optional[int] = None
    executable_path: Optional[str] = None
    classification: str
    reason: Optional[str] = None
    resolution_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EventCreate(EventBase):
    event_id: Optional[UUID] = None


class EventUpdate(BaseModel):
    session_id: Optional[UUID] = None
    device_id: Optional[UUID] = None
    device_name: Optional[str] = None
    ip_address: Optional[str] = None
    student_roll_number: Optional[str] = None
    event_type: Optional[str] = None
    timestamp: Optional[datetime] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    executable_path: Optional[str] = None
    classification: Optional[str] = None
    reason: Optional[str] = None
    resolution_status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EventRead(EventBase):
    event_id: UUID
