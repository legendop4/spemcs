from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ExamBase(BaseModel):
    exam_name: str
    section: Optional[str] = None
    exam_link: Optional[str] = None
    approved_browser: str = "chrome"
    status: str = "pending"
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ExamCreate(BaseModel):
    exam_name: str
    section: Optional[str] = None
    exam_link: Optional[str] = None
    approved_browser: str = "chrome"
    device_ids: Optional[List[UUID]] = None  # devices to assign on creation

    model_config = ConfigDict(from_attributes=True)


class ExamUpdate(BaseModel):
    exam_name: Optional[str] = None
    section: Optional[str] = None
    exam_link: Optional[str] = None
    approved_browser: Optional[str] = None
    status: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ExamRead(ExamBase):
    exam_id: UUID
    created_at: Optional[datetime] = None
    device_count: Optional[int] = None
    alert_count: Optional[int] = None
    session_count: Optional[int] = None


class ExamDeviceBase(BaseModel):
    exam_id: UUID
    device_id: UUID
    status: str = "pending"

    model_config = ConfigDict(from_attributes=True)


class ExamDeviceCreate(ExamDeviceBase):
    id: Optional[UUID] = None


class ExamDeviceUpdate(BaseModel):
    exam_id: Optional[UUID] = None
    device_id: Optional[UUID] = None
    status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ExamDeviceRead(ExamDeviceBase):
    id: UUID
    device_name: Optional[str] = None
    device_status: Optional[str] = None
