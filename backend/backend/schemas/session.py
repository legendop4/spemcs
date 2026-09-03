from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ExamSessionBase(BaseModel):
    exam_id: UUID
    device_id: UUID
    student_roll_number: str
    status: str = "active"
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ExamSessionCreate(BaseModel):
    exam_id: UUID
    device_id: UUID
    student_roll_number: str
    session_id: Optional[UUID] = None

    model_config = ConfigDict(from_attributes=True)


class ExamSessionUpdate(BaseModel):
    student_roll_number: Optional[str] = None
    status: Optional[str] = None
    ended_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ExamSessionRead(ExamSessionBase):
    session_id: UUID
