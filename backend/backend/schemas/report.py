from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ReportBase(BaseModel):
    exam_id: UUID
    generated_at: Optional[datetime] = None
    summary: Optional[Dict[str, Any]] = None
    report_data: Optional[Dict[str, Any]] = None
    alert_count: int = 0
    event_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class ReportCreate(ReportBase):
    report_id: Optional[UUID] = None


class ReportUpdate(BaseModel):
    exam_id: Optional[UUID] = None
    generated_at: Optional[datetime] = None
    summary: Optional[Dict[str, Any]] = None
    report_data: Optional[Dict[str, Any]] = None
    alert_count: Optional[int] = None
    event_count: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)


class ReportRead(ReportBase):
    report_id: UUID
