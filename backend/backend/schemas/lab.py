from datetime import datetime
from pydantic import BaseModel, ConfigDict
from typing import Optional
from uuid import UUID


class LabBase(BaseModel):
    lab_id: UUID
    building_id: str
    lab_name: str
    description: Optional[str] = None
    capacity: int
    spemcs_enabled: bool = False
    status: str = "active"
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class LabRead(LabBase):
    pass


class LabUpdate(BaseModel):
    spemcs_enabled: Optional[bool] = None

    model_config = ConfigDict(from_attributes=True)
