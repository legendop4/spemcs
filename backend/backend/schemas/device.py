from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class DeviceBase(BaseModel):
    device_name: str
    hardware_uuid: Optional[str] = None
    building_name: Optional[str] = None
    lab_name: Optional[str] = None
    pc_number: Optional[str] = None
    registered_ip: Optional[str] = None
    status: str = "offline"
    last_seen: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    device_name: Optional[str] = None
    hardware_uuid: Optional[str] = None
    building_name: Optional[str] = None
    lab_name: Optional[str] = None
    pc_number: Optional[str] = None
    registered_ip: Optional[str] = None
    status: Optional[str] = None
    last_seen: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class DeviceRead(DeviceBase):
    device_id: UUID
    created_at: datetime
    risk_score: Optional[int] = 0
    risk_level: Optional[str] = "normal"


class DeviceTreeNode(BaseModel):
    """Hierarchical device tree node for Building -> Lab -> PC selection."""
    name: str
    type: str  # 'building', 'lab', 'device'
    id: Optional[str] = None
    device_id: Optional[UUID] = None
    hardware_uuid: Optional[str] = None
    status: Optional[str] = None
    children: list["DeviceTreeNode"] = []

    model_config = ConfigDict(from_attributes=True)


DeviceTreeNode.model_rebuild()
