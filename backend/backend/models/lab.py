import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, Boolean, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base


class LabStatus(str, enum.Enum):
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    INACTIVE = "inactive"


class Lab(Base):
    __tablename__ = "labs"

    lab_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    building_id = Column(String, nullable=False)
    lab_name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    capacity = Column(Integer, nullable=False)
    spemcs_enabled = Column(Boolean, nullable=False, default=False)
    status = Column(String, default=LabStatus.ACTIVE.value, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # relationships
    devices = relationship("LabDevice", back_populates="lab")

    __table_args__ = (
        Index("ix_labs_building_lab", "building_id", "lab_name"),
    )
