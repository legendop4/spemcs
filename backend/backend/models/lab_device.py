import uuid
from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import ForeignKey, Index
from sqlalchemy.orm import relationship

from .base import Base


class LabDevice(Base):
    __tablename__ = "lab_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    lab_id = Column(UUID(as_uuid=True), ForeignKey("labs.lab_id"), nullable=False)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.device_id"), nullable=False)

    lab = relationship("Lab", back_populates="devices")
    device = relationship("Device", back_populates="lab_links")

    __table_args__ = (
        Index("ix_lab_devices_lab_id", "lab_id"),
        Index("ix_lab_devices_device_id", "device_id"),
    )
