from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from backend.services.policy_signer import SUPPORTED_APPROVED_BROWSERS


def _validate_approved_browser(value: Optional[str]) -> Optional[str]:
    """Normalize and gate `approved_browser` on the WRITE path.

    An exam whose approved_browser cannot be scoped to a real executable is an exam that
    can never be activated with network enforcement: the policy compiler raises
    InvalidApprovedBrowserError, the signer raises UnsupportedApprovedBrowserError, and the
    endpoint agent rejects the payload. Catching it here turns "the exam silently cannot
    start on exam day" into a 422 at creation time, while the admin is still looking at the
    form.

    Deliberately NOT applied to ExamBase/ExamRead. Those are how existing rows are read
    back, and models.exam.ApprovedBrowser still carries FIREFOX so historical rows keep
    loading. Validating on read would turn old data into a 500 on the exam list.
    """
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized not in SUPPORTED_APPROVED_BROWSERS:
        raise ValueError(
            f"approved_browser must be one of {sorted(SUPPORTED_APPROVED_BROWSERS)}; got '{value}'. "
            "Firefox is not supported: the endpoint agent classifies firefox.exe as an "
            "unapproved browser and cannot scope firewall allow rules to it."
        )
    return normalized


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
    network_enforcement: Optional[bool] = False
    vendor_profile_id: Optional[UUID] = None

    model_config = ConfigDict(from_attributes=True)

    _normalize_browser = field_validator("approved_browser")(_validate_approved_browser)


class ExamUpdate(BaseModel):
    exam_name: Optional[str] = None
    section: Optional[str] = None
    exam_link: Optional[str] = None
    approved_browser: Optional[str] = None
    status: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    network_enforcement: Optional[bool] = None
    vendor_profile_id: Optional[UUID] = None

    model_config = ConfigDict(from_attributes=True)

    _normalize_browser = field_validator("approved_browser")(_validate_approved_browser)


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
