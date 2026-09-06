from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Optional
from uuid import UUID

from backend.models.lab import LabStatus


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


class LabCreate(BaseModel):
    """Fields an administrator supplies when creating a lab.

    ``lab_id`` and ``created_at`` are absent deliberately - both are server-assigned, and accepting a
    caller-chosen primary key would let one request overwrite or probe for another lab's row.
    """

    building_id: str = Field(min_length=1, max_length=120)
    lab_name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=500)
    capacity: int = Field(ge=1, le=1000)
    # A new lab is NOT monitored until somebody says so. Defaulting this to True would mean creating
    # a room silently opts every workstation in it into enforcement.
    spemcs_enabled: bool = False
    status: LabStatus = LabStatus.ACTIVE

    model_config = ConfigDict(from_attributes=True)

    @field_validator("building_id", "lab_name")
    @classmethod
    def _reject_whitespace_only(cls, value: str) -> str:
        """Refuse an all-whitespace name, and store the trimmed form.

        ``min_length=1`` counts characters, so ``"   "`` satisfies it. A lab whose name is three
        spaces is indistinguishable from every other such lab in the wizard's dropdown - the person
        at the workstation sees a blank entry and cannot tell which room it is. Trimming as well as
        refusing matters for the duplicate check in ``create_lab``: ``"Lab 101"`` and ``"Lab 101 "``
        would otherwise be two different rooms.
        """
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("must not be blank")
        return trimmed


class LabEnrollmentRead(BaseModel):
    """The minimum a not-yet-enrolled workstation needs to name the lab it is being installed in.

    Deliberately narrower than :class:`LabRead`. This is the only lab shape reachable with the
    bootstrap enrolment key - a secret every workstation in the deployment holds, so it must be
    assumed readable by anyone who can copy an agent binary. ``description`` and ``created_at`` are
    withheld because nothing in the setup wizard uses them, and ``spemcs_enabled`` is withheld
    because the response already contains only enabled labs, so repeating it would add a field that
    is constant by construction.
    """

    lab_id: UUID
    building_id: str
    lab_name: str
    capacity: int

    model_config = ConfigDict(from_attributes=True)
