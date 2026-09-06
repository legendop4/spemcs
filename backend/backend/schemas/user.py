"""Pydantic schemas for User authentication and management."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from backend.models.user import UserRole


class UserCreate(BaseModel):
    """Payload for creating an operator account.

    ``role`` was previously ``str = "admin"``. Two separate defects lived in that one line:

    1. The DEFAULT was administrator, so a request carrying only username, email and password -
       the minimum a client can send - produced a full administrator. Nothing had to be
       manipulated; omitting the field was the exploit.
    2. The type was an unconstrained ``str``, so any value was accepted and written straight to
       ``users.role``. ``require_role`` compares against a fixed allow-list, so an invented role
       like ``superadmin`` grants nothing today - but it also means the account bypasses every
       role check silently rather than being rejected at creation, and the next role list added
       anywhere in the system decides retroactively what that stored string means.

    Now the type is the :class:`~backend.models.user.UserRole` enum, so an unknown role is a 422
    at the boundary, and the default is the least-privileged role rather than the most. Creation
    is additionally gated on an authenticated administrator - see ``routes/auth.py`` - because
    validating the role field does not help if anyone may choose a valid privileged one.
    """

    username: str = Field(min_length=1, max_length=50)
    email: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    role: UserRole = UserRole.PROCTOR


class UserRead(BaseModel):
    user_id: UUID
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None
