"""User model for admin/proctor authentication."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID

from .base import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    PROCTOR = "proctor"


class User(Base):
    __tablename__ = "users"

    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Legacy columns already required by the deployed PostgreSQL users table.
    # `password` receives the same bcrypt hash as `password_hash`; plaintext
    # passwords are never persisted.
    name = Column(String(100), nullable=False)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    # The column default is the LEAST privileged role. It used to be ADMIN, which made any future
    # insert that omitted `role` an administrator by accident - the same defect the UserCreate
    # schema had, one layer down. This is a Python-side default applied at INSERT, not a
    # server_default, so changing it needs no migration and rewrites no existing row.
    role = Column(String(20), default=UserRole.PROCTOR.value, nullable=False)
    avatar_color = Column(String(20), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
