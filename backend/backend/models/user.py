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
    role = Column(String(20), default=UserRole.ADMIN.value, nullable=False)
    avatar_color = Column(String(20), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
