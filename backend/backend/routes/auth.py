"""Authentication routes — JWT login, registration, and token verification."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.models.audit_log import AuditLog
from backend.models.user import User
from backend.schemas.user import UserCreate, UserRead, UserLogin, Token
from backend.services.auth_service import (
    create_access_token,
    hash_password,
    require_auth,
    verify_password,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(req: UserCreate, db: Session = Depends(get_db)):
    """Register a new admin/proctor user."""
    existing = db.query(User).filter(
        (User.username == req.username) | (User.email == req.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    password_hash = hash_password(req.password)
    user = User(
        name=req.username,
        username=req.username,
        email=req.email,
        password=password_hash,
        password_hash=password_hash,
        role=req.role,
        avatar_color="#D89400",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info(f"User registered: {user.username} ({user.role})")
    return user


@router.post("/login", response_model=Token)
def login(req: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    token = create_access_token(
        data={"sub": str(user.user_id), "username": user.username, "role": user.role}
    )
    db.add(AuditLog(
        user_id=user.user_id,
        action="LOGIN",
        entity_type="user",
        entity_id=str(user.user_id),
        details={"username": user.username},
    ))
    db.commit()
    logger.info(f"User logged in: {user.username}")
    return Token(access_token=token)


@router.get("/me", response_model=UserRead)
def get_current_user_info(user: User = Depends(require_auth)):
    """Return the user represented by the supplied bearer token."""
    return user
