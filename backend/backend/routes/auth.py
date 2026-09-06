"""Authentication routes — JWT login, registration, and token verification."""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.dependencies import require_admin
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
def register_user(
    req: UserCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_admin),
):
    """Create an operator account. Administrators only.

    THIS ENDPOINT IS NOT SELF-SERVICE REGISTRATION, and the change from what it used to be is the
    point. Previously it was reachable unauthenticated and ``UserCreate.role`` defaulted to
    ``"admin"``, so a single anonymous POST with a username, an email and a password created a
    full administrator - no role manipulation required, because omitting the field was already
    the privilege escalation. Anyone who could reach the API owned it.

    There is no legitimate self-service path in an examination control system: an account here can
    activate exams, compile signed network policies and read every candidate's violation history.
    Accounts are therefore created BY an administrator, and the frontend never called this
    endpoint (``api.register`` is exported but has no consumer), so nothing user-facing depended
    on the anonymous behaviour.

    Bootstrap is unaffected: the first administrator is seeded at startup by
    ``backend.seed.seed_demo_admin.ensure_demo_admin``, so the requirement for an existing
    administrator can always be met.
    """
    existing = db.query(User).filter(
        (User.username == req.username) | (User.email == req.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    # req.role is a UserRole enum, so an unknown role was already rejected as a 422 by the schema.
    # Taking .value here rather than str(req.role) keeps the stored column as "admin"/"proctor"
    # instead of "UserRole.ADMIN", which require_role would then never match.
    role_value = req.role.value

    password_hash = hash_password(req.password)
    user = User(
        name=req.username,
        username=req.username,
        email=req.email,
        password=password_hash,
        password_hash=password_hash,
        role=role_value,
        avatar_color="#D89400",
    )
    db.add(user)
    db.flush()
    # Who created a privileged account is exactly the thing an incident review needs, and it was
    # not recorded before - the old log line named the new account but not its creator.
    db.add(AuditLog(
        user_id=actor.user_id,
        action="USER_CREATED",
        entity_type="user",
        entity_id=str(user.user_id),
        details={"username": user.username, "role": role_value,
                 "created_by": actor.username},
    ))
    db.commit()
    db.refresh(user)
    logger.info("User %s created account %s with role %s",
                actor.username, user.username, role_value)
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
