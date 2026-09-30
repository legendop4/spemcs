"""Idempotently seed the initial administrator if no administrator exists."""

import logging

from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.models.user import User, UserRole
from backend.services.auth_service import hash_password

logger = logging.getLogger(__name__)

INITIAL_ADMIN_USERNAME = "admin"
INITIAL_ADMIN_EMAIL = "admin@campusshield.edu"


def ensure_demo_admin(db: Session) -> None:
    """Create the initial administrator account if no admin account exists.

    CRITICAL SECURITY INVARIANT:
    If an administrator account already exists, this function MUST NEVER modify,
    refresh, or overwrite its password hash. The password must remain persistent
    across application restarts, ECS task lifecycle events, and rolling deployments.
    """
    existing = db.query(User).filter(User.username == INITIAL_ADMIN_USERNAME).first()
    if existing:
        # Account already exists: NEVER modify its password on startup.
        return

    # Check if an initial password was injected via environment/secrets
    initial_password = (settings.INITIAL_ADMIN_PASSWORD or "").strip()
    if not initial_password:
        logger.info(
            "No admin account exists and INITIAL_ADMIN_PASSWORD is not configured; skipping initial admin creation."
        )
        return

    if len(initial_password) < 8:
        logger.warning(
            "INITIAL_ADMIN_PASSWORD must be at least 8 characters; skipping initial admin creation."
        )
        return

    email = INITIAL_ADMIN_EMAIL
    if db.query(User).filter(User.email == email).first():
        email = "admin-initial@campusshield.edu"

    password_hash = hash_password(initial_password)
    db.add(User(
        name="CampusShield Administrator",
        username=INITIAL_ADMIN_USERNAME,
        email=email,
        password=password_hash,
        password_hash=password_hash,
        role=UserRole.ADMIN.value,
        avatar_color="#D89400",
        is_active=True,
    ))
    db.commit()
    logger.info("Initial administrator account '%s' created from INITIAL_ADMIN_PASSWORD", INITIAL_ADMIN_USERNAME)

