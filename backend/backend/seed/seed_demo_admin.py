"""Create the documented demo administrator in the configured PostgreSQL database."""

import logging

from sqlalchemy.orm import Session

from backend.models.user import User, UserRole
from backend.services.auth_service import hash_password, verify_password

logger = logging.getLogger(__name__)

DEMO_USERNAME = "admin"
DEMO_EMAIL = "admin@campusshield.edu"
DEMO_PASSWORD = "Admin@0123"


def ensure_demo_admin(db: Session) -> None:
    """Idempotently create the demo account or ensure its password hash is valid."""
    existing = db.query(User).filter(User.username == DEMO_USERNAME).first()
    if existing:
        if not verify_password(DEMO_PASSWORD, existing.password_hash or ""):
            new_hash = hash_password(DEMO_PASSWORD)
            existing.password_hash = new_hash
            existing.password = new_hash
            existing.is_active = True
            db.commit()
            logger.info("Demo administrator password hash refreshed")
        return

    email = DEMO_EMAIL
    if db.query(User).filter(User.email == email).first():
        email = "admin-demo@campusshield.edu"

    password_hash = hash_password(DEMO_PASSWORD)
    db.add(User(
        name="CampusShield Administrator",
        username=DEMO_USERNAME,
        email=email,
        password=password_hash,
        password_hash=password_hash,
        role=UserRole.ADMIN.value,
        avatar_color="#D89400",
        is_active=True,
    ))
    db.commit()
    logger.info("Demo administrator account created")
