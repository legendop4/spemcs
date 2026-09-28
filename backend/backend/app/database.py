"""Database engine, session factory, and dependency for FastAPI routes."""

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.config import settings

logger = logging.getLogger(__name__)

# Single SQLAlchemy engine connected to local PostgreSQL with strict UTC session timezone.
connect_args = {"options": "-c timezone=utc"} if "postgresql" in settings.DATABASE_URL else {}
engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_size=50, max_overflow=20, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency that yields a DB session and ensures cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        try:
            db.rollback()
        except Exception:
            pass
        try:
            db.close()
        except Exception as e:
            logger.warning(f"Error closing database session: {e}")
