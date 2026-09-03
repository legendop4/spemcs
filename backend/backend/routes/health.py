"""Health check endpoint."""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("")
def health_check(db: Session = Depends(get_db)):
    """Basic health check — verifies API and database connectivity."""
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    return {
        "status": "ok" if db_status == "connected" else "degraded",
        "database": db_status,
    }


management_router = APIRouter(prefix="/api/v1/management", tags=["management"])


@management_router.get("/health")
def management_health_check(db: Session = Depends(get_db)):
    """Application-level health verification endpoint for SPEMCS management control plane."""
    from datetime import datetime
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    return {
        "service": "SPEMCS",
        "status": "ok" if db_status == "connected" else "degraded",
        "version": "1.0",
        "database": db_status,
        "server_time_utc": datetime.utcnow().isoformat() + "Z",
    }
