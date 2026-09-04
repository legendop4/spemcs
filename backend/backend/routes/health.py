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
def management_health_check():
    """Application-level health verification endpoint for SPEMCS management control plane.

    IMPORTANT: This endpoint is polled by ManagementConnectivityVerifier on the endpoint
    agent (NT AUTHORITY\\SYSTEM) both immediately before and immediately after the firewall
    default-outbound-block is applied, against a hard ~3s client-side timeout. Its only job
    is to prove that the agent can still reach the management control plane over the network
    -- it must respond fast and deterministically regardless of downstream dependency health.

    This intentionally does NOT touch the database. DATABASE_URL points at a remote,
    serverless Neon Postgres instance (see backend/README.md) which auto-suspends its
    compute after a period of inactivity; the first query after suspension pays a cold-start
    penalty that can run well past 3 seconds. Previously this endpoint ran `SELECT 1` on
    every call, so the pre/post-enforcement probe would intermittently time out whenever the
    Neon compute happened to be asleep -- even though the backend process itself, and the
    network path to it, were perfectly reachable. That produced exactly the symptom reported
    in practice: the same probe passing most of the time and failing unpredictably, with a
    manual `curl` right afterwards (which re-woke the DB) succeeding immediately.

    Overall API/database health (for dashboards, ops monitoring, etc.) is still available at
    GET /api/health, which is not on this latency budget.
    """
    from datetime import datetime

    return {
        "service": "SPEMCS",
        "status": "ok",
        "version": "1.0",
        "server_time_utc": datetime.utcnow().isoformat() + "Z",
    }
