"""Read-only audit-log API for the administrative dashboard."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.models.audit_log import AuditLog
from backend.schemas.audit_log import AuditLogRead

router = APIRouter(prefix="/api/audit-logs", tags=["audit-logs"])


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )
