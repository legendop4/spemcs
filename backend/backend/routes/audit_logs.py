"""Read-only audit-log API for the administrative dashboard."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.dependencies import require_admin
from backend.models.audit_log import AuditLog
from backend.schemas.audit_log import AuditLogRead

# Administrators only, not staff. The audit log is the record of who activated which exam, who
# created which account and who logged in when - it is the evidence an incident review reads, and
# it names every operator. Read access is therefore narrower than read access to the exam data the
# log describes.
router = APIRouter(
    prefix="/api/audit-logs",
    tags=["audit-logs"],
    dependencies=[Depends(require_admin)],
)


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )
