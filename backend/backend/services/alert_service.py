"""Alert management service."""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.models.alert import Alert
from backend.models.device import Device
from backend.models.exam import Exam
from backend.models.session import ExamSession

logger = logging.getLogger(__name__)


def get_alerts_for_exam(db: Session, exam_id: UUID, limit: int = 100) -> list[dict]:
    """Get alerts for an exam with device and student info."""
    results = (
        db.query(Alert, Device)
        .join(Device, Alert.device_id == Device.device_id)
        .filter(Alert.exam_id == exam_id)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )
    
    alerts = []
    for alert, device in results:
        alert_dict = {
            "alert_id": str(alert.alert_id),
            "event_id": str(alert.event_id),
            "exam_id": str(alert.exam_id),
            "device_id": str(alert.device_id),
            "device_name": device.device_name,
            "severity": alert.severity,
            "message": alert.message,
            "status": alert.status,
            "agent_event_id": alert.agent_event_id,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        }
        
        # Try to get student info from the related event's session
        if alert.event and alert.event.student_roll_number:
            alert_dict["student_roll_number"] = alert.event.student_roll_number
        
        alerts.append(alert_dict)
    
    return alerts


def update_alert_status(
    db: Session,
    alert_id: UUID,
    status: str,
) -> Alert:
    """Update an alert's status (open -> acknowledged -> resolved)."""
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")
    
    valid_transitions = {
        "open": ["acknowledged", "resolved"],
        "acknowledged": ["resolved"],
        "resolved": [],
    }
    
    allowed = valid_transitions.get(alert.status, [])
    if status not in allowed:
        raise ValueError(
            f"Invalid status transition: {alert.status} -> {status}. "
            f"Allowed: {allowed}"
        )
    
    alert.status = status
    db.commit()
    db.refresh(alert)
    
    logger.info(f"Alert {alert_id} status updated to {status}")
    return alert


def check_duplicate(db: Session, agent_event_id: str) -> Optional[Alert]:
    """Check if an alert with this agent_event_id already exists."""
    return db.query(Alert).filter(Alert.agent_event_id == agent_event_id).first()
