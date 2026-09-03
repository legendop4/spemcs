from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.models.alert import Alert
from backend.models.event import Event
from backend.models.device import Device
from backend.models.exam import Exam
from backend.models.session import ExamSession
from backend.schemas.alert import AlertCreate, AlertRead, AlertReadDetailed, AlertUpdate

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _as_dict(model: Any) -> dict:
    return model.model_dump(exclude_unset=True) if hasattr(model, "model_dump") else model.dict(exclude_unset=True)


def _enrich_alert(db: Session, alert: Alert) -> dict:
    device = db.get(Device, alert.device_id) if alert.device_id else None
    exam = db.get(Exam, alert.exam_id) if alert.exam_id else None
    event = db.get(Event, alert.event_id) if alert.event_id else None
    session = (
        db.query(ExamSession)
        .filter(ExamSession.device_id == alert.device_id, ExamSession.exam_id == alert.exam_id)
        .first()
    ) if (alert.device_id and alert.exam_id) else None
    
    roll = None
    if event and event.student_roll_number and event.student_roll_number != "UNKNOWN":
        roll = event.student_roll_number
    elif session and session.student_roll_number:
        roll = session.student_roll_number
        
    dev_name = None
    if event and event.device_name:
        dev_name = event.device_name
    elif device and device.device_name:
        dev_name = device.device_name

    return {
        "alert_id": alert.alert_id,
        "event_id": alert.event_id,
        "exam_id": alert.exam_id,
        "device_id": alert.device_id,
        "severity": alert.severity,
        "message": alert.message,
        "status": alert.status,
        "agent_event_id": alert.agent_event_id,
        "created_at": alert.created_at,
        "device_name": dev_name or "Unknown PC",
        "exam_name": exam.exam_name if exam else None,
        "student_roll_number": roll,
        "process_name": event.process_name if event else None,
        "pid": event.pid if event else None,
        "executable_path": event.executable_path if event else None,
        "event_type": event.event_type if event else None,
        "reason": event.reason if event else alert.message,
        "classification": event.classification if event else None,
        "ip_address": (event.ip_address if event else None) or (device.registered_ip if device else None),
    }


@router.get("", response_model=list[AlertReadDetailed])
def list_alerts(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    rows = (
        db.query(Alert, Device.device_name, Device.registered_ip, Exam.exam_name, Event)
        .outerjoin(Device, Alert.device_id == Device.device_id)
        .outerjoin(Exam, Alert.exam_id == Exam.exam_id)
        .outerjoin(Event, Alert.event_id == Event.event_id)
        .order_by(Alert.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    
    results = []
    for alert, dev_name, reg_ip, exam_name, event in rows:
        roll = event.student_roll_number if event and event.student_roll_number and event.student_roll_number != "UNKNOWN" else None
        results.append({
            "alert_id": alert.alert_id,
            "event_id": alert.event_id,
            "exam_id": alert.exam_id,
            "device_id": alert.device_id,
            "severity": alert.severity,
            "message": alert.message,
            "status": alert.status,
            "agent_event_id": alert.agent_event_id,
            "created_at": alert.created_at,
            "device_name": (event.device_name if event and event.device_name else None) or dev_name or "Unknown PC",
            "exam_name": exam_name,
            "student_roll_number": roll,
            "process_name": event.process_name if event else None,
            "pid": event.pid if event else None,
            "executable_path": event.executable_path if event else None,
            "event_type": event.event_type if event else None,
            "reason": event.reason if event else alert.message,
            "classification": event.classification if event else None,
            "ip_address": (event.ip_address if event else None) or reg_ip,
        })
    return results


@router.get("/{alert_id}", response_model=AlertReadDetailed)
def get_alert(alert_id: UUID, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return _enrich_alert(db, alert)


@router.post("", response_model=AlertRead, status_code=status.HTTP_201_CREATED)
def create_alert(payload: AlertCreate, db: Session = Depends(get_db)):
    data = _as_dict(payload)
    if data.get("alert_id") is None:
        data.pop("alert_id", None)
    alert = Alert(**data)
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.put("/{alert_id}", response_model=AlertRead)
def update_alert(alert_id: UUID, payload: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        
    old_status = alert.status
    for key, value in _as_dict(payload).items():
        setattr(alert, key, value)
    db.commit()
    db.refresh(alert)
    
    if old_status != alert.status and alert.status in ("acknowledged", "resolved"):
        from backend.models.audit_log import AuditLog
        db.add(AuditLog(
            action=f"ALERT_{alert.status.upper()}",
            entity_type="alert",
            entity_id=str(alert.alert_id),
            details={"previous_status": old_status, "new_status": alert.status}
        ))
        db.commit()
        
    return alert


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alert(alert_id: UUID, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
