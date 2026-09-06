"""Exam CRUD and lifecycle management endpoints."""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status, BackgroundTasks
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.dependencies import require_staff
from backend.models.exam import Exam, ExamDevice
from backend.models.alert import Alert
from backend.models.session import ExamSession
from backend.schemas.exam import ExamCreate, ExamRead, ExamUpdate
from backend.services import enforcement_readiness, exam_service, realtime_service
from backend.services.auth_service import require_role

logger = logging.getLogger(__name__)
# The CRUD routes below carry their own per-route role gates and always did. The four
# sub-resource reads (/devices, /sessions, /alerts, /timeline) did not, so an anonymous caller who
# knew or guessed an exam id could read that exam's candidate list, session records, violation
# alerts and full event timeline while every route beside them was authenticated. A router-level
# floor rather than four more decorators, so the next sub-resource added here inherits it instead
# of repeating the omission. Per-route require_admin dependencies still apply on top: this is a
# minimum, not a ceiling.
router = APIRouter(
    prefix="/api/exams",
    tags=["exams"],
    dependencies=[Depends(require_staff)],
)


def _as_dict(model: Any) -> dict:
    return model.model_dump(exclude_unset=True) if hasattr(model, "model_dump") else model.dict(exclude_unset=True)


def _enrich_exam(db: Session, exam: Exam) -> dict:
    """Add computed counts to exam response."""
    device_count = db.query(ExamDevice).filter(ExamDevice.exam_id == exam.exam_id).count()
    alert_count = db.query(Alert).filter(Alert.exam_id == exam.exam_id).count()
    session_count = db.query(ExamSession).filter(ExamSession.exam_id == exam.exam_id).count()
    
    data = {
        "exam_id": exam.exam_id,
        "exam_name": exam.exam_name,
        "exam_link": exam.exam_link,
        "approved_browser": exam.approved_browser,
        "status": exam.status,
        "started_at": (exam.started_at.isoformat() + "Z") if exam.started_at else None,
        "ended_at": (exam.ended_at.isoformat() + "Z") if exam.ended_at else None,
        "created_at": (exam.created_at.isoformat() + "Z") if exam.created_at else None,
        "device_count": device_count,
        "alert_count": alert_count,
        "session_count": session_count,
        "network_enforcement": getattr(exam, "network_enforcement", False),
        "vendor_profile_id": str(exam.vendor_profile_id) if getattr(exam, "vendor_profile_id", None) else None,
    }
    return data


@router.get("")
def list_exams(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    exams = db.query(Exam).order_by(Exam.created_at.desc()).offset(skip).limit(limit).all()
    return [_enrich_exam(db, e) for e in exams]


@router.get("/{exam_id}")
def get_exam(
    exam_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    exam = db.get(Exam, exam_id)
    if exam is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")
    return _enrich_exam(db, exam)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_exam(
    payload: ExamCreate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    """Create an exam with optional device assignments."""
    exam = exam_service.create_exam(
        db=db,
        exam_name=payload.exam_name,
        exam_link=payload.exam_link,
        approved_browser=payload.approved_browser,
        device_ids=payload.device_ids,
        network_enforcement=payload.network_enforcement,
        vendor_profile_id=payload.vendor_profile_id,
    )
    return _enrich_exam(db, exam)


@router.put("/{exam_id}")
def update_exam(
    exam_id: UUID,
    payload: ExamUpdate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    exam = db.get(Exam, exam_id)
    if exam is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")
    for key, value in _as_dict(payload).items():
        setattr(exam, key, value)
    db.commit()
    db.refresh(exam)
    return _enrich_exam(db, exam)


@router.delete("/{exam_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_exam(
    exam_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    exam = db.get(Exam, exam_id)
    if exam is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")
    db.delete(exam)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Exam Lifecycle Endpoints ---

@router.get("/{exam_id}/enforcement-readiness")
def get_exam_enforcement_readiness(
    exam_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Whether this exam may be activated, and what is stopping it if not.

    The same evaluation the activate endpoint refuses on, exposed as a read so an operator can see
    the reason before pressing Launch instead of discovering it in a 409.
    """
    exam = db.get(Exam, exam_id)
    if exam is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")
    readiness = enforcement_readiness.evaluate_exam_readiness(db, exam)
    payload = readiness.to_dict()
    payload["unarmed_devices"] = enforcement_readiness.describe_unarmed_devices(db, readiness)
    return payload


@router.post("/{exam_id}/activate")
async def activate_exam(
    exam_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Activate an exam and send LAUNCH_EXAM_MODE to assigned devices.

    For a network-enforcement exam the lockdown precondition is checked HERE, on the server,
    before anything is written. It used to live entirely in the browser
    (`ExamShieldPage.tsx::handleActivate`), which meant a direct POST with any staff token produced
    an ACTIVE enforcement exam with no policy at all, and meant the front-end's own distribution
    loop could fail on every device and still reach this endpoint, which would report "activated".
    A refusal is a 409 and leaves the exam PENDING - nothing is half-started.
    """
    exam = db.get(Exam, exam_id)
    if exam is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")

    readiness = enforcement_readiness.evaluate_exam_readiness(db, exam)
    if not readiness.ready:
        detail = readiness.to_dict()
        detail["unarmed_devices"] = enforcement_readiness.describe_unarmed_devices(db, readiness)
        detail["message"] = (
            "This exam enforces a network lockdown and is not ready to activate: "
            + " ".join(p.message for p in readiness.problems)
        )
        logger.warning(
            "Refused activation of enforcement exam %s: %s",
            exam_id, ", ".join(p.code for p in readiness.problems),
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

    for warning in readiness.warnings:
        logger.warning("Activating exam %s with a caveat (%s): %s",
                       exam_id, warning.code, warning.message)

    # Only armed devices are launched and marked MONITORING. For a non-enforcement exam the
    # readiness result marks every assigned device armed, so this is the pre-existing behaviour.
    try:
        exam, hardware_uuids = exam_service.activate_exam(
            db, exam_id, armed_device_ids=readiness.armed_device_ids
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Update cache
    from backend.websocket.manager import realtime_manager
    realtime_manager.set_exam_active(str(exam_id), hardware_uuids)

    # Send WebSocket commands to devices
    results = await realtime_service.send_exam_launch(db, exam, hardware_uuids)

    # Notify dashboards
    await realtime_service.broadcast_exam_status(
        exam_id=str(exam_id),
        status="active",
        exam_name=exam.exam_name,
    )

    online = sum(1 for v in results.values() if v)
    unarmed = enforcement_readiness.describe_unarmed_devices(db, readiness)

    from backend.models.audit_log import AuditLog
    db.add(AuditLog(
        action="EXAM_ACTIVATED",
        entity_type="exam",
        entity_id=str(exam.exam_id),
        details={
            "exam_name": exam.exam_name,
            "devices_targeted": len(hardware_uuids),
            "devices_reached": online,
            "network_enforcement": readiness.enforcement_required,
            "policy_id": str(readiness.policy_id) if readiness.policy_id else None,
            "devices_not_enforcing": len(unarmed),
        }
    ))
    db.commit()
    return {
        "status": "activated",
        "exam_id": str(exam.exam_id),
        "exam_name": exam.exam_name,
        "devices_targeted": len(hardware_uuids),
        "devices_reached": online,
        "results": results,
        "network_enforcement": readiness.enforcement_required,
        "policy_id": str(readiness.policy_id) if readiness.policy_id else None,
        # Named, not counted: an operator who launches 40 seats and gets 38 needs to know which
        # two were left out, and those two are NOT under exam control.
        "devices_not_enforcing": unarmed,
        "warnings": [w.to_dict() for w in readiness.warnings],
    }


@router.post("/{exam_id}/deactivate")
async def deactivate_exam(
    exam_id: UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Deactivate an exam and send STOP_EXAM_MODE to devices."""
    try:
        exam, hardware_uuids = exam_service.deactivate_exam(db, exam_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Update cache
    from backend.websocket.manager import realtime_manager
    realtime_manager.set_exam_inactive(str(exam_id))
    
    # Send stop commands in the background so the HTTP response returns instantly
    background_tasks.add_task(realtime_service.send_exam_stop, exam, hardware_uuids)
    
    # Notify dashboards
    await realtime_service.broadcast_exam_status(
        exam_id=str(exam_id),
        status="stopped",
        exam_name=exam.exam_name,
    )
    
    from backend.models.audit_log import AuditLog
    db.add(AuditLog(
        action="EXAM_DEACTIVATED",
        entity_type="exam",
        entity_id=str(exam.exam_id),
        details={"exam_name": exam.exam_name, "devices_targeted": len(hardware_uuids)}
    ))
    db.commit()
    
    return {
        "status": "deactivated",
        "exam_id": str(exam.exam_id),
        "exam_name": exam.exam_name,
        "devices_targeted": len(hardware_uuids),
    }


@router.get("/{exam_id}/devices")
def get_exam_devices(exam_id: UUID, db: Session = Depends(get_db)):
    """Get all devices assigned to an exam with their status."""
    exam = db.get(Exam, exam_id)
    if exam is None:
        raise HTTPException(status_code=404, detail="Exam not found")
    return exam_service.get_devices_for_exam(db, exam_id)


@router.get("/{exam_id}/sessions")
def get_exam_sessions(exam_id: UUID, db: Session = Depends(get_db)):
    """Get all sessions for an exam."""
    from backend.services.session_service import get_sessions_for_exam
    sessions = get_sessions_for_exam(db, exam_id)
    return [
        {
            "session_id": str(s.session_id),
            "exam_id": str(s.exam_id),
            "device_id": str(s.device_id),
            "student_roll_number": s.student_roll_number,
            "status": s.status,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "ended_at": s.ended_at.isoformat() if s.ended_at else None,
        }
        for s in sessions
    ]


@router.get("/{exam_id}/alerts")
def get_exam_alerts(exam_id: UUID, db: Session = Depends(get_db)):
    """Get all alerts for an exam."""
    from backend.services.alert_service import get_alerts_for_exam
    return get_alerts_for_exam(db, exam_id)


@router.get("/{exam_id}/timeline")
def get_exam_timeline(exam_id: UUID, limit: int = 200, db: Session = Depends(get_db)):
    """Get chronological event timeline for an exam."""
    from backend.services.event_service import get_events_timeline
    events = get_events_timeline(db, exam_id=exam_id, limit=limit)
    return [
        {
            "event_id": str(e.event_id),
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_type": e.event_type,
            "device_name": e.device_name,
            "student_roll_number": e.student_roll_number,
            "process_name": e.process_name,
            "classification": e.classification,
            "reason": e.reason,
        }
        for e in events
    ]
