"""Exam CRUD and lifecycle management endpoints."""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status, BackgroundTasks
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.dependencies import require_staff
from backend.models.exam import Exam, ExamDevice, ExamStatus, ExamDeviceStatus
from backend.models.device import Device
from backend.models.policy import DevicePolicyState
from backend.models.alert import Alert
from backend.models.session import ExamSession
from backend.schemas.exam import ExamCreate, ExamRead, ExamUpdate, ExamAssignDevices
from backend.services import (
    device_policy_state_service as dps,
    enforcement_readiness,
    exam_service,
    policy_service,
    realtime_service,
)
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


def _enrich_exam(
    db: Session,
    exam: Exam,
    device_count: int | None = None,
    alert_count: int | None = None,
    session_count: int | None = None,
) -> dict:
    """Add computed counts to exam response."""
    if device_count is None:
        device_count = db.query(ExamDevice).filter(ExamDevice.exam_id == exam.exam_id).count()
    if alert_count is None:
        alert_count = db.query(Alert).filter(Alert.exam_id == exam.exam_id).count()
    if session_count is None:
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
    if not exams:
        return []
    exam_ids = [e.exam_id for e in exams]
    device_counts = dict(
        db.query(ExamDevice.exam_id, func.count(ExamDevice.id))
        .filter(ExamDevice.exam_id.in_(exam_ids))
        .group_by(ExamDevice.exam_id)
        .all()
    )
    alert_counts = dict(
        db.query(Alert.exam_id, func.count(Alert.alert_id))
        .filter(Alert.exam_id.in_(exam_ids))
        .group_by(Alert.exam_id)
        .all()
    )
    session_counts = dict(
        db.query(ExamSession.exam_id, func.count(ExamSession.session_id))
        .filter(ExamSession.exam_id.in_(exam_ids))
        .group_by(ExamSession.exam_id)
        .all()
    )
    return [
        _enrich_exam(
            db,
            e,
            device_count=device_counts.get(e.exam_id, 0),
            alert_count=alert_counts.get(e.exam_id, 0),
            session_count=session_counts.get(e.exam_id, 0),
        )
        for e in exams
    ]


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
async def create_exam(
    payload: ExamCreate,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin"])),
):
    """Create an exam with optional device assignments.
    
    If network enforcement is enabled with a vendor profile, automatically compiles,
    signs, and distributes the policy to online assigned workstations to complete
    the activation readiness workflow without manual intervention.
    """
    exam = exam_service.create_exam(
        db=db,
        exam_name=payload.exam_name,
        exam_link=payload.exam_link,
        approved_browser=payload.approved_browser,
        device_ids=payload.device_ids,
        network_enforcement=payload.network_enforcement,
        vendor_profile_id=payload.vendor_profile_id,
    )

    if exam.network_enforcement and exam.vendor_profile_id:
        try:
            from datetime import datetime, timedelta, timezone
            from backend.app.config import settings
            from backend.models.device import Device
            from backend.services import policy_service
            from backend.services.signing_key_manager import get_signing_key_manager
            from backend.websocket.manager import realtime_manager
            from backend.services.canonical_json import canonicalize

            now = datetime.now(timezone.utc)
            signer = get_signing_key_manager().active_signer()
            policy = policy_service.compile_and_persist_exam_policy(
                db=db,
                exam_id=exam.exam_id,
                version=1,
                management_server=settings.get_management_server_dict(),
                not_before=now - timedelta(minutes=5),
                expires_at=now + timedelta(hours=8),
                signer=signer,
                vendor_profile_id=exam.vendor_profile_id,
                approved_browser=exam.approved_browser,
            )

            # Initialize device policy states for assigned devices as PENDING distribution
            if payload.device_ids:
                assigned_devs = db.query(Device).filter(Device.device_id.in_(payload.device_ids)).all()
                for dev in assigned_devs:
                    dps.record_state(
                        db,
                        exam_id=exam.exam_id,
                        device_id=dev.device_id,
                        policy_id=policy.policy_id,
                        status=dps.STATUS_PENDING,
                        last_error="Pending policy distribution",
                    )
        except Exception as e:
            logger.warning("Automatic policy compilation/distribution for exam %s deferred: %s", exam.exam_id, e)

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
    from backend.models.report import Report
    from backend.models.policy import DevicePolicyState, NetworkPolicy
    from backend.models.session import ExamSession
    from backend.models.alert import Alert
    from backend.models.exam import ExamDevice
    db.query(Report).filter(Report.exam_id == exam_id).delete()
    db.query(DevicePolicyState).filter(DevicePolicyState.exam_id == exam_id).delete()
    db.query(NetworkPolicy).filter(NetworkPolicy.exam_id == exam_id).delete()
    db.query(Alert).filter(Alert.exam_id == exam_id).delete()
    db.query(ExamSession).filter(ExamSession.exam_id == exam_id).delete()
    db.query(ExamDevice).filter(ExamDevice.exam_id == exam_id).delete()
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
    if not readiness.ready and bool(getattr(exam, "network_enforcement", False)):
        states = dps.get_states_for_exam(db, exam_id)
        has_applying = any(s.status == dps.STATUS_APPLYING for s in states)
        if has_applying:
            import asyncio
            for _ in range(10):
                await asyncio.sleep(0.3)
                db.expire_all()
                readiness = enforcement_readiness.evaluate_exam_readiness(db, exam)
                if readiness.ready:
                    break

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


@router.put("/{exam_id}/devices")
def update_exam_devices(
    exam_id: UUID,
    payload: ExamAssignDevices,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Update assigned devices for a pending exam.
    
    Strictly restricted to PENDING exams. Validates all target device IDs,
    transactionally reconciles exam_devices rows, safely removes policy states
    for unassigned devices, and never deletes the Device records themselves.
    """
    exam = db.get(Exam, exam_id)
    if exam is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")
    if exam.status != ExamStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot modify assigned devices: exam is '{exam.status}', but must be 'pending'",
        )

    target_ids = set(payload.device_ids)
    if target_ids:
        existing_devices = db.query(Device).filter(Device.device_id.in_(target_ids)).all()
        found_ids = {d.device_id for d in existing_devices}
        missing_ids = target_ids - found_ids
        if missing_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid device IDs: {[str(i) for i in missing_ids]} do not exist",
            )

    current_rows = db.query(ExamDevice).filter(ExamDevice.exam_id == exam_id).all()
    current_ids = {row.device_id for row in current_rows if row.device_id}

    to_remove = current_ids - target_ids
    to_add = target_ids - current_ids

    if to_remove:
        db.query(ExamDevice).filter(
            ExamDevice.exam_id == exam_id,
            ExamDevice.device_id.in_(to_remove),
        ).delete(synchronize_session=False)
        db.query(DevicePolicyState).filter(
            DevicePolicyState.exam_id == exam_id,
            DevicePolicyState.device_id.in_(to_remove),
        ).delete(synchronize_session=False)

    policy = policy_service.get_latest_exam_policy(db, exam_id)
    for dev_id in to_add:
        db.add(ExamDevice(
            exam_id=exam_id,
            device_id=dev_id,
            status=ExamDeviceStatus.PENDING.value,
        ))
        if policy:
            dps.record_state(
                db,
                exam_id=exam_id,
                device_id=dev_id,
                policy_id=policy.policy_id,
                status=dps.STATUS_PENDING,
                last_error="Pending policy distribution",
            )

    db.commit()
    logger.info(
        "Exam %s devices updated: %d assigned (+%d, -%d)",
        exam_id, len(target_ids), len(to_add), len(to_remove),
    )
    return exam_service.get_devices_for_exam(db, exam_id)


@router.delete("/{exam_id}/devices/{device_id}", status_code=status.HTTP_200_OK)
def remove_exam_device(
    exam_id: UUID,
    device_id: UUID,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "proctor"])),
):
    """Unassign a device from a pending exam.
    
    Removes the exam_devices assignment and cleans any associated device_policy_states
    record safely without deleting the Device itself.
    """
    exam = db.get(Exam, exam_id)
    if exam is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Exam not found")
    if exam.status != ExamStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot remove device: exam is '{exam.status}', but must be 'pending'",
        )

    assignment = db.query(ExamDevice).filter(
        ExamDevice.exam_id == exam_id,
        ExamDevice.device_id == device_id,
    ).first()
    if not assignment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{device_id}' is not assigned to exam '{exam_id}'",
        )

    db.delete(assignment)
    db.query(DevicePolicyState).filter(
        DevicePolicyState.exam_id == exam_id,
        DevicePolicyState.device_id == device_id,
    ).delete(synchronize_session=False)
    db.commit()

    logger.info("Unassigned device %s from exam %s", device_id, exam_id)
    return {
        "status": "unassigned",
        "exam_id": str(exam_id),
        "device_id": str(device_id),
    }



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
