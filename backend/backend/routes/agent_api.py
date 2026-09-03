"""Agent integration API — REST endpoints for device agents to register,
start sessions, verify students, and push violation events.

WebSocket endpoints are in backend/websocket/agent_ws.py and dashboard_ws.py.
This module provides REST endpoints used by endpoint agent HTTP adapters.
"""

import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.models.device import Device
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.session import ExamSession
from backend.services import device_service, session_service, event_service
from backend.services import realtime_service
from backend.websocket.manager import realtime_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["agent-integration"])


# --- Request Schemas ---

class DeviceRegisterReq(BaseModel):
    deviceName: str
    ipAddress: Optional[str] = "127.0.0.1"
    hardwareUuid: Optional[str] = None
    labId: Optional[str] = None
    pcNumber: Optional[str] = None
    hostname: Optional[str] = None
    enrollmentKey: Optional[str] = None


class SessionStartReq(BaseModel):
    sessionId: Optional[str] = None
    hardwareUuid: Optional[str] = None
    deviceName: Optional[str] = None
    approvedBrowser: str = "chrome"


class StudentVerifyReq(BaseModel):
    sessionId: str
    rollNumber: str


class ViolationEventReq(BaseModel):
    eventId: str
    deviceName: str
    studentRollNumber: Optional[str] = None
    eventType: str
    processId: int
    processName: str
    timestampUtc: str
    executablePath: Optional[str] = None
    reason: Optional[str] = None


# --- Endpoints ---

@router.post("/devices/register")
async def register_device(
    req: DeviceRegisterReq,
    request: Request,
    db: Session = Depends(get_db),
):
    """Register or update a device. Validates bootstrap enrollment key and issues cryptographically authenticated device_token."""
    from backend.app.config import settings
    from backend.services.auth_service import create_device_token
    import hmac

    # Verify bootstrap enrollment key
    provided_key = req.enrollmentKey or request.headers.get("X-Enrollment-Key")
    if settings.ENROLLMENT_BOOTSTRAP_KEY:
        if not provided_key or not hmac.compare_digest(
            provided_key.encode("utf-8"),
            settings.ENROLLMENT_BOOTSTRAP_KEY.encode("utf-8")
        ):
            logger.warning("Device registration rejected: missing or invalid bootstrap enrollment key")
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing enrollment bootstrap key",
            )

    hw_uuid = req.hardwareUuid or req.deviceName
    
    try:
        device = device_service.register_device(
            db=db,
            hardware_uuid=hw_uuid,
            device_name=req.deviceName,
            ip_address=req.ipAddress,
            lab_id=req.labId,
            pc_number=req.pcNumber,
            hostname=req.hostname,
        )
    except ValueError as val_err:
        raise HTTPException(status_code=409, detail=str(val_err))
    except Exception as exc:
        logger.exception("Failed to register device")
        raise HTTPException(status_code=500, detail="Registration failed")
    
    # Issue cryptographically authenticated device token
    device_token = create_device_token(hardware_uuid=device.hardware_uuid)

    # Cache device ID mapping in memory
    dev_id_str = str(device.device_id)
    if device.device_name:
        realtime_manager.register_device_id(device.device_name, dev_id_str)
    if device.hardware_uuid:
        realtime_manager.register_device_id(device.hardware_uuid, dev_id_str)
        
    # Notify dashboard of device coming online
    await realtime_manager.broadcast_to_dashboard({
        "type": "DEVICE_STATUS_CHANGE",
        "payload": {
            "device_id": str(device.device_id),
            "hardware_uuid": device.hardware_uuid,
            "device_name": device.device_name,
            "status": "online",
            "building_name": device.building_name,
            "lab_name": device.lab_name,
            "pc_number": device.pc_number,
            "timestamp": datetime.utcnow().isoformat(),
        }
    })
    
    from backend.models.audit_log import AuditLog
    # Avoid duplicate logs if device was just updating presence
    if not device.last_seen or (datetime.utcnow() - device.created_at).total_seconds() < 10:
        db.add(AuditLog(
            action="DEVICE_REGISTERED",
            entity_type="device",
            entity_id=str(device.device_id),
            details={"device_name": device.device_name, "source": "agent"}
        ))
        db.commit()
    
    return {
        "deviceId": str(device.device_id),
        "deviceName": device.device_name,
        "hardwareUuid": device.hardware_uuid,
        "deviceToken": device_token,
        "device_token": device_token,
        "buildingName": device.building_name,
        "labName": device.lab_name,
        "pcNumber": device.pc_number,
        "ipAddress": device.registered_ip,
        "registeredAtUtc": device.created_at.isoformat() if device.created_at else datetime.utcnow().isoformat(),
        "registered": True,
    }


@router.post("/sessions/start")
async def start_session(req: SessionStartReq, db: Session = Depends(get_db)):
    """Start a real exam session. Validates registered device and assigned active exam."""
    device = None
    if req.hardwareUuid:
        device = device_service.get_device_by_uuid(db, req.hardwareUuid)
    if not device and req.deviceName:
        device = device_service.get_device_by_name(db, req.deviceName)
    if not device:
        raise HTTPException(status_code=404, detail="Device must be registered before starting a session")
    
    # Find active exam specifically assigned to this device
    from backend.services.exam_service import get_active_exam_for_device
    exam = get_active_exam_for_device(db, device.device_id)
    if not exam:
        raise HTTPException(status_code=404, detail="No active exam is assigned to this device")
    
    # Resolve requested session ID
    session_uuid = None
    if req.sessionId:
        try:
            session_uuid = uuid.UUID(req.sessionId)
        except Exception:
            session_uuid = None

    # Create or retrieve real session
    try:
        session = session_service.start_session(
            db=db,
            device_id=device.device_id,
            exam_id=exam.exam_id,
            session_id=session_uuid,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return {
        "status": "SessionStarted",
        "sessionId": str(session.session_id),
        "examId": str(exam.exam_id),
        "examName": exam.exam_name,
        "allowedDomain": exam.exam_link or "",
    }


@router.post("/sessions/verify-student")
async def verify_student(req: StudentVerifyReq, db: Session = Depends(get_db)):
    """Validate student roll number and bind to session."""
    session_uuid = None
    try:
        session_uuid = uuid.UUID(req.sessionId)
    except Exception:
        pass
    
    session = None
    if session_uuid:
        session = db.query(ExamSession).filter(ExamSession.session_id == session_uuid).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Active exam session not found")
    
    roll = req.rollNumber.strip()
    if not roll:
        raise HTTPException(status_code=400, detail="Student roll number cannot be empty")
    
    # Update session with student info
    try:
        session = session_service.verify_student(
            db=db,
            session_id=session.session_id,
            roll_number=roll,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Notify proctors via exam room and global dashboard
    exam_id_str = str(session.exam_id)
    session_payload = {
        "session_id": str(session.session_id),
        "exam_id": exam_id_str,
        "device_id": str(session.device_id),
        "student_roll_number": session.student_roll_number,
        "started_at": session.started_at.isoformat() if session.started_at else None,
    }
    await realtime_service.broadcast_session_started(
        exam_id=exam_id_str,
        session_data=session_payload,
    )
    await realtime_manager.broadcast_to_dashboard({
        "type": "SESSION_STARTED",
        "payload": session_payload,
    })
    
    return {
        "valid": True,
        "studentName": f"Student {roll}",
        "message": "Verification successful",
        "sessionId": str(session.session_id),
    }


@router.post("/events")
async def receive_event(event_req: ViolationEventReq, db: Session = Depends(get_db)):
    """Strictly ingest a violation event from an endpoint agent."""
    try:
        new_event, new_alert = event_service.ingest_event(
            db=db,
            event_id=event_req.eventId,
            device_name=event_req.deviceName,
            event_type=event_req.eventType,
            process_name=event_req.processName,
            process_id=event_req.processId,
            timestamp_utc=event_req.timestampUtc,
            student_roll_number=event_req.studentRollNumber,
            executable_path=event_req.executablePath,
            reason=event_req.reason,
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        logger.exception("Event ingestion failed")
        raise HTTPException(status_code=500, detail="Event ingestion failed")
    
    # Determine alert broadcast data
    alert_data = None
    if new_alert:
        exam_id_str = str(new_alert.exam_id) if new_alert.exam_id else ""
        alert_data = {
            "alert_id": str(new_alert.alert_id),
            "event_id": str(new_event.event_id),
            "exam_id": exam_id_str,
            "device_id": str(new_event.device_id),
            "device_name": event_req.deviceName,
            "severity": new_alert.severity,
            "message": new_alert.message,
            "status": new_alert.status,
            "event_type": event_req.eventType,
            "process_name": event_req.processName,
            "student_roll_number": event_req.studentRollNumber,
            "timestamp": event_req.timestampUtc,
            "created_at": new_alert.created_at.isoformat() if new_alert.created_at else None,
        }
    else:
        # For non-prohibited background events, we send them as low-severity log alerts
        # so they stream in real-time to the dashboard without DB writes
        action = "opened" if event_req.eventType == "APPLICATION_OPENED" else "closed"
        message = f"LOG: {event_req.processName} {action}"
        
        # Look up active exam and device ID from in-memory cache to avoid database queries
        exam_id_str = realtime_manager.get_active_exam_for_device(event_req.deviceName) or ""
        device_id_str = realtime_manager.get_device_id(event_req.deviceName) or ""
        
        alert_data = {
            "alert_id": str(uuid.uuid4()),
            "event_id": str(new_event.event_id) if new_event else str(uuid.uuid4()),
            "exam_id": exam_id_str,
            "device_id": device_id_str,
            "device_name": event_req.deviceName,
            "severity": "low",
            "message": message,
            "status": "open",
            "event_type": event_req.eventType,
            "process_name": event_req.processName,
            "student_roll_number": event_req.studentRollNumber,
            "timestamp": event_req.timestampUtc,
            "created_at": datetime.utcnow().isoformat(),
        }

    # Broadcast alert to proctor dashboards via WebSocket only if there is an active exam
    if alert_data:
        exam_id_str = alert_data.get("exam_id", "")
        if exam_id_str:
            await realtime_service.broadcast_alert_to_exam(
                exam_id=exam_id_str,
                alert_data=alert_data,
            )
            await realtime_manager.broadcast_to_dashboard({
                "type": "VIOLATION_ALERT",
                "payload": alert_data,
            })
    
    return {
        "status": "Ingested",
        "eventId": str(new_event.event_id),
        "alertId": str(new_alert.alert_id) if new_alert else None,
    }
