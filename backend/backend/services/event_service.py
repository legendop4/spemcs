"""
Event ingestion and query service — Strict V1 Real-Time Enforcement.
No fallback auto-registrations or arbitrary exam matching.
"""

import logging
import uuid as uuid_mod
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.models.event import Event, Classification
from backend.models.alert import Alert
from backend.models.device import Device
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.session import ExamSession

logger = logging.getLogger(__name__)


def ingest_event(
    db: Session,
    event_id: str,
    device_name: str,
    event_type: str,
    process_name: str,
    process_id: int,
    timestamp_utc: str,
    student_roll_number: Optional[str] = None,
    executable_path: Optional[str] = None,
    reason: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> tuple[Event, Optional[Alert]]:
    """Strictly ingest a violation event from a registered agent.
    
    1. Validates strict UUID for event_id.
    2. Resolves registered device by device_name or hardware_uuid.
    3. Resolves assigned active exam and active session.
    4. Persists Event and creates Alert when appropriate.
    """
    # Strict UUID validation
    try:
        parsed_event_uuid = uuid_mod.UUID(str(event_id))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid event_id UUID format")

    # Check cache for active exam. If no active exam, discard immediately.
    from backend.websocket.manager import realtime_manager
    if not realtime_manager.get_active_exam_for_device(device_name):
        logger.info(f"No active exam for device {device_name}, ignoring event {event_id}")
        dummy_event = Event(
            event_id=parsed_event_uuid,
            device_name=device_name,
            event_type=event_type,
            process_name=process_name,
            pid=process_id,
            timestamp=datetime.utcnow(),
        )
        return dummy_event, None

    # Early discard check: if the event is not from WindowServer, we only allow real violation types
    # (like BLOCKED_PROCESS or AGENT_STOPPED) or unapproved/prohibited process events.
    if "windowserver" not in str(device_name).lower():
        proc_lower = (process_name or "").lower()
        # For remote lab PCs, we only look for remote desktop and AI assistant tools to prevent
        # background browser helper processes (Edge/Chrome/Firefox update/render processes) from flooding the DB.
        is_prohibited = any(kw in proc_lower for kw in [
            "dwagent", "dwagsvc", "dwrcs", "anydesk", "teamviewer", "rustdesk",
            "ultraviewer", "parsec", "splashtop", "ammyy", "supremo", "vnc", "screenconnect",
            "chatgpt", "claude", "codex", "copilot", "gemini", "discord", "telegram"
        ])
        
        # Discard background noise (allowed sessions, safe apps, standard process opens/closes)
        if event_type not in ("BLOCKED_PROCESS", "AGENT_STOPPED") and not is_prohibited:
            event = Event(
                event_id=parsed_event_uuid,
                device_name=device_name,
                event_type=event_type,
                process_name=process_name,
                pid=process_id,
                timestamp=datetime.utcnow(),
            )
            return event, None

    # Deduplication check
    existing = db.query(Event).filter(Event.event_id == parsed_event_uuid).first()
    if existing:
        logger.info(f"Duplicate event {event_id}, skipping")
        existing_alert = db.query(Alert).filter(Alert.event_id == existing.event_id).first()
        return existing, existing_alert
    
    # Resolve registered device strictly
    device = db.query(Device).filter(Device.device_name == device_name).first()
    if not device:
        device = db.query(Device).filter(Device.hardware_uuid == device_name).first()
    
    if not device:
        raise HTTPException(
            status_code=400,
            detail=f"Unregistered device '{device_name}'. Device must be registered before publishing events."
        )

    # Update device last seen
    device.last_seen = datetime.utcnow()
    device.status = "online"
    if ip_address:
        device.registered_ip = ip_address

    # Resolve active exam specifically assigned to THIS device
    exam = (
        db.query(Exam)
        .join(ExamDevice, ExamDevice.exam_id == Exam.exam_id)
        .filter(
            ExamDevice.device_id == device.device_id,
            Exam.status == ExamStatus.ACTIVE.value,
        )
        .first()
    )

    # Resolve active session for this device and exam
    session = None
    if exam:
        session = (
            db.query(ExamSession)
            .filter(
                ExamSession.device_id == device.device_id,
                ExamSession.exam_id == exam.exam_id,
                ExamSession.status == "active",
            )
            .first()
        )
    
    # Determine student roll number
    effective_roll = (
        student_roll_number or 
        (session.student_roll_number if session else None) or 
        "N/A"
    )

    # Parse timestamp
    try:
        ts = datetime.fromisoformat(timestamp_utc.replace("Z", "+00:00"))
        ts = ts.replace(tzinfo=None)
    except (ValueError, AttributeError):
        ts = datetime.utcnow()

    # Determine classification
    classification = Classification.UNAUTHORIZED.value
    if event_type in ("SESSION_STARTED", "SESSION_HEARTBEAT"):
        classification = Classification.ALLOWED.value

    # Create Event
    event = Event(
        event_id=parsed_event_uuid,
        session_id=session.session_id if session else None,
        device_id=device.device_id,
        device_name=device.device_name,
        ip_address=ip_address or device.registered_ip or "127.0.0.1",
        student_roll_number=effective_roll,
        event_type=event_type,
        timestamp=ts,
        process_name=process_name,
        pid=process_id,
        executable_path=executable_path,
        classification=classification,
        reason=reason or f"Event: {event_type}",
        resolution_status="active",
    )
    db.add(event)
    db.flush()

    # Determine alert generation
    alert = None
    if classification == Classification.UNAUTHORIZED.value:
        severity = "medium"
        proc_lower = (process_name or "").lower()
        reason_lower = (reason or "").lower()

        if any(kw in proc_lower or kw in reason_lower for kw in [
            "dwagent", "dwagsvc", "dwrcs", "anydesk", "teamviewer", "rustdesk",
            "ultraviewer", "parsec", "splashtop", "ammyy", "supremo", "vnc", "screenconnect"
        ]):
            severity = "critical"
        elif any(kw in proc_lower or kw in reason_lower for kw in [
            "chatgpt", "claude", "codex", "copilot", "gemini", "discord", "telegram"
        ]):
            severity = "high"
        elif event_type in ("AGENT_STOPPED", "DEVICE_DISCONNECTED"):
            severity = "high"

        alert = Alert(
            event_id=event.event_id,
            exam_id=exam.exam_id if exam else None,
            device_id=device.device_id,
            severity=severity,
            message=f"{severity.upper()}: {reason or process_name}",
            status="open",
        )
        db.add(alert)
        db.flush()

    db.commit()
    db.refresh(event)
    if alert:
        db.refresh(alert)

    logger.info(f"Strict event ingested: {event.event_id} ({event_type}) for device {device.device_name}")
    return event, alert


def get_events_timeline(
    db: Session,
    exam_id: Optional[UUID] = None,
    device_id: Optional[UUID] = None,
    limit: int = 200,
) -> list[Event]:
    """Retrieve chronological event timeline filtered strictly by exam or device."""
    query = db.query(Event)

    if exam_id:
        query = query.join(ExamSession, Event.session_id == ExamSession.session_id).filter(
            ExamSession.exam_id == exam_id
        )
    if device_id:
        query = query.filter(Event.device_id == device_id)

    return query.order_by(Event.timestamp.desc()).limit(limit).all()
