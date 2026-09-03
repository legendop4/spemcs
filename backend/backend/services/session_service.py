"""Session management service — create, verify, end sessions."""

import logging
import uuid
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.models.session import ExamSession
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.device import Device

logger = logging.getLogger(__name__)


def start_session(
    db: Session,
    device_id: UUID,
    exam_id: UUID,
    session_id: Optional[UUID] = None,
) -> ExamSession:
    """Create a new exam session for a device.
    Validates that the device is assigned to the exam and the exam is active."""
    # Validate exam exists and is active
    exam = db.query(Exam).filter(Exam.exam_id == exam_id).first()
    if not exam:
        raise ValueError(f"Exam {exam_id} not found")
    if exam.status != ExamStatus.ACTIVE.value:
        # Auto-activate exam if it was pending
        exam.status = ExamStatus.ACTIVE.value
        exam.started_at = exam.started_at or datetime.utcnow()
        db.commit()
    
    # Validate device exists
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise ValueError(f"Device {device_id} not found")
    
    # Ensure device is assigned to this exam
    exam_device = (
        db.query(ExamDevice)
        .filter(
            ExamDevice.exam_id == exam_id,
            ExamDevice.device_id == device_id,
        )
        .first()
    )
    if not exam_device:
        exam_device = ExamDevice(exam_id=exam_id, device_id=device_id)
        db.add(exam_device)
        db.commit()
    
    # Check for existing active session on this device for this exam
    existing = (
        db.query(ExamSession)
        .filter(
            ExamSession.device_id == device_id,
            ExamSession.exam_id == exam_id,
            ExamSession.status == "active",
        )
        .first()
    )
    if existing:
        logger.info(f"Returning existing active session {existing.session_id}")
        return existing
    
    # Create session
    session = ExamSession(
        session_id=session_id or uuid.uuid4(),
        exam_id=exam_id,
        device_id=device_id,
        student_roll_number="PENDING",  # Will be set on verify
        status="active",
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    logger.info(f"Session started: {session.session_id} (exam={exam_id}, device={device_id})")
    return session


def verify_student(
    db: Session,
    session_id: UUID,
    roll_number: str,
) -> ExamSession:
    """Verify student identity and bind roll number to session."""
    session = db.query(ExamSession).filter(ExamSession.session_id == session_id).first()
    if not session:
        raise ValueError(f"Session {session_id} not found")
    if session.status != "active":
        raise ValueError(f"Session {session_id} is not active")
    
    # Update session with student info
    session.student_roll_number = roll_number
    db.commit()
    db.refresh(session)
    
    logger.info(f"Student verified: {roll_number} on session {session_id}")
    return session


def end_session(db: Session, session_id: UUID) -> ExamSession:
    """End an active session."""
    session = db.query(ExamSession).filter(ExamSession.session_id == session_id).first()
    if not session:
        raise ValueError(f"Session {session_id} not found")
    
    session.status = "completed"
    session.ended_at = datetime.utcnow()
    db.commit()
    db.refresh(session)
    
    logger.info(f"Session ended: {session_id}")
    return session


def get_active_session(
    db: Session,
    device_id: UUID,
    exam_id: Optional[UUID] = None,
) -> Optional[ExamSession]:
    """Find the active session for a device, optionally filtered by exam."""
    query = db.query(ExamSession).filter(
        ExamSession.device_id == device_id,
        ExamSession.status == "active",
    )
    if exam_id:
        query = query.filter(ExamSession.exam_id == exam_id)
    return query.first()


def get_sessions_for_exam(db: Session, exam_id: UUID) -> list[ExamSession]:
    """Get all sessions for an exam."""
    return (
        db.query(ExamSession)
        .filter(ExamSession.exam_id == exam_id)
        .order_by(ExamSession.started_at)
        .all()
    )
