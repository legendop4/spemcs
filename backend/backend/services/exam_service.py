"""Exam lifecycle service — creation, activation, deactivation."""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session

from backend.models.exam import Exam, ExamDevice, ExamStatus, ExamDeviceStatus
from backend.models.session import ExamSession
from backend.models.device import Device

logger = logging.getLogger(__name__)


def create_exam(
    db: Session,
    exam_name: str,
    exam_link: Optional[str] = None,
    approved_browser: str = "chrome",
    device_ids: Optional[list[UUID]] = None,
) -> Exam:
    """Create an exam and optionally assign devices."""
    exam = Exam(
        exam_name=exam_name,
        exam_link=exam_link,
        approved_browser=approved_browser,
        status=ExamStatus.PENDING.value,
    )
    db.add(exam)
    db.flush()  # Get exam_id before adding devices
    
    if device_ids:
        for device_id in device_ids:
            exam_device = ExamDevice(
                exam_id=exam.exam_id,
                device_id=device_id,
                status=ExamDeviceStatus.PENDING.value,
            )
            db.add(exam_device)
    
    db.commit()
    db.refresh(exam)
    logger.info(f"Exam created: {exam_name} (ID: {exam.exam_id})")
    return exam


def activate_exam(db: Session, exam_id: UUID) -> tuple[Exam, list[str]]:
    """Activate an exam. Returns (exam, list_of_device_hardware_uuids).
    The caller is responsible for sending WebSocket commands."""
    exam = db.query(Exam).filter(Exam.exam_id == exam_id).first()
    if not exam:
        raise ValueError(f"Exam {exam_id} not found")
    if exam.status == ExamStatus.ACTIVE.value:
        raise ValueError(f"Exam {exam_id} is already active")
    
    exam.status = ExamStatus.ACTIVE.value
    exam.started_at = datetime.utcnow()
    
    # Get assigned devices with their hardware UUIDs
    exam_devices = (
        db.query(ExamDevice)
        .filter(ExamDevice.exam_id == exam_id)
        .all()
    )
    
    device_ids = [ed.device_id for ed in exam_devices if ed.device_id]
    devices = db.query(Device).filter(Device.device_id.in_(device_ids)).all() if device_ids else []
    device_map = {d.device_id: d for d in devices}
    
    hardware_uuids = []
    for ed in exam_devices:
        ed.status = ExamDeviceStatus.MONITORING.value
        device = device_map.get(ed.device_id)
        if device:
            target_id = device.hardware_uuid or device.device_name
            if target_id:
                hardware_uuids.append(target_id)
    
    db.commit()
    db.refresh(exam)
    
    logger.info(f"Exam activated: {exam.exam_name} -> {len(hardware_uuids)} devices")
    return exam, hardware_uuids


def deactivate_exam(db: Session, exam_id: UUID) -> tuple[Exam, list[str]]:
    """Deactivate/stop an exam. Returns (exam, list_of_device_hardware_uuids).
    Ends all active sessions and resets device assignments."""
    exam = db.query(Exam).filter(Exam.exam_id == exam_id).first()
    if not exam:
        raise ValueError(f"Exam {exam_id} not found")
    
    exam.status = ExamStatus.STOPPED.value
    exam.ended_at = datetime.utcnow()
    
    # End all active sessions for this exam
    active_sessions = (
        db.query(ExamSession)
        .filter(
            ExamSession.exam_id == exam_id,
            ExamSession.status == "active",
        )
        .all()
    )
    for session in active_sessions:
        session.status = "completed"
        session.ended_at = datetime.utcnow()
    
    # Reset exam device statuses
    exam_devices = db.query(ExamDevice).filter(ExamDevice.exam_id == exam_id).all()
    device_ids = [ed.device_id for ed in exam_devices if ed.device_id]
    devices = db.query(Device).filter(Device.device_id.in_(device_ids)).all() if device_ids else []
    device_map = {d.device_id: d for d in devices}
    
    hardware_uuids = []
    for ed in exam_devices:
        ed.status = ExamDeviceStatus.PENDING.value
        device = device_map.get(ed.device_id)
        if device:
            target_id = device.hardware_uuid or device.device_name
            if target_id:
                hardware_uuids.append(target_id)
    
    db.commit()
    db.refresh(exam)
    
    logger.info(f"Exam deactivated: {exam.exam_name} -> {len(hardware_uuids)} devices")
    return exam, hardware_uuids


def get_active_exam_for_device(db: Session, device_id: UUID) -> Optional[Exam]:
    """Find the currently active exam assigned to a device."""
    result = (
        db.query(Exam)
        .join(ExamDevice, ExamDevice.exam_id == Exam.exam_id)
        .filter(
            ExamDevice.device_id == device_id,
            Exam.status == ExamStatus.ACTIVE.value,
        )
        .first()
    )
    return result


def get_exam_with_counts(db: Session, exam_id: UUID) -> Optional[dict]:
    """Get exam with device_count, alert_count, session_count."""
    from backend.models.alert import Alert
    
    exam = db.query(Exam).filter(Exam.exam_id == exam_id).first()
    if not exam:
        return None
    
    device_count = db.query(ExamDevice).filter(ExamDevice.exam_id == exam_id).count()
    alert_count = db.query(Alert).filter(Alert.exam_id == exam_id).count()
    session_count = db.query(ExamSession).filter(ExamSession.exam_id == exam_id).count()
    
    return {
        "exam": exam,
        "device_count": device_count,
        "alert_count": alert_count,
        "session_count": session_count,
    }


def get_devices_for_exam(db: Session, exam_id: UUID) -> list[dict]:
    """Get all devices assigned to an exam with their current status and real-time risk score."""
    from backend.services.risk_service import get_device_risk_score

    results = (
        db.query(ExamDevice, Device)
        .join(Device, ExamDevice.device_id == Device.device_id)
        .filter(ExamDevice.exam_id == exam_id)
        .all()
    )
    
    devices_list = []
    for ed, device in results:
        risk_info = get_device_risk_score(db, device.device_id)
        devices_list.append({
            "id": str(ed.id),
            "exam_id": str(ed.exam_id),
            "device_id": str(ed.device_id),
            "exam_device_status": ed.status,
            "device_name": device.device_name,
            "hardware_uuid": device.hardware_uuid,
            "device_status": device.status,
            "building_name": device.building_name,
            "lab_name": device.lab_name,
            "pc_number": device.pc_number,
            "risk_score": risk_info.get("score", 0),
            "risk_level": risk_info.get("level", "normal"),
        })
    
    return devices_list
