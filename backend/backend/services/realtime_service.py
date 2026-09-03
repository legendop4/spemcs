"""Realtime orchestration service — wraps RealtimeManager with business logic."""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from backend.models.device import Device
from backend.models.exam import Exam, ExamDevice, ExamStatus
from backend.models.session import ExamSession
from backend.websocket.manager import realtime_manager

logger = logging.getLogger(__name__)


async def send_exam_launch(
    db: Session,
    exam: Exam,
    hardware_uuids: list[str],
) -> dict:
    """Send LAUNCH_EXAM_MODE to a list of devices. Returns {uuid: success}."""
    import secrets
    import uuid
    from datetime import datetime

    payload = {
        "action": "LAUNCH_EXAM_MODE",
        "command_id": str(uuid.uuid4()),
        "nonce": secrets.token_hex(16),
        "issued_at_utc": datetime.utcnow().isoformat() + "Z",
        "exam_id": str(exam.exam_id),
        "exam_name": exam.exam_name,
        "allowed_domain": exam.exam_link or "",
        "approved_browser": exam.approved_browser,
    }
    
    results = await realtime_manager.send_to_exam_devices(hardware_uuids, payload)
    
    sent_count = sum(1 for v in results.values() if v)
    logger.info(f"LAUNCH_EXAM_MODE sent to {sent_count}/{len(hardware_uuids)} devices")
    
    return results


async def send_exam_stop(
    exam: Exam,
    hardware_uuids: list[str],
) -> dict:
    """Send STOP_EXAM_MODE to a list of devices. Returns {uuid: success}."""
    import secrets
    import uuid
    from datetime import datetime

    payload = {
        "action": "STOP_EXAM_MODE",
        "command_id": str(uuid.uuid4()),
        "nonce": secrets.token_hex(16),
        "issued_at_utc": datetime.utcnow().isoformat() + "Z",
        "exam_id": str(exam.exam_id),
        "exam_name": exam.exam_name,
    }
    
    results = await realtime_manager.send_to_exam_devices(hardware_uuids, payload)
    
    sent_count = sum(1 for v in results.values() if v)
    logger.info(f"STOP_EXAM_MODE sent to {sent_count}/{len(hardware_uuids)} devices")
    
    return results


async def broadcast_alert_to_exam(
    exam_id: str,
    alert_data: dict,
) -> int:
    """Broadcast a violation alert to all proctors watching this exam."""
    payload = {
        "type": "VIOLATION_ALERT",
        "payload": alert_data,
    }
    return await realtime_manager.broadcast_to_exam(exam_id, payload)


async def broadcast_exam_status(
    exam_id: str,
    status: str,
    exam_name: str,
) -> None:
    """Broadcast exam status change to all dashboard clients."""
    await realtime_manager.broadcast_to_dashboard({
        "type": "EXAM_STATUS_CHANGE",
        "payload": {
            "exam_id": exam_id,
            "status": status,
            "exam_name": exam_name,
        }
    })


async def broadcast_session_started(
    exam_id: str,
    session_data: dict,
) -> None:
    """Broadcast session start to proctors watching this exam."""
    await realtime_manager.broadcast_to_exam(exam_id, {
        "type": "SESSION_STARTED",
        "payload": session_data,
    })
