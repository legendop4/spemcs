"""Dashboard summary and statistics endpoints."""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.models.device import Device
from backend.models.exam import Exam, ExamDevice
from backend.models.alert import Alert
from backend.models.session import ExamSession
from backend.models.lab import Lab
from backend.websocket.manager import realtime_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Aggregated statistics for the Admin Dashboard."""
    total_exams = db.query(Exam).count()
    active_exams = db.query(Exam).filter(Exam.status == 'active').count()

    total_devices = db.query(Device).count()
    devices_online = db.query(Device).filter(Device.status == 'online').count()
    devices_offline = total_devices - devices_online

    open_alerts = db.query(Alert).filter(Alert.status == 'open').count()
    active_sessions = db.query(ExamSession).filter(ExamSession.status == 'active').count()
    
    total_labs = db.query(Lab).count()
    
    # WebSocket connected counts
    ws_device_count = realtime_manager.get_device_count()
    ws_dashboard_count = realtime_manager.get_dashboard_count()
    
    # Active exam summaries
    active_exam_list = db.query(Exam).filter(Exam.status == 'active').all()
    active_exam_summary = []
    for exam in active_exam_list:
        dev_count = db.query(ExamDevice).filter(ExamDevice.exam_id == exam.exam_id).count()
        alert_count = db.query(Alert).filter(Alert.exam_id == exam.exam_id, Alert.status == 'open').count()
        session_count = db.query(ExamSession).filter(
            ExamSession.exam_id == exam.exam_id, ExamSession.status == 'active'
        ).count()
        active_exam_summary.append({
            "exam_id": str(exam.exam_id),
            "exam_name": exam.exam_name,
            "device_count": dev_count,
            "alert_count": alert_count,
            "session_count": session_count,
            "started_at": exam.started_at.isoformat() if exam.started_at else None,
        })
    
    # Online device list
    online_devices = db.query(Device).filter(Device.status == 'online').limit(50).all()
    online_device_list = [
        {
            "device_id": str(d.device_id),
            "device_name": d.device_name,
            "hardware_uuid": d.hardware_uuid,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        }
        for d in online_devices
    ]

    return {
        "total_exams": total_exams,
        "active_exams": active_exams,
        "total_devices": total_devices,
        "devices_online": devices_online,
        "devices_offline": devices_offline,
        "open_alerts": open_alerts,
        "active_sessions": active_sessions,
        "total_labs": total_labs,
        "ws_connected_devices": ws_device_count,
        "ws_connected_dashboards": ws_dashboard_count,
        "active_exam_summary": active_exam_summary,
        "online_device_list": online_device_list,
    }
