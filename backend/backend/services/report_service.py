"""Report generation service."""

import logging
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from backend.models.report import Report
from backend.models.exam import Exam
from backend.models.session import ExamSession
from backend.models.event import Event
from backend.models.alert import Alert
from backend.models.device import Device

logger = logging.getLogger(__name__)


def generate_exam_report(db: Session, exam_id: UUID) -> Report:
    """Generate a comprehensive exam report with summary and timeline data."""
    exam = db.query(Exam).filter(Exam.exam_id == exam_id).first()
    if not exam:
        raise ValueError(f"Exam {exam_id} not found")
    
    # Gather sessions
    sessions = (
        db.query(ExamSession)
        .filter(ExamSession.exam_id == exam_id)
        .all()
    )
    
    # Gather events (via session or via associated alert for this exam)
    events = (
        db.query(Event)
        .outerjoin(ExamSession, Event.session_id == ExamSession.session_id)
        .outerjoin(Alert, Event.event_id == Alert.event_id)
        .filter(
            or_(
                ExamSession.exam_id == exam_id,
                Alert.exam_id == exam_id
            )
        )
        .order_by(Event.timestamp)
        .all()
    )
    
    # Gather alerts
    alerts = (
        db.query(Alert)
        .filter(Alert.exam_id == exam_id)
        .order_by(Alert.created_at)
        .all()
    )
    
    # Build summary
    summary = {
        "exam_name": exam.exam_name,
        "exam_status": exam.status,
        "started_at": exam.started_at.isoformat() if exam.started_at else None,
        "ended_at": exam.ended_at.isoformat() if exam.ended_at else None,
        "total_sessions": len(sessions),
        "total_events": len(events),
        "total_alerts": len(alerts),
        "severity_breakdown": {},
        "event_type_breakdown": {},
        "students": [],
    }
    
    # Severity breakdown
    for alert in alerts:
        sev = alert.severity
        summary["severity_breakdown"][sev] = summary["severity_breakdown"].get(sev, 0) + 1
    
    # Event type breakdown
    for event in events:
        et = event.event_type
        summary["event_type_breakdown"][et] = summary["event_type_breakdown"].get(et, 0) + 1
    
    # Per-student summary
    student_data = {}
    for session in sessions:
        roll = session.student_roll_number
        if roll:
            if roll not in student_data:
                student_data[roll] = {
                    "roll_number": roll,
                    "session_count": 0,
                    "event_count": 0,
                    "alert_count": 0,
                }
            student_data[roll]["session_count"] += 1
    
    for event in events:
        roll = event.student_roll_number
        if roll:
            if roll not in student_data:
                student_data[roll] = {
                    "roll_number": roll,
                    "session_count": 0,
                    "event_count": 0,
                    "alert_count": 0,
                }
            student_data[roll]["event_count"] += 1

    for alert in alerts:
        if alert.event and alert.event.student_roll_number:
            roll = alert.event.student_roll_number
            if roll:
                if roll not in student_data:
                    student_data[roll] = {
                        "roll_number": roll,
                        "session_count": 0,
                        "event_count": 0,
                        "alert_count": 0,
                    }
                student_data[roll]["alert_count"] += 1
    
    summary["students"] = list(student_data.values())
    
    # Build timeline data
    report_data = {
        "timeline": [
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
        ],
        "alerts": [
            {
                "alert_id": str(a.alert_id),
                "severity": a.severity,
                "message": a.message,
                "status": a.status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
    }
    
    # Create or update report
    existing_report = (
        db.query(Report)
        .filter(Report.exam_id == exam_id)
        .first()
    )
    
    if existing_report:
        existing_report.generated_at = datetime.utcnow()
        existing_report.summary = summary
        existing_report.report_data = report_data
        existing_report.alert_count = len(alerts)
        existing_report.event_count = len(events)
        db.commit()
        db.refresh(existing_report)
        logger.info(f"Report updated for exam {exam_id}")
        return existing_report
    
    report = Report(
        exam_id=exam_id,
        summary=summary,
        report_data=report_data,
        alert_count=len(alerts),
        event_count=len(events),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    
    logger.info(f"Report generated for exam {exam_id}")
    return report


def get_student_timeline(
    db: Session,
    exam_id: UUID,
    roll_number: str,
) -> list[dict]:
    """Get chronological event timeline for a specific student in an exam."""
    events = (
        db.query(Event)
        .outerjoin(ExamSession, Event.session_id == ExamSession.session_id)
        .outerjoin(Alert, Event.event_id == Alert.event_id)
        .filter(
            or_(
                ExamSession.exam_id == exam_id,
                Alert.exam_id == exam_id
            ),
            Event.student_roll_number == roll_number,
        )
        .order_by(Event.timestamp)
        .all()
    )
    
    return [
        {
            "event_id": str(e.event_id),
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_type": e.event_type,
            "process_name": e.process_name,
            "classification": e.classification,
            "reason": e.reason,
            "device_name": e.device_name,
        }
        for e in events
    ]


def get_device_timeline(
    db: Session,
    exam_id: UUID,
    device_id: UUID,
) -> list[dict]:
    """Get chronological event timeline for a specific device in an exam."""
    events = (
        db.query(Event)
        .outerjoin(ExamSession, Event.session_id == ExamSession.session_id)
        .outerjoin(Alert, Event.event_id == Alert.event_id)
        .filter(
            or_(
                ExamSession.exam_id == exam_id,
                Alert.exam_id == exam_id
            ),
            Event.device_id == device_id,
        )
        .order_by(Event.timestamp)
        .all()
    )
    
    return [
        {
            "event_id": str(e.event_id),
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_type": e.event_type,
            "process_name": e.process_name,
            "student_roll_number": e.student_roll_number,
            "classification": e.classification,
            "reason": e.reason,
        }
        for e in events
    ]
