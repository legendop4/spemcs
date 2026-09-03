"""Report CRUD, generation, and export endpoints."""

import csv
import io
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.models.report import Report
from backend.schemas.report import ReportCreate, ReportRead, ReportUpdate
from backend.services import report_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])


def _as_dict(model: Any) -> dict:
    return model.model_dump(exclude_unset=True) if hasattr(model, "model_dump") else model.dict(exclude_unset=True)


@router.get("", response_model=list[ReportRead])
def list_reports(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(Report).order_by(Report.generated_at.desc()).offset(skip).limit(limit).all()


@router.get("/{report_id}", response_model=ReportRead)
def get_report(report_id: UUID, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@router.post("", response_model=ReportRead, status_code=status.HTTP_201_CREATED)
def create_report(payload: ReportCreate, db: Session = Depends(get_db)):
    data = _as_dict(payload)
    if data.get("report_id") is None:
        data.pop("report_id", None)
    report = Report(**data)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.put("/{report_id}", response_model=ReportRead)
def update_report(report_id: UUID, payload: ReportUpdate, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    for key, value in _as_dict(payload).items():
        setattr(report, key, value)
    db.commit()
    db.refresh(report)
    return report


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(report_id: UUID, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    db.delete(report)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Report Generation ---

@router.post("/generate/{exam_id}", response_model=ReportRead)
def generate_report(exam_id: UUID, db: Session = Depends(get_db)):
    """Generate a comprehensive exam report from live data."""
    try:
        report = report_service.generate_exam_report(db, exam_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return report


@router.get("/{report_id}/export/csv")
def export_report_csv(report_id: UUID, db: Session = Depends(get_db)):
    """Export report timeline data as CSV."""
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if not report.report_data or "timeline" not in report.report_data:
        raise HTTPException(status_code=400, detail="Report has no timeline data")
    
    timeline = report.report_data["timeline"]
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "event_id", "timestamp", "event_type", "device_name",
        "student_roll_number", "process_name", "classification", "reason",
    ])
    writer.writeheader()
    for row in timeline:
        writer.writerow(row)
    
    output.seek(0)
    exam_name = report.exam.exam_name if report.exam else "report"
    filename = f"{exam_name.replace(' ', '_')}_report.csv"
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{report_id}/timeline/student/{roll_number}")
def get_student_timeline(report_id: UUID, roll_number: str, db: Session = Depends(get_db)):
    """Get student-specific timeline from a report's exam."""
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_service.get_student_timeline(db, report.exam_id, roll_number)


@router.get("/{report_id}/timeline/device/{device_id}")
def get_device_timeline(report_id: UUID, device_id: UUID, db: Session = Depends(get_db)):
    """Get device-specific timeline from a report's exam."""
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_service.get_device_timeline(db, report.exam_id, device_id)
