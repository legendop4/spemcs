from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.models.exam import ExamDevice
from backend.schemas.exam import ExamDeviceCreate, ExamDeviceRead, ExamDeviceUpdate

router = APIRouter(prefix="/api/exam-devices", tags=["exam_devices"])


def _as_dict(model: Any) -> dict:
    return model.model_dump(exclude_unset=True) if hasattr(model, "model_dump") else model.dict(exclude_unset=True)


@router.get("", response_model=list[ExamDeviceRead])
def list_exam_devices(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(ExamDevice).offset(skip).limit(limit).all()


@router.get("/{id}", response_model=ExamDeviceRead)
def get_exam_device(id: UUID, db: Session = Depends(get_db)):
    exam_device = db.get(ExamDevice, id)
    if exam_device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ExamDevice not found")
    return exam_device


@router.post("", response_model=ExamDeviceRead, status_code=status.HTTP_201_CREATED)
def create_exam_device(payload: ExamDeviceCreate, db: Session = Depends(get_db)):
    data = _as_dict(payload)
    if data.get("id") is None:
        data.pop("id", None)
    exam_device = ExamDevice(**data)
    db.add(exam_device)
    db.commit()
    db.refresh(exam_device)
    return exam_device


@router.put("/{id}", response_model=ExamDeviceRead)
def update_exam_device(id: UUID, payload: ExamDeviceUpdate, db: Session = Depends(get_db)):
    exam_device = db.get(ExamDevice, id)
    if exam_device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ExamDevice not found")
    for key, value in _as_dict(payload).items():
        setattr(exam_device, key, value)
    db.commit()
    db.refresh(exam_device)
    return exam_device


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_exam_device(id: UUID, db: Session = Depends(get_db)):
    exam_device = db.get(ExamDevice, id)
    if exam_device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ExamDevice not found")
    db.delete(exam_device)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
